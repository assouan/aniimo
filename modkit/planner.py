from __future__ import annotations

import fnmatch
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .config import LoadedYaml, enabled_features
from .errors import CaptureError, ConfigurationError
from .util import digest_json, normalize_logical_path, stable_sorted_dicts


@dataclass(frozen=True)
class SourceStat:
    size_bytes: int
    mtime_ns: int
    device: int | None
    inode: int | None

    @classmethod
    def from_path(cls, path: Path) -> SourceStat:
        stat_result = path.stat()
        return cls(
            size_bytes=stat_result.st_size,
            mtime_ns=stat_result.st_mtime_ns,
            device=getattr(stat_result, "st_dev", None),
            inode=getattr(stat_result, "st_ino", None),
        )

    def public(self) -> dict[str, int]:
        return {"size_bytes": self.size_bytes, "mtime_ns": self.mtime_ns}

    def stable_tuple(self) -> tuple[int, int, int | None, int | None]:
        return (self.size_bytes, self.mtime_ns, self.device, self.inode)


@dataclass
class PlannedPayload:
    logical_path: str
    source_path: Path = field(repr=False)
    source_kind: str
    rule_id: str
    feature: str
    required: bool
    roles: list[str]
    identity_contribution: str
    stat: SourceStat

    def public(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "identity_contribution": self.identity_contribution,
            "logical_path": self.logical_path,
            "required": self.required,
            "roles": sorted(set(self.roles)),
            "rule_id": self.rule_id,
            "source_kind": self.source_kind,
            **self.stat.public(),
        }


@dataclass
class CapturePlan:
    schema_version: int
    selection_id: str
    selection_sha256: str
    features: list[str]
    payloads: list[PlannedPayload]
    absences: list[dict[str, Any]]
    inventory: list[dict[str, Any]]
    coherence: list[dict[str, Any]]
    estimated_bytes: int
    plan_id: str
    inventory_passes: int = 1

    def public(self) -> dict[str, Any]:
        return {
            "absences": stable_sorted_dicts(self.absences),
            "coherence": sorted(self.coherence, key=lambda item: item["group_id"]),
            "estimated_bytes": self.estimated_bytes,
            "features": sorted(self.features),
            "inventory": stable_sorted_dicts(self.inventory),
            "inventory_passes": self.inventory_passes,
            "payloads": [
                item.public()
                for item in sorted(
                    self.payloads, key=lambda item: item.logical_path.casefold()
                )
            ],
            "plan_id": self.plan_id,
            "schema_version": self.schema_version,
            "selection_id": self.selection_id,
            "selection_sha256": self.selection_sha256,
        }


def _is_excluded(logical_path: str, patterns: list[str]) -> bool:
    path = PurePosixPath(logical_path)
    return any(
        path.match(pattern)
        or fnmatch.fnmatchcase(logical_path.casefold(), pattern.casefold())
        for pattern in patterns
    )


def _has_link_or_reparse(root: Path, candidate: Path) -> bool:
    current = root
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return True
    for part in relative.parts:
        current = current / part
        try:
            stat_result = current.lstat()
        except OSError:
            continue
        if current.is_symlink() or bool(
            getattr(stat_result, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            return True
    return False


def _safe_source(root: Path, logical_path: str) -> Path:
    normalized = normalize_logical_path(logical_path)
    candidate = root.joinpath(*normalized.split("/"))
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise CaptureError(
            f"Sélecteur hors installation : {logical_path}",
            error_code="unsafe_source_path",
        ) from exc
    if _has_link_or_reparse(root, candidate):
        raise CaptureError(
            f"Lien symbolique interdit par le profil : {logical_path}",
            error_code="symlink_rejected",
        )
    return candidate


def _glob_matches(root: Path, pattern: str, max_matches: int) -> list[tuple[str, Path]]:
    normalized = normalize_logical_path(pattern)
    matches: list[tuple[str, Path]] = []
    for candidate in root.glob(normalized):
        if (
            not candidate.is_file()
            or candidate.is_symlink()
            or _has_link_or_reparse(root, candidate)
        ):
            continue
        try:
            relative = candidate.relative_to(root).as_posix()
        except ValueError as exc:
            raise CaptureError(
                f"Résultat de glob hors installation : {candidate}",
                error_code="unsafe_source_path",
            ) from exc
        matches.append((relative, candidate))
        if len(matches) > max_matches:
            raise CaptureError(
                f"Le glob {pattern!r} dépasse max_matches={max_matches}.",
                error_code="glob_limit_exceeded",
            )
    return sorted(matches, key=lambda item: item[0].casefold())


def _bounded_pe_metadata(path: Path, fields: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if not any(field in fields for field in ("pe_machine", "pe_timestamp")):
        return result
    try:
        with path.open("rb") as stream:
            prefix = stream.read(64)
            if len(prefix) < 64 or prefix[:2] != b"MZ":
                return {"pe_parse_status": "not_pe"}
            pe_offset = int.from_bytes(prefix[60:64], "little")
            if pe_offset > 16 * 1024 * 1024:
                return {"pe_parse_status": "invalid_pe_offset"}
            stream.seek(pe_offset)
            header = stream.read(24)
        if len(header) != 24 or header[:4] != b"PE\0\0":
            return {"pe_parse_status": "invalid_signature"}
        result["pe_parse_status"] = "parsed"
        if "pe_machine" in fields:
            result["pe_machine"] = f"0x{int.from_bytes(header[4:6], 'little'):04x}"
        if "pe_timestamp" in fields:
            result["pe_timestamp"] = int.from_bytes(header[8:12], "little")
        if "signer_fingerprint" in fields:
            result["signer_fingerprint"] = None
            result["signer_status"] = "not_collected_by_portable_m1_reader"
    except OSError as exc:
        result = {"pe_parse_status": "read_error", "error": type(exc).__name__}
    return result


def build_capture_plan(
    profile: LoadedYaml,
    game_root: Path,
    steam_manifest: Path,
    *,
    disabled_features: set[str] | None = None,
) -> CapturePlan:
    """Resolve the bounded allowlist exactly once for dry-run or capture."""
    if not game_root.is_dir():
        raise ConfigurationError(
            f"Installation absente : {game_root}", error_code="missing_game_root"
        )
    if not steam_manifest.is_file():
        raise ConfigurationError(
            f"Manifeste Steam absent : {steam_manifest}",
            error_code="missing_steam_manifest",
        )
    if steam_manifest.stat().st_size > 4 * 1024 * 1024:
        raise CaptureError(
            "Manifeste Steam anormalement volumineux.",
            error_code="steam_manifest_too_large",
        )
    try:
        steam_text = steam_manifest.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise CaptureError(
            f"Manifeste Steam illisible : {type(exc).__name__}",
            error_code="steam_manifest_invalid",
        ) from exc
    state_match = re.search(r'"StateFlags"\s+"([0-9]+)"', steam_text)
    if state_match is None or int(state_match.group(1)) != 4:
        raise CaptureError(
            "L’installation Steam n’est pas dans l’état complet (StateFlags=4).",
            error_code="steam_install_incomplete",
        )
    features = enabled_features(profile, disabled_features)
    data = profile.data
    excluded = list(data.get("always_excluded_paths", []))
    payload_by_casefold: dict[str, PlannedPayload] = {}
    absences: list[dict[str, Any]] = []

    exact_rules: list[dict[str, Any]] = []
    glob_rules: list[dict[str, Any]] = []
    for rule in data.get("payload_rules", []):
        if rule.get("feature") not in features:
            continue
        selector = rule.get("selector", {})
        (exact_rules if selector.get("type") == "exact" else glob_rules).append(rule)

    def add_payload(
        rule: dict[str, Any], logical_path: str, source: Path, source_kind: str = "game"
    ) -> None:
        normalized = normalize_logical_path(logical_path)
        if _is_excluded(normalized, excluded):
            raise CaptureError(
                f"Une règle payload cible un chemin toujours exclu : {normalized}",
                error_code="payload_excluded",
            )
        key = normalized.casefold()
        if key in payload_by_casefold:
            existing = payload_by_casefold[key]
            if existing.logical_path != normalized:
                raise CaptureError(
                    f"Collision de casse : {existing.logical_path!r} / {normalized!r}",
                    error_code="case_collision",
                )
            existing.roles = sorted(set(existing.roles + list(rule.get("roles", []))))
            return
        payload_by_casefold[key] = PlannedPayload(
            logical_path=normalized,
            source_path=source,
            source_kind=source_kind,
            rule_id=str(rule["id"]),
            feature=str(rule.get("feature", "core")),
            required=bool(rule.get("required", False)),
            roles=list(rule.get("roles", [])),
            identity_contribution=str(
                rule.get(
                    "identity_contribution",
                    data.get("policy", {}).get(
                        "payload_identity_default", "build_content"
                    ),
                )
            ),
            stat=SourceStat.from_path(source),
        )

    for rule in exact_rules:
        logical = str(rule.get("selector", {}).get("path", ""))
        source = _safe_source(game_root, logical)
        if source.is_file():
            add_payload(rule, logical, source)
        else:
            absence = {
                "feature": rule["feature"],
                "logical_path": normalize_logical_path(logical),
                "required": bool(rule.get("required", False)),
                "rule_id": rule["id"],
                "status": "absent",
            }
            absences.append(absence)
            if absence["required"]:
                raise CaptureError(
                    f"Entrée requise absente : {logical}",
                    error_code="missing_required_payload",
                )

    for rule in glob_rules:
        selector = rule.get("selector", {})
        pattern = str(selector.get("path", ""))
        matches = _glob_matches(
            game_root, pattern, int(selector.get("max_matches", 1024))
        )
        if not matches:
            absence = {
                "feature": rule["feature"],
                "logical_path": pattern,
                "required": bool(rule.get("required", False)),
                "rule_id": rule["id"],
                "status": "unmatched_glob",
            }
            absences.append(absence)
            if absence["required"]:
                raise CaptureError(
                    f"Glob requis sans résultat : {pattern}",
                    error_code="missing_required_payload",
                )
        for logical, source in matches:
            add_payload(rule, logical, source)

    for rule in data.get("external_payload_rules", []):
        if rule.get("feature") not in features:
            continue
        if rule.get("source") != "steam_manifest":
            raise ConfigurationError(
                f"Source externe M1 non prise en charge : {rule.get('source')}"
            )
        logical = normalize_logical_path(str(rule["logical_path"]))
        if steam_manifest.is_file():
            external_rule = dict(rule)
            external_rule["identity_contribution"] = rule.get(
                "identity_contribution",
                data.get("policy", {}).get(
                    "external_payload_identity_default", "evidence_only"
                ),
            )
            add_payload(external_rule, logical, steam_manifest, "external")
        elif rule.get("required", False):
            raise CaptureError(
                "Manifeste Steam externe requis absent.",
                error_code="missing_required_payload",
            )

    case_paths: dict[str, str] = {}
    for payload in payload_by_casefold.values():
        key = payload.logical_path.casefold()
        prior = case_paths.get(key)
        if prior is not None and prior != payload.logical_path:
            raise CaptureError(
                f"Collision de casse : {prior!r} / {payload.logical_path!r}",
                error_code="case_collision",
            )
        case_paths[key] = payload.logical_path

    inventory: list[dict[str, Any]] = []
    for rule in data.get("inventory_rules", []):
        selector = rule.get("selector", {})
        selector_type = selector.get("type")
        if selector_type == "exact":
            logical = str(selector.get("path", ""))
            source = _safe_source(game_root, logical)
            matches = (
                [(normalize_logical_path(logical), source)] if source.is_file() else []
            )
        elif selector_type == "glob":
            matches = _glob_matches(
                game_root,
                str(selector.get("path", "")),
                int(selector.get("max_matches", 1024)),
            )
        else:
            raise ConfigurationError(
                f"Type de sélecteur inventaire invalide : {selector_type}"
            )
        if not matches:
            inventory.append(
                {
                    "logical_path": str(selector.get("path", "")),
                    "mode": "inventory_only",
                    "presence": "absent",
                    "rule_id": rule["id"],
                }
            )
        for logical, source in matches:
            source_stat = SourceStat.from_path(source)
            record_fields = list(rule.get("record", []))
            item: dict[str, Any] = {
                "logical_path": logical,
                "mode": "inventory_only",
                "presence": "present",
                "rule_id": rule["id"],
                "roles": list(rule.get("roles", [])),
            }
            if "size_bytes" in record_fields:
                item["size_bytes"] = source_stat.size_bytes
            if "mtime_ns" in record_fields:
                item["mtime_ns"] = source_stat.mtime_ns
            item.update(_bounded_pe_metadata(source, record_fields))
            inventory.append(item)

    logical_present = {payload.logical_path for payload in payload_by_casefold.values()}
    coherence: list[dict[str, Any]] = []
    for group in data.get("coherence_groups", []):
        if group.get("feature") not in features:
            continue
        members = [
            normalize_logical_path(str(member)) for member in group.get("members", [])
        ]
        present = [member for member in members if member in logical_present]
        status = (
            "complete"
            if len(present) == len(members)
            else "absent"
            if not present
            else "inconsistent"
        )
        coherence.append(
            {
                "group_id": group["id"],
                "members": members,
                "present": present,
                "rule": group.get("rule"),
                "status": status,
            }
        )
        if status == "inconsistent" and group.get("rule") == "all_or_none":
            raise CaptureError(
                f"Groupe de cohérence incomplet : {group['id']}",
                error_code="inconsistent_capture_group",
            )

    payloads = sorted(
        payload_by_casefold.values(), key=lambda item: item.logical_path.casefold()
    )
    public_without_id = {
        "absences": stable_sorted_dicts(absences),
        "coherence": sorted(coherence, key=lambda item: item["group_id"]),
        "estimated_bytes": sum(item.stat.size_bytes for item in payloads),
        "features": sorted(features),
        "inventory": stable_sorted_dicts(inventory),
        "inventory_passes": 1,
        "payloads": [item.public() for item in payloads],
        "schema_version": 1,
        "selection_id": str(data["selection_id"]),
        "selection_sha256": profile.sha256,
    }
    identity_payloads = [
        {key: value for key, value in item.items() if key != "mtime_ns"}
        for item in public_without_id["payloads"]
    ]
    identity_inventory = [
        {key: value for key, value in item.items() if key != "mtime_ns"}
        for item in public_without_id["inventory"]
    ]
    plan_id = f"plan-{digest_json({**public_without_id, 'payloads': identity_payloads, 'inventory': identity_inventory})}"
    return CapturePlan(
        schema_version=1,
        selection_id=str(data["selection_id"]),
        selection_sha256=profile.sha256,
        features=features,
        payloads=payloads,
        absences=absences,
        inventory=inventory,
        coherence=coherence,
        estimated_bytes=public_without_id["estimated_bytes"],
        plan_id=plan_id,
    )
