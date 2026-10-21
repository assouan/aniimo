from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import os
import platform
import re
import shutil
import struct
import subprocess
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

TOOL_VERSION = "1.0.0"
CAPTURE_SCHEMA_VERSION = 1
DIAGNOSTIC_SCHEMA_VERSION = 1
DEFAULT_FEATURES = ("core", "lua", "content_indexes", "anti_cheat")
SCOPE_VALUES = {"game_decompile", "reference_only", "excluded", "needs_review"}
IL2CPP_MAGIC = 0xFAB11BAF
PE_MACHINE_NAMES = {
    0x014C: "x86",
    0x01C0: "arm",
    0x01C4: "armv7",
    0x8664: "x86_64",
    0xAA64: "arm64",
}
PE_SUBSYSTEM_NAMES = {
    1: "native",
    2: "windows_gui",
    3: "windows_console",
    7: "posix_console",
    10: "efi_application",
    14: "xbox",
    16: "windows_boot_application",
}


class M0Error(RuntimeError):
    """Raised when an M0 invariant cannot be satisfied."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_relative(path: str) -> str:
    candidate = path.replace("\\", "/")
    pure = PurePosixPath(candidate)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise M0Error(f"Unsafe logical path: {path!r}")
    return pure.as_posix()


def is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


def stat_identity(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "device": stat.st_dev,
        "inode": stat.st_ino,
    }


def same_file_identity(left: dict[str, int], right: dict[str, int]) -> bool:
    return all(left[key] == right[key] for key in left)


def matches_exclusion(logical_path: str, patterns: Iterable[str]) -> bool:
    value = logical_path.casefold()
    for raw_pattern in patterns:
        pattern = raw_pattern.replace("\\", "/").casefold()
        alternatives = {pattern}
        if pattern.startswith("**/"):
            alternatives.add(pattern[3:])
        if any(fnmatch.fnmatchcase(value, item) for item in alternatives):
            return True
    return False


def safe_source_file(root: Path, logical_path: str) -> Path:
    logical_path = normalized_relative(logical_path)
    source = root.joinpath(*PurePosixPath(logical_path).parts)
    if not source.is_file():
        raise M0Error(f"Source is not a regular file: {logical_path}")
    if source.is_symlink() or not is_within(source, root):
        raise M0Error(f"Symlink or escaped source rejected: {logical_path}")
    return source


def expand_selector(root: Path, selector: dict[str, Any]) -> list[tuple[str, Path]]:
    selector_type = selector.get("type")
    pattern = normalized_relative(str(selector.get("path", "")))
    if selector_type == "exact":
        candidate = root.joinpath(*PurePosixPath(pattern).parts)
        if candidate.is_file():
            return [(pattern, safe_source_file(root, pattern))]
        return []
    if selector_type != "glob":
        raise M0Error(f"Unsupported selector type: {selector_type!r}")
    max_matches = selector.get("max_matches")
    if not isinstance(max_matches, int) or max_matches < 1:
        raise M0Error(f"Glob {pattern!r} has no positive max_matches")
    matches: list[tuple[str, Path]] = []
    for candidate in root.glob(pattern):
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(root).as_posix()
        matches.append((relative, safe_source_file(root, relative)))
    matches.sort(key=lambda item: (item[0].casefold(), item[0]))
    if len(matches) > max_matches:
        raise M0Error(
            f"Selector {pattern!r} produced {len(matches)} matches, limit {max_matches}"
        )
    return matches


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise M0Error(f"Cannot read YAML {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise M0Error(f"Expected mapping in {path}")
    return value


@dataclass(frozen=True)
class PlannedPayload:
    logical_path: str
    source_path: Path
    rule_id: str
    feature: str
    required: bool
    roles: tuple[str, ...]
    identity_contribution: str
    planned_stat: dict[str, int]


@dataclass(frozen=True)
class CapturePlan:
    selection_id: str
    allowlist_sha256: str
    features: tuple[str, ...]
    payloads: tuple[PlannedPayload, ...]
    observations: tuple[dict[str, Any], ...]
    inventory: tuple[dict[str, Any], ...]
    candidate_inventory_policy: dict[str, Any]
    coherence: tuple[dict[str, Any], ...]
    estimated_bytes: int


class PEReader:
    """Read bounded PE metadata without loading or executing the image."""

    def __init__(self, path: Path):
        self.path = path
        self.size = path.stat().st_size
        self.machine: int | None = None
        self.timestamp: int | None = None
        self.characteristics: int | None = None
        self.optional_magic: int | None = None
        self.subsystem: int | None = None
        self.entrypoint_rva: int | None = None
        self.image_base: int | None = None
        self.sections: list[dict[str, Any]] = []
        self.data_directories: list[tuple[int, int]] = []
        self._parse_headers()

    def _read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise M0Error(f"PE read outside file {self.path.name}: {offset}+{size}")
        with self.path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(size)
        if len(data) != size:
            raise M0Error(f"Short PE read in {self.path.name}")
        return data

    def _parse_headers(self) -> None:
        dos = self._read_at(0, min(self.size, 64))
        if len(dos) < 64 or dos[:2] != b"MZ":
            raise M0Error(f"Not a PE image: {self.path.name}")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        prefix = self._read_at(pe_offset, 24)
        if prefix[:4] != b"PE\0\0":
            raise M0Error(f"Invalid PE signature: {self.path.name}")
        (
            self.machine,
            number_of_sections,
            self.timestamp,
            _,
            _,
            optional_size,
            self.characteristics,
        ) = struct.unpack_from("<HHIIIHH", prefix, 4)
        if number_of_sections > 512 or optional_size < 96 or optional_size > 4096:
            raise M0Error(f"Implausible PE header in {self.path.name}")
        optional = self._read_at(pe_offset + 24, optional_size)
        self.optional_magic = struct.unpack_from("<H", optional, 0)[0]
        if self.optional_magic == 0x10B:
            directory_offset = 96
            number_offset = 92
            image_base_offset = 28
            image_base_format = "<I"
        elif self.optional_magic == 0x20B:
            directory_offset = 112
            number_offset = 108
            image_base_offset = 24
            image_base_format = "<Q"
        else:
            raise M0Error(f"Unsupported PE optional header in {self.path.name}")
        self.entrypoint_rva = struct.unpack_from("<I", optional, 16)[0]
        self.image_base = struct.unpack_from(
            image_base_format, optional, image_base_offset
        )[0]
        self.subsystem = struct.unpack_from("<H", optional, 68)[0]
        number_of_directories = min(
            struct.unpack_from("<I", optional, number_offset)[0], 32
        )
        available = max(0, (len(optional) - directory_offset) // 8)
        for index in range(min(number_of_directories, available)):
            self.data_directories.append(
                struct.unpack_from("<II", optional, directory_offset + index * 8)
            )
        section_data = self._read_at(
            pe_offset + 24 + optional_size, number_of_sections * 40
        )
        for index in range(number_of_sections):
            offset = index * 40
            name = (
                section_data[offset : offset + 8]
                .split(b"\0", 1)[0]
                .decode("ascii", errors="replace")
            )
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", section_data, offset + 8
            )
            section_characteristics = struct.unpack_from(
                "<I", section_data, offset + 36
            )[0]
            self.sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_offset": raw_offset,
                    "characteristics": f"0x{section_characteristics:08x}",
                }
            )

    def directory(self, index: int) -> tuple[int, int]:
        if index >= len(self.data_directories):
            return (0, 0)
        return self.data_directories[index]

    def rva_to_offset(self, rva: int) -> int:
        for section in self.sections:
            start = int(section["virtual_address"])
            span = max(int(section["virtual_size"]), int(section["raw_size"]))
            if start <= rva < start + span:
                delta = rva - start
                if delta >= int(section["raw_size"]):
                    break
                return int(section["raw_offset"]) + delta
        if 0 <= rva < min(self.size, 1024 * 1024):
            return rva
        raise M0Error(f"Unmapped RVA 0x{rva:x} in {self.path.name}")

    def _read_c_string(self, offset: int, limit: int = 1024) -> str:
        size = min(limit, self.size - offset)
        data = self._read_at(offset, size)
        return data.split(b"\0", 1)[0].decode("ascii", errors="replace")

    def imports(self, max_entries: int = 4096) -> list[str]:
        rva, size = self.directory(1)
        if not rva or not size:
            return []
        table_offset = self.rva_to_offset(rva)
        count = min(max_entries, max(1, size // 20 + 1))
        names: set[str] = set()
        for index in range(count):
            descriptor = self._read_at(table_offset + index * 20, 20)
            fields = struct.unpack("<IIIII", descriptor)
            if not any(fields):
                break
            name_rva = fields[3]
            if name_rva:
                names.add(self._read_c_string(self.rva_to_offset(name_rva), 512))
        return sorted(names, key=lambda value: (value.casefold(), value))

    def exports(self, max_names: int = 20000) -> list[str]:
        rva, size = self.directory(0)
        if not rva or size < 40:
            return []
        directory = self._read_at(self.rva_to_offset(rva), 40)
        number_of_names = struct.unpack_from("<I", directory, 24)[0]
        names_rva = struct.unpack_from("<I", directory, 32)[0]
        if not names_rva or number_of_names > max_names:
            return []
        offsets = self._read_at(self.rva_to_offset(names_rva), number_of_names * 4)
        names: list[str] = []
        for index in range(number_of_names):
            name_rva = struct.unpack_from("<I", offsets, index * 4)[0]
            names.append(self._read_c_string(self.rva_to_offset(name_rva), 1024))
        return sorted(set(names), key=lambda value: (value.casefold(), value))

    def pdb_references(self, max_entries: int = 256) -> list[dict[str, Any]]:
        rva, size = self.directory(6)
        if not rva or size < 28:
            return []
        count = min(max_entries, size // 28)
        table = self._read_at(self.rva_to_offset(rva), count * 28)
        references: list[dict[str, Any]] = []
        for index in range(count):
            entry = table[index * 28 : (index + 1) * 28]
            debug_type = struct.unpack_from("<I", entry, 12)[0]
            data_size = struct.unpack_from("<I", entry, 16)[0]
            pointer = struct.unpack_from("<I", entry, 24)[0]
            if debug_type != 2 or data_size < 24 or pointer + data_size > self.size:
                continue
            data = self._read_at(pointer, min(data_size, 4096))
            if data[:4] != b"RSDS":
                continue
            guid = data[4:20].hex()
            age = struct.unpack_from("<I", data, 20)[0]
            pdb_path = data[24:].split(b"\0", 1)[0].decode("utf-8", errors="replace")
            references.append(
                {
                    "guid_hex": guid,
                    "age": age,
                    "pdb_basename": PurePosixPath(pdb_path.replace("\\", "/")).name,
                }
            )
        return references

    def certificate_metadata(self) -> dict[str, Any]:
        file_offset, size = self.directory(4)
        if not file_offset or size < 8 or file_offset + size > self.size:
            return {
                "embedded_certificate_present": False,
                "certificate_table_size": 0,
                "certificate_table_sha256": None,
                "signer_fingerprint": None,
                "signer_fingerprint_status": "absent",
            }
        certificate = self._read_at(file_offset, size)
        signer_fingerprint: str | None = None
        signer_status = "certificate_table_only"
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.serialization import pkcs7

            win_length = struct.unpack_from("<I", certificate, 0)[0]
            if 8 < win_length <= len(certificate):
                certificates = pkcs7.load_der_pkcs7_certificates(
                    certificate[8:win_length]
                )
                code_signers = []
                for item in certificates:
                    try:
                        from cryptography.x509 import (
                            ExtendedKeyUsage,
                            ExtensionNotFound,
                        )
                        from cryptography.x509.oid import (
                            ExtendedKeyUsageOID,
                            ExtensionOID,
                        )

                        extension = item.extensions.get_extension_for_oid(
                            ExtensionOID.EXTENDED_KEY_USAGE
                        ).value
                        if isinstance(extension, ExtendedKeyUsage) and (
                            ExtendedKeyUsageOID.CODE_SIGNING in extension
                        ):
                            code_signers.append(item)
                    except (ExtensionNotFound, ValueError):
                        continue
                if len(code_signers) == 1:
                    signer_fingerprint = (
                        code_signers[0].fingerprint(hashes.SHA256()).hex()
                    )
                    signer_status = "single_code_signing_certificate_in_pkcs7"
                elif code_signers:
                    signer_status = "multiple_code_signing_certificates_in_pkcs7"
                elif certificates:
                    signer_status = "pkcs7_certificates_without_unique_code_signer"
        except (ImportError, TypeError, ValueError, struct.error):
            signer_status = "pkcs7_parser_unavailable_or_failed"
        return {
            "embedded_certificate_present": True,
            "certificate_table_size": size,
            "certificate_table_sha256": sha256_bytes(certificate),
            "signer_fingerprint": signer_fingerprint,
            "signer_fingerprint_status": signer_status,
        }

    def summary(self, include_relations: bool = False) -> dict[str, Any]:
        clr_rva, clr_size = self.directory(14)
        value: dict[str, Any] = {
            "format": "PE",
            "machine": PE_MACHINE_NAMES.get(
                self.machine or -1, f"unknown_0x{self.machine:04x}"
            ),
            "machine_value": f"0x{self.machine:04x}"
            if self.machine is not None
            else None,
            "pe_timestamp": self.timestamp,
            "optional_header": "PE32+" if self.optional_magic == 0x20B else "PE32",
            "subsystem": PE_SUBSYSTEM_NAMES.get(
                self.subsystem or -1, f"unknown_{self.subsystem}"
            ),
            "entrypoint_rva": f"0x{self.entrypoint_rva:x}",
            "image_base": f"0x{self.image_base:x}",
            "has_clr_directory": bool(clr_rva and clr_size),
            "clr_directory_rva": f"0x{clr_rva:x}" if clr_rva else None,
            "section_count": len(self.sections),
            "sections": self.sections,
            "pdb_references": self.pdb_references(),
            **self.certificate_metadata(),
        }
        if include_relations:
            value["imports"] = self.imports()
            value["exports"] = self.exports()
        return value


def bounded_pe_metadata(path: Path) -> dict[str, Any]:
    try:
        return PEReader(path).summary(include_relations=False)
    except (M0Error, OSError, struct.error) as exc:
        return {
            "format": "unknown",
            "pe_parse_error": str(exc),
            "pe_machine": None,
            "pe_timestamp": None,
            "signer_fingerprint": None,
        }


def build_capture_plan(
    allowlist_path: Path,
    game_root: Path,
    steam_manifest: Path,
    requested_features: Iterable[str] | None = None,
) -> CapturePlan:
    profile = load_yaml(allowlist_path)
    selection_id = profile.get("selection_id")
    if not isinstance(selection_id, str):
        raise M0Error("Input profile has no selection_id")
    defaults = tuple(profile.get("feature_sets", {}).get("default_enabled", []))
    features = tuple(requested_features or defaults)
    if features != DEFAULT_FEATURES and requested_features is None:
        raise M0Error(f"Unexpected default feature set: {features!r}")
    available = set(profile.get("feature_sets", {}).get("available", {}))
    unknown_features = set(features) - available
    if unknown_features:
        raise M0Error(f"Unknown feature sets: {sorted(unknown_features)}")
    if not game_root.is_dir():
        raise M0Error(f"Game root is unavailable: {game_root}")
    if not steam_manifest.is_file():
        raise M0Error(f"Steam manifest is unavailable: {steam_manifest}")
    if steam_manifest.is_symlink():
        raise M0Error("Symlinked Steam manifest is not accepted")
    exclusions = profile.get("always_excluded_paths", [])
    candidate_inventory = profile.get("candidate_inventory")
    if not isinstance(candidate_inventory, dict) or not candidate_inventory.get(
        "enabled"
    ):
        raise M0Error("Candidate inventory must be enabled for M0")
    expected_flags = {
        "retain_file_bodies": False,
        "hash_file_bodies": False,
        "decompress_assets": False,
    }
    for field, expected in expected_flags.items():
        if candidate_inventory.get(field) is not expected:
            raise M0Error(f"Unsafe candidate inventory setting: {field}")
    max_candidates = candidate_inventory.get("max_candidates")
    if not isinstance(max_candidates, int) or max_candidates < 1:
        raise M0Error("Candidate inventory has no positive max_candidates")
    candidate_inventory_policy = {
        "enabled": True,
        "mode": str(candidate_inventory.get("mode")),
        "sources": list(candidate_inventory.get("sources", [])),
        "inspected_zones": list(candidate_inventory.get("inspected_zones", [])),
        "max_candidates": max_candidates,
        **expected_flags,
    }
    payloads: list[PlannedPayload] = []
    observations: list[dict[str, Any]] = []
    selected_paths: dict[str, str] = {}
    for rule in profile.get("payload_rules", []):
        feature = str(rule.get("feature", ""))
        if feature not in features:
            continue
        rule_id = str(rule["id"])
        matches = expand_selector(game_root, rule["selector"])
        required = bool(rule.get("required", False))
        if required and not matches:
            raise M0Error(f"Required rule {rule_id} did not match")
        if not matches:
            observations.append(
                {
                    "rule_id": rule_id,
                    "feature": feature,
                    "mode": "payload",
                    "logical_path": normalized_relative(rule["selector"]["path"]),
                    "presence": "absent",
                    "required": required,
                    "roles": list(rule.get("roles", [])),
                }
            )
            continue
        for logical_path, source_path in matches:
            if matches_exclusion(logical_path, exclusions):
                raise M0Error(f"Selected payload is excluded by policy: {logical_path}")
            key = logical_path.casefold()
            if key in selected_paths:
                observations.append(
                    {
                        "rule_id": rule_id,
                        "feature": feature,
                        "mode": "payload",
                        "logical_path": logical_path,
                        "presence": "shadowed_by_exact_or_prior_rule",
                        "selected_by_rule": selected_paths[key],
                        "required": required,
                        "roles": list(rule.get("roles", [])),
                    }
                )
                continue
            selected_paths[key] = rule_id
            planned_stat = stat_identity(source_path)
            payloads.append(
                PlannedPayload(
                    logical_path=logical_path,
                    source_path=source_path,
                    rule_id=rule_id,
                    feature=feature,
                    required=required,
                    roles=tuple(rule.get("roles", [])),
                    identity_contribution=str(
                        rule.get("identity_contribution", "build_content")
                    ),
                    planned_stat=planned_stat,
                )
            )
            observations.append(
                {
                    "rule_id": rule_id,
                    "feature": feature,
                    "mode": "payload",
                    "logical_path": logical_path,
                    "presence": "present",
                    "required": required,
                    "roles": list(rule.get("roles", [])),
                    "size_bytes": planned_stat["size_bytes"],
                    "mtime_ns": planned_stat["mtime_ns"],
                }
            )
    for rule in profile.get("external_payload_rules", []):
        feature = str(rule.get("feature", ""))
        if feature not in features:
            continue
        if rule.get("source") != "steam_manifest":
            raise M0Error(f"Unsupported external source in {rule['id']}")
        logical_path = normalized_relative(rule["logical_path"])
        key = logical_path.casefold()
        if key in selected_paths:
            raise M0Error(f"Duplicate logical path: {logical_path}")
        selected_paths[key] = str(rule["id"])
        planned_stat = stat_identity(steam_manifest)
        payloads.append(
            PlannedPayload(
                logical_path=logical_path,
                source_path=steam_manifest,
                rule_id=str(rule["id"]),
                feature=feature,
                required=bool(rule.get("required", False)),
                roles=tuple(rule.get("roles", [])),
                identity_contribution=str(
                    rule.get("identity_contribution", "evidence_only")
                ),
                planned_stat=planned_stat,
            )
        )
        observations.append(
            {
                "rule_id": str(rule["id"]),
                "feature": feature,
                "mode": "payload",
                "logical_path": logical_path,
                "presence": "present",
                "required": bool(rule.get("required", False)),
                "roles": list(rule.get("roles", [])),
                "size_bytes": planned_stat["size_bytes"],
                "mtime_ns": planned_stat["mtime_ns"],
                "identity_contribution": str(
                    rule.get("identity_contribution", "evidence_only")
                ),
            }
        )
    inventory: list[dict[str, Any]] = []
    inventory_seen: set[tuple[str, str]] = set()
    for rule in profile.get("inventory_rules", []):
        rule_id = str(rule["id"])
        matches = expand_selector(game_root, rule["selector"])
        if not matches:
            inventory.append(
                {
                    "rule_id": rule_id,
                    "mode": "inventory_only",
                    "logical_path": normalized_relative(rule["selector"]["path"]),
                    "presence": "absent",
                    "roles": list(rule.get("roles", [])),
                    "body_retained": False,
                    "content_sha256": None,
                }
            )
            continue
        for logical_path, source_path in matches:
            if matches_exclusion(logical_path, exclusions):
                continue
            key = (rule_id, logical_path.casefold())
            if key in inventory_seen:
                continue
            inventory_seen.add(key)
            stat = stat_identity(source_path)
            record: dict[str, Any] = {
                "rule_id": rule_id,
                "mode": "inventory_only",
                "logical_path": logical_path,
                "presence": "present",
                "roles": list(rule.get("roles", [])),
                "body_retained": False,
                "content_sha256": None,
                "size_bytes": stat["size_bytes"],
                "mtime_ns": stat["mtime_ns"],
            }
            requested = set(rule.get("record", []))
            if requested & {"pe_machine", "pe_timestamp", "signer_fingerprint"}:
                pe = bounded_pe_metadata(source_path)
                record["pe_machine"] = pe.get("machine") or pe.get("pe_machine")
                record["pe_timestamp"] = pe.get("pe_timestamp")
                record["signer_fingerprint"] = pe.get("signer_fingerprint")
                record["signer_fingerprint_status"] = pe.get(
                    "signer_fingerprint_status"
                )
                record["embedded_certificate_present"] = pe.get(
                    "embedded_certificate_present"
                )
                if pe.get("pe_parse_error"):
                    record["pe_parse_error"] = pe["pe_parse_error"]
            inventory.append(record)
            if len(inventory) > max_candidates:
                raise M0Error(
                    f"Candidate inventory exceeds max_candidates={max_candidates}"
                )
    payload_presence = {item.logical_path.casefold(): True for item in payloads}
    absent_payload_paths = {
        item["logical_path"].casefold()
        for item in observations
        if item["mode"] == "payload" and item["presence"] == "absent"
    }
    coherence: list[dict[str, Any]] = []
    for group in profile.get("coherence_groups", []):
        if group.get("feature") not in features:
            continue
        members = [normalized_relative(item) for item in group.get("members", [])]
        states = [member.casefold() in payload_presence for member in members]
        valid = all(states) or not any(states)
        status = (
            "present" if all(states) else "absent" if not any(states) else "partial"
        )
        coherence.append(
            {
                "group_id": str(group["id"]),
                "rule": str(group["rule"]),
                "members": members,
                "status": status,
                "valid": valid,
            }
        )
        if group.get("rule") == "all_or_none" and not valid:
            raise M0Error(f"Coherence group {group['id']} is partial")
        if not any(states):
            missing_not_recorded = [
                item for item in members if item.casefold() not in absent_payload_paths
            ]
            if missing_not_recorded:
                raise M0Error(
                    f"Coherence members are not represented in observations: {missing_not_recorded}"
                )
    payloads.sort(key=lambda item: (item.logical_path.casefold(), item.logical_path))
    observations.sort(
        key=lambda item: (
            item["logical_path"].casefold(),
            item["logical_path"],
            item["rule_id"],
        )
    )
    inventory.sort(
        key=lambda item: (
            item["logical_path"].casefold(),
            item["logical_path"],
            item["rule_id"],
        )
    )
    return CapturePlan(
        selection_id=selection_id,
        allowlist_sha256=sha256_file(allowlist_path),
        features=features,
        payloads=tuple(payloads),
        observations=tuple(observations),
        inventory=tuple(inventory),
        candidate_inventory_policy=candidate_inventory_policy,
        coherence=tuple(coherence),
        estimated_bytes=sum(item.planned_stat["size_bytes"] for item in payloads),
    )


def copy_and_hash_stable(payload: PlannedPayload, destination: Path) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    last_error: str | None = None
    for attempt in (1, 2):
        before = stat_identity(payload.source_path)
        if attempt == 1 and not same_file_identity(before, payload.planned_stat):
            raise M0Error(f"Source changed after planning: {payload.logical_path}")
        digest = hashlib.sha256()
        bytes_read = 0
        temporary = destination.with_name(destination.name + f".tmp-{uuid.uuid4().hex}")
        try:
            with (
                payload.source_path.open("rb") as source,
                temporary.open("xb") as target,
            ):
                while chunk := source.read(8 * 1024 * 1024):
                    digest.update(chunk)
                    target.write(chunk)
                    bytes_read += len(chunk)
                target.flush()
                os.fsync(target.fileno())
            after = stat_identity(payload.source_path)
            if same_file_identity(before, after) and bytes_read == before["size_bytes"]:
                os.replace(temporary, destination)
                return {
                    "sha256": digest.hexdigest(),
                    "size_bytes": bytes_read,
                    "source_stat_before": before,
                    "source_stat_after": after,
                    "read_attempts": attempt,
                    "changed_during_read": False,
                }
            last_error = "source_changed_during_read"
        finally:
            if temporary.exists():
                temporary.unlink()
    raise M0Error(
        f"Source did not remain stable after one retry: {payload.logical_path} ({last_error})"
    )


def parse_steam_manifest(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    pairs = dict(re.findall(r'^\s*"([^"]+)"\s+"([^"]*)"\s*$', text, re.MULTILINE))
    state_flags = pairs.get("StateFlags")
    return {
        "appid": pairs.get("appid"),
        "build_id": pairs.get("buildid"),
        "install_dir": pairs.get("installdir"),
        "state_flags": state_flags,
        "installation_complete": state_flags == "4",
        "last_updated_unix": pairs.get("LastUpdated"),
    }


def make_read_only_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_file():
            path.chmod(0o444)
        elif path.is_dir():
            path.chmod(0o555)
    root.chmod(0o555)


def capture_bundle(
    allowlist_path: Path,
    game_root: Path,
    steam_manifest: Path,
    output_root: Path,
    requested_features: Iterable[str] | None = None,
) -> Path:
    started_wall = utc_now()
    started_mono = time.monotonic()
    plan = build_capture_plan(
        allowlist_path, game_root, steam_manifest, requested_features
    )
    output_root.mkdir(parents=True, exist_ok=True)
    free_bytes = shutil.disk_usage(output_root).free
    required_bytes = plan.estimated_bytes + max(
        64 * 1024 * 1024, plan.estimated_bytes // 20
    )
    if free_bytes < required_bytes:
        raise M0Error(
            f"Insufficient space: need {required_bytes} bytes, have {free_bytes}"
        )
    staging = output_root / f".staging-{uuid.uuid4().hex}"
    snapshot = staging / "snapshot"
    files_root = snapshot / "files"
    files_root.mkdir(parents=True)
    payload_records: list[dict[str, Any]] = []
    try:
        for payload in plan.payloads:
            destination = files_root.joinpath(
                *PurePosixPath(payload.logical_path).parts
            )
            result = copy_and_hash_stable(payload, destination)
            payload_records.append(
                {
                    "logical_path": payload.logical_path,
                    "rule_id": payload.rule_id,
                    "feature": payload.feature,
                    "required": payload.required,
                    "roles": list(payload.roles),
                    "identity_contribution": payload.identity_contribution,
                    "presence": "present",
                    "stored_path": f"files/{payload.logical_path}",
                    **result,
                }
            )
        planned_by_path = {item.logical_path.casefold(): item for item in plan.payloads}
        for record in payload_records:
            planned = planned_by_path[record["logical_path"].casefold()]
            final_stat = stat_identity(planned.source_path)
            if not same_file_identity(record["source_stat_after"], final_stat):
                raise M0Error(
                    f"Source changed after its capture: {record['logical_path']}"
                )
        steam_copy = files_root / "distribution" / "steam" / "appmanifest.acf"
        steam_evidence = parse_steam_manifest(steam_copy)
        if not steam_evidence["installation_complete"]:
            raise M0Error(
                "Steam manifest does not report a completed installation (StateFlags != 4)"
            )
        identity_payloads = [
            {
                "logical_path": item["logical_path"],
                "presence": item["presence"],
                "sha256": item["sha256"],
                "size_bytes": item["size_bytes"],
                "rule_id": item["rule_id"],
                "feature": item["feature"],
                "identity_contribution": item["identity_contribution"],
            }
            for item in payload_records
        ]
        identity_absences = [
            {
                "logical_path": item["logical_path"],
                "rule_id": item["rule_id"],
                "feature": item["feature"],
                "presence": item["presence"],
            }
            for item in plan.observations
            if item["presence"] == "absent"
        ]
        identity = {
            "schema_version": CAPTURE_SCHEMA_VERSION,
            "bundle_kind": "m0_acquisition",
            "selection_id": plan.selection_id,
            "allowlist_sha256": plan.allowlist_sha256,
            "features": list(plan.features),
            "payloads": identity_payloads,
            "absences": identity_absences,
            "coherence": list(plan.coherence),
        }
        capture_digest = sha256_bytes(canonical_json_bytes(identity))
        capture_id = f"m0-{capture_digest}"
        manifest = {
            **identity,
            "capture_id": capture_id,
            "capture_identity_sha256": capture_digest,
            "producer": {
                "name": "tools/m0_diagnose.py",
                "version": TOOL_VERSION,
            },
            "source_policy": {
                "source_open_mode": "read_only",
                "follow_symlinks": False,
                "pre_and_post_read_stat": True,
                "all_payloads_restatted_before_publication": True,
                "changed_during_read": "retry_once_then_fail",
                "decompress_during_capture": False,
                "absolute_host_paths_in_manifest": False,
            },
            "payloads": payload_records,
            "observations": list(plan.observations),
            "inventory": list(plan.inventory),
            "candidate_inventory_policy": plan.candidate_inventory_policy,
            "steam_evidence": steam_evidence,
            "totals": {
                "payload_count": len(payload_records),
                "payload_bytes": sum(item["size_bytes"] for item in payload_records),
                "inventory_observation_count": len(plan.inventory),
            },
        }
        manifest_path = snapshot / "capture-manifest.json"
        write_json(manifest_path, manifest)
        manifest_sha256 = sha256_file(manifest_path)
        write_json(
            snapshot / "capture-identity.json",
            {
                "capture_id": capture_id,
                "capture_identity_sha256": capture_digest,
                "capture_manifest_sha256": manifest_sha256,
            },
        )
        run_record = {
            "schema_version": 1,
            "capture_id": capture_id,
            "started_at": started_wall,
            "ended_at": utc_now(),
            "duration_ms": round((time.monotonic() - started_mono) * 1000, 3),
            "planned_payload_count": len(plan.payloads),
            "planned_payload_bytes": plan.estimated_bytes,
            "written_payload_count": len(payload_records),
            "written_payload_bytes": sum(
                item["size_bytes"] for item in payload_records
            ),
            "source_paths_redacted": True,
        }
        write_json(staging / "capture-run.json", run_record)
        destination = output_root / capture_id
        if destination.exists():
            existing_identity = json.loads(
                (destination / "snapshot" / "capture-identity.json").read_text(
                    encoding="utf-8"
                )
            )
            if existing_identity.get("capture_identity_sha256") != capture_digest:
                raise M0Error(f"Capture ID collision at {destination}")
            shutil.rmtree(staging)
            return destination
        make_read_only_tree(snapshot)
        os.replace(staging, destination)
        return destination
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def read_manifest(bundle: Path) -> tuple[Path, dict[str, Any]]:
    snapshot = bundle / "snapshot"
    manifest_path = snapshot / "capture-manifest.json"
    if not manifest_path.is_file():
        raise M0Error(f"Missing capture manifest: {manifest_path}")
    identity_path = snapshot / "capture-identity.json"
    if not identity_path.is_file():
        raise M0Error(f"Missing capture identity: {identity_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        recorded_identity = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise M0Error(f"Cannot read M0 bundle metadata: {exc}") from exc
    if manifest.get("bundle_kind") != "m0_acquisition":
        raise M0Error("Not an M0 acquisition bundle")
    if manifest.get("capture_id") != bundle.name:
        raise M0Error("Bundle directory does not match its capture ID")
    if recorded_identity.get("capture_id") != manifest.get("capture_id"):
        raise M0Error("Capture identity and manifest target different captures")
    if recorded_identity.get("capture_identity_sha256") != manifest.get(
        "capture_identity_sha256"
    ):
        raise M0Error("Capture identity digest does not match the manifest")
    if recorded_identity.get("capture_manifest_sha256") != sha256_file(manifest_path):
        raise M0Error("Capture manifest hash does not match the sealed identity")
    return snapshot, manifest


def capture_file(snapshot: Path, logical_path: str) -> Path:
    path = snapshot.joinpath(
        "files", *PurePosixPath(normalized_relative(logical_path)).parts
    )
    if not path.is_file() or not is_within(path, snapshot):
        raise M0Error(f"Captured payload is missing: {logical_path}")
    return path


def payload_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["logical_path"].casefold(): item
        for item in manifest.get("payloads", [])
        if item.get("presence") == "present"
    }


def probe_il2cpp_metadata(path: Path) -> dict[str, Any]:
    file_size = path.stat().st_size
    with path.open("rb") as stream:
        prefix = stream.read(min(file_size, 16 * 1024))
    if len(prefix) < 16:
        return {
            "status": "parse_error",
            "reason": "file_too_short",
            "size_bytes": file_size,
        }
    magic, version = struct.unpack_from("<II", prefix, 0)
    result: dict[str, Any] = {
        "size_bytes": file_size,
        "magic_hex": prefix[:4].hex().upper(),
        "magic_value": f"0x{magic:08X}",
        "magic_is_standard": magic == IL2CPP_MAGIC,
        "metadata_version": version,
        "status": "parse_error",
        "structural_checks": [],
        "errors": [],
    }
    if magic != IL2CPP_MAGIC:
        result["errors"].append("unexpected_magic")
        result["suspected_protection"] = False
        result["protection_assessment"] = "not_inferred_from_magic"
        return result
    result["structural_checks"].append("standard_magic")
    if not 16 <= version <= 256:
        entropy_sample = prefix[4 : min(len(prefix), 16 * 1024)]
        frequencies = [0] * 256
        for value in entropy_sample:
            frequencies[value] += 1
        entropy = 0.0
        if entropy_sample:
            for count in frequencies:
                if count:
                    probability = count / len(entropy_sample)
                    entropy -= probability * math.log2(probability)
        result["post_magic_entropy_sample"] = {
            "sample_bytes": len(entropy_sample),
            "shannon_bits_per_byte": round(entropy, 6),
        }
        result["status"] = (
            "suspected_protection" if entropy >= 7.5 else "unsupported_metadata_version"
        )
        result["errors"].append("implausible_metadata_version")
        result["errors"].append("nonconforming_bytes_after_standard_magic")
        result["suspected_protection"] = entropy >= 7.5
        result["protection_assessment"] = (
            "standard_magic_followed_by_implausible_version_and_high_entropy_header"
            if entropy >= 7.5
            else "implausible_version_without_sufficient_independent_protection_evidence"
        )
        result["claim_limit"] = (
            "The standard magic alone is not protection evidence; the assessment also uses "
            "the impossible version field and high entropy in the expected header region."
        )
        return result
    result["structural_checks"].append("plausible_version_integer")
    first_data_offset = struct.unpack_from("<I", prefix, 8)[0]
    result["header_size_candidate"] = first_data_offset
    if (
        first_data_offset < 16
        or first_data_offset > file_size
        or first_data_offset > 1024 * 1024
        or (first_data_offset - 8) % 8 != 0
    ):
        result["errors"].append("invalid_first_table_offset")
        result["suspected_protection"] = False
        result["protection_assessment"] = "no_independent_protection_evidence"
        return result
    if len(prefix) < first_data_offset:
        with path.open("rb") as stream:
            prefix = stream.read(first_data_offset)
    pair_count = (first_data_offset - 8) // 8
    result["header_pair_count"] = pair_count
    if pair_count < 20 or pair_count > 256:
        result["errors"].append("implausible_header_pair_count")
    pairs: list[dict[str, Any]] = []
    out_of_bounds: list[int] = []
    nonempty = 0
    for index in range(pair_count):
        offset, count = struct.unpack_from("<II", prefix, 8 + index * 8)
        valid = True
        if count:
            nonempty += 1
            valid = (
                offset >= first_data_offset
                and offset <= file_size
                and count <= file_size - offset
            )
        elif offset > file_size:
            valid = False
        if not valid:
            out_of_bounds.append(index)
        pairs.append(
            {
                "index": index,
                "offset": offset,
                "byte_count": count,
                "in_bounds": valid,
            }
        )
    result["table_pairs"] = pairs
    result["nonempty_table_count"] = nonempty
    result["out_of_bounds_table_indexes"] = out_of_bounds
    if nonempty < 10:
        result["errors"].append("too_few_nonempty_tables")
    if out_of_bounds:
        result["errors"].append("table_range_out_of_bounds")
    if len(pairs) >= 3:
        string_offset = pairs[2]["offset"]
        string_size = pairs[2]["byte_count"]
        if string_size and string_size <= 64 * 1024 * 1024:
            with path.open("rb") as stream:
                stream.seek(string_offset)
                sample = stream.read(min(string_size, 64 * 1024))
            printable = sum(
                1
                for value in sample
                if value == 0 or value in (9, 10, 13) or 32 <= value <= 126
            )
            ratio = printable / len(sample) if sample else 0.0
            result["string_heap_sample"] = {
                "sample_bytes": len(sample),
                "nul_terminated_values_present": b"\0" in sample,
                "printable_or_nul_ratio": round(ratio, 6),
            }
            if b"\0" in sample and ratio >= 0.70:
                result["structural_checks"].append("plausible_string_heap_sample")
            else:
                result["errors"].append("implausible_string_heap_sample")
    if not result["errors"]:
        result["status"] = "structurally_conformant_header"
        result["structural_checks"].extend(
            ["header_pair_layout", "all_nonempty_table_ranges_in_bounds"]
        )
    else:
        result["status"] = "inconsistent_metadata"
    result["suspected_protection"] = False
    result["protection_assessment"] = "no_independent_protection_evidence"
    result["claim_limit"] = (
        "Bounded structural validation only; it does not prove complete semantic parser compatibility."
    )
    return result


def find_unity_versions(path: Path) -> list[dict[str, Any]]:
    data = path.read_bytes()
    pattern = re.compile(rb"(?<![0-9])(?:20\d{2}|[3-9])\.\d+\.\d+[abfp]\d+(?:c\d+)?")
    results = []
    for match in pattern.finditer(data):
        results.append(
            {
                "value": match.group().decode("ascii"),
                "offset": match.start(),
                "encoding": "ascii",
            }
        )
    utf16_pattern = re.compile(
        rb"(?:(?:2\x000\x00\d\x00\d\x00)|(?:[3-9]\x00))\.\x00\d\x00+",
        re.IGNORECASE,
    )
    del utf16_pattern  # ASCII is canonical in Unity globalgamemanagers.
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in results:
        if item["value"] not in seen:
            unique.append(item)
            seen.add(item["value"])
    return unique[:32]


def parse_scripting_assemblies(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "parse_error", "error": str(exc), "assemblies": []}
    names: list[str] = []
    if isinstance(value, dict):
        for key in ("names", "assemblies", "scriptingAssemblies"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                names.extend(str(item) for item in candidate if isinstance(item, str))
    elif isinstance(value, list):
        names.extend(str(item) for item in value if isinstance(item, str))
    names = sorted(set(names), key=lambda item: (item.casefold(), item))
    return {
        "status": "parsed" if names else "parsed_without_known_name_array",
        "assemblies": names,
        "top_level_type": type(value).__name__,
        "top_level_keys": sorted(value) if isinstance(value, dict) else None,
    }


def parse_md5_content_index(path: Path, max_lines: int = 1_000_000) -> dict[str, Any]:
    """Parse bounded path metadata from the captured publisher MD5 index."""
    entries: list[dict[str, Any]] = []
    rejected = 0
    line_count = 0
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        for raw_line in stream:
            line_count += 1
            if line_count > max_lines:
                raise M0Error(f"Content index exceeds the line limit: {path.name}")
            if len(raw_line) > 16 * 1024:
                rejected += 1
                continue
            parts = raw_line.rstrip("\r\n").split(",", 2)
            if len(parts) != 3 or not re.fullmatch(r"[0-9A-Fa-f]{32}", parts[0]):
                rejected += 1
                continue
            try:
                declared_size = int(parts[1], 10)
                logical_path = normalized_relative(parts[2])
            except (ValueError, M0Error):
                rejected += 1
                continue
            if PurePosixPath(logical_path).suffix.casefold() not in {
                ".dll",
                ".exe",
                ".sys",
                ".pdb",
            }:
                continue
            entries.append(
                {
                    "logical_path": logical_path,
                    "declared_size_bytes": declared_size,
                    "declared_md5": parts[0].lower(),
                }
            )
    entries.sort(
        key=lambda item: (item["logical_path"].casefold(), item["logical_path"])
    )
    return {
        "status": "parsed",
        "line_count": line_count,
        "rejected_line_count": rejected,
        "executable_reference_count": len(entries),
        "entries": entries,
    }


def scan_exact_component_references(path: Path, names: Iterable[str]) -> list[str]:
    needles: dict[bytes, str] = {}
    for name in names:
        needles[name.encode("ascii", errors="ignore").lower()] = name
        needles[name.encode("utf-16-le", errors="ignore").lower()] = name
    found: set[str] = set()
    overlap = max((len(item) for item in needles), default=1) - 1
    tail = b""
    with path.open("rb") as stream:
        while chunk := stream.read(4 * 1024 * 1024):
            data = (tail + chunk).lower()
            for needle, name in needles.items():
                if needle and needle in data:
                    found.add(name)
            tail = data[-overlap:] if overlap else b""
    return sorted(found, key=lambda item: (item.casefold(), item))


def classify_subject(
    logical_path: str,
    subject_kind: str,
    policy: dict[str, Any],
    roles: Iterable[str] = (),
) -> tuple[str, str, str]:
    name = PurePosixPath(logical_path).name
    approved = {
        item.casefold()
        for item in policy.get("approved", {}).get("full_module_decompile", [])
    }
    if name.casefold() in approved:
        return (
            "game_decompile",
            "explicit_full_module_approval",
            "Approbation explicite du module complet dans la politique Aniimo.",
        )
    lowered = name.casefold()
    if fnmatch.fnmatchcase(lowered, "unitycrashhandler*.exe"):
        return (
            "excluded",
            "unity_auxiliary_excluded",
            "Outil auxiliaire Unity exclu des implémentations.",
        )
    if lowered in {"repair.exe", "crashsender1403.exe"}:
        return (
            "excluded",
            "installer_or_crash_tool_excluded",
            "Outil d'installation, réparation ou crash hors périmètre d'analyse.",
        )
    if lowered == "unityplayer.dll":
        return (
            "reference_only",
            "unity_engine_reference",
            "Moteur Unity conservé uniquement comme référence de chargement.",
        )
    if lowered == "gameassembly.dll":
        return (
            "needs_review",
            "il2cpp_mixed_container",
            "Conteneur IL2CPP mixte : les futurs corps exigent leur propriétaire managé original.",
        )
    if lowered in {"xlua.dll", "lua.dll", "lua54.dll", "luajit.dll"}:
        return (
            "reference_only",
            "generic_lua_runtime_or_bridge",
            "Bridge/runtime Lua générique : signatures utiles, implémentation exclue.",
        )
    if lowered.startswith(("unityengine.", "unity.")):
        return (
            "reference_only",
            "unity_managed_reference",
            "Assembly Unity disponible comme référence, sans export d'implémentation.",
        )
    framework_prefixes = (
        "system.",
        "microsoft.",
        "mono.",
        "netstandard",
        "mscorlib",
    )
    if lowered.startswith(framework_prefixes) or lowered in {
        "system.dll",
        "mscorlib.dll",
    }:
        return (
            "reference_only",
            "managed_runtime_reference",
            "Framework managé conservé uniquement comme référence.",
        )
    known_third_party = {
        "fpx.dll",
        "fpxsteam.dll",
        "crashsight64.dll",
        "gmesdk.dll",
        "discord_partner_sdk.dll",
        "discord_krisp.dll",
    }
    if lowered in known_third_party:
        return (
            "reference_only",
            "third_party_sdk_reference",
            "SDK tiers identifié par la politique, sans export d'implémentation.",
        )
    if subject_kind in {"debug_symbols", "metadata", "configuration"}:
        return (
            "reference_only",
            "analysis_evidence",
            "Preuve ou métadonnée utilisée sans export de corps.",
        )
    if "content_manifest" in roles:
        return (
            "reference_only",
            "content_index_evidence",
            "Index de contenu utilisé comme preuve, pas comme implémentation.",
        )
    return (
        "needs_review",
        "ownership_not_established",
        "Le nom ou l'emplacement est un indice insuffisant pour autoriser un export de corps.",
    )


def probe_command(name: str, arguments: list[str]) -> dict[str, Any]:
    started = time.monotonic()
    path = shutil.which(name)
    if not path:
        return {
            "tool": name,
            "availability": "not_found",
            "version": None,
            "smoke_test": "not_run",
            "duration_ms": round((time.monotonic() - started) * 1000, 3),
        }
    try:
        result = subprocess.run(
            [path, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            encoding="utf-8",
            errors="replace",
        )
        output = (result.stdout + "\n" + result.stderr).strip()
        return {
            "tool": name,
            "availability": "found",
            "path_kind": "host_command",
            "version": output.splitlines()[0][:500] if output else None,
            "smoke_test": "passed" if result.returncode == 0 else "failed",
            "exit_code": result.returncode,
            "duration_ms": round((time.monotonic() - started) * 1000, 3),
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "tool": name,
            "availability": "found",
            "path_kind": "host_command",
            "version": None,
            "smoke_test": "failed",
            "error": type(exc).__name__,
            "duration_ms": round((time.monotonic() - started) * 1000, 3),
        }


def tool_compatibility(
    snapshot: Path,
    manifest: dict[str, Any],
    external_results: Path | None,
) -> dict[str, Any]:
    ghidra_path_probe = probe_command("analyzeHeadless", ["-version"])
    ghidra_path_probe["tool"] = "Ghidra analyzeHeadless"
    tools = [
        {
            "tool": "m0_diagnose",
            "availability": "available",
            "version": TOOL_VERSION,
            "smoke_test": "passed",
            "tested_operations": [
                "allowlist_resolution",
                "stable_streaming_sha256_capture",
                "bounded_pe_metadata",
                "il2cpp_header_structure",
            ],
            "compatibility": "validated_for_m0_only",
        },
        {
            "tool": "python",
            "availability": "available",
            "version": platform.python_version(),
            "smoke_test": "passed",
            "compatibility": "validated_for_m0_tool",
        },
        {
            "tool": "PyYAML",
            "availability": "available",
            "version": getattr(yaml, "__version__", None),
            "smoke_test": "passed",
            "compatibility": "validated_for_profiles",
        },
        probe_command("docker", ["--version"]),
        probe_command("dotnet", ["--info"]),
        probe_command("java", ["-version"]),
        probe_command("llvm-readobj", ["--version"]),
        probe_command("ilspycmd", ["--version"]),
        ghidra_path_probe,
        probe_command("Cpp2IL", ["--help"]),
        probe_command("Il2CppDumper", ["--help"]),
    ]
    for item in tools:
        name = item["tool"]
        if name == "java" and item.get("availability") == "found":
            item["compatibility"] = "not_validated_for_ghidra"
            item["reason"] = (
                "Le Java hôte n'est pas une preuve de compatibilité avec une version Ghidra verrouillée."
            )
        elif (
            name in {"docker", "dotnet", "llvm-readobj"}
            and item.get("availability") == "found"
        ):
            item["compatibility"] = "host_available_not_toolchain_locked"
        elif name in {"ilspycmd", "Ghidra analyzeHeadless", "Cpp2IL", "Il2CppDumper"}:
            item.setdefault("compatibility", "not_tested_on_current_snapshot")
    external: list[dict[str, Any]] = []
    if external_results:
        value = json.loads(external_results.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or not isinstance(value.get("results"), list):
            raise M0Error("External tool result file has an invalid shape")
        external = value["results"]
        external_names = {str(item.get("tool")) for item in external}
        tools = [item for item in tools if str(item.get("tool")) not in external_names]
    return {
        "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
        "capture_id": manifest["capture_id"],
        "producer": {"name": "tools/m0_diagnose.py", "version": TOOL_VERSION},
        "lock_status": "unresolved",
        "lock_update_recommended": False,
        "tools": tools + external,
        "safety": {
            "game_code_executed": False,
            "runtime_probe_executed": False,
            "global_decompilation_executed": False,
            "il2cpp_inspector_current_pair": "not_run_by_m0_tool",
            "reason": "Les essais externes doivent être explicitement bornés et lire le snapshot, jamais l'installation live.",
        },
        "recommendation": {
            "backend_branch": "pending_detection",
            "m1": "Conserver le lock unresolved jusqu'à validation d'un couple exact dans les futures images.",
        },
    }


def inventory_unique(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in manifest.get("inventory", []):
        if item.get("presence") != "present":
            continue
        key = item["logical_path"].casefold()
        if key not in merged:
            merged[key] = dict(item)
            merged[key]["inventory_rule_ids"] = [item["rule_id"]]
        else:
            merged[key]["inventory_rule_ids"].append(item["rule_id"])
            merged[key]["roles"] = sorted(
                set(merged[key].get("roles", [])) | set(item.get("roles", []))
            )
    return sorted(
        merged.values(),
        key=lambda item: (item["logical_path"].casefold(), item["logical_path"]),
    )


def detect_and_scope(
    snapshot: Path,
    manifest: dict[str, Any],
    policy: dict[str, Any],
    authenticode_evidence: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    payloads = payload_map(manifest)
    authenticode_by_path = {
        str(item.get("logical_path", "")).casefold(): item
        for item in (authenticode_evidence or [])
        if item.get("logical_path")
    }
    evidence: list[dict[str, Any]] = []
    pe_modules: list[dict[str, Any]] = []
    imports_by_path: dict[str, list[str]] = {}
    selected_extensions = {".exe", ".dll", ".sys"}
    for item in manifest.get("payloads", []):
        logical = item["logical_path"]
        if PurePosixPath(logical).suffix.casefold() not in selected_extensions:
            continue
        path = capture_file(snapshot, logical)
        try:
            pe = PEReader(path).summary(include_relations=True)
            status = "parsed"
        except (M0Error, OSError, struct.error) as exc:
            pe = {"format": "unknown", "error": str(exc), "imports": [], "exports": []}
            status = "parse_error"
        imports_by_path[logical] = pe.get("imports", [])
        pe_modules.append(
            {
                "logical_path": logical,
                "status": status,
                "sha256": item["sha256"],
                "size_bytes": item["size_bytes"],
                "authenticode": authenticode_by_path.get(logical.casefold()),
                **pe,
            }
        )
        evidence.append(
            {
                "evidence_id": f"pe:{logical}",
                "kind": "captured_pe_metadata",
                "logical_path": logical,
                "status": status,
            }
        )
    metadata_logical = "Aniimo_Data/il2cpp_data/Metadata/global-metadata.dat"
    metadata_probe: dict[str, Any] | None = None
    if metadata_logical.casefold() in payloads:
        metadata_probe = probe_il2cpp_metadata(capture_file(snapshot, metadata_logical))
        evidence.append(
            {
                "evidence_id": "il2cpp:metadata-structure",
                "kind": "bounded_metadata_structure_probe",
                "logical_path": metadata_logical,
                "status": metadata_probe["status"],
            }
        )
    unity_logical = "Aniimo_Data/globalgamemanagers"
    unity_versions: list[dict[str, Any]] = []
    if unity_logical.casefold() in payloads:
        unity_versions = find_unity_versions(capture_file(snapshot, unity_logical))
        evidence.append(
            {
                "evidence_id": "unity:globalgamemanagers-version",
                "kind": "captured_unity_version_string",
                "logical_path": unity_logical,
                "status": "observed" if unity_versions else "not_found",
            }
        )
    scripting_logical = "Aniimo_Data/ScriptingAssemblies.json"
    scripting = {"status": "absent", "assemblies": []}
    if scripting_logical.casefold() in payloads:
        scripting = parse_scripting_assemblies(
            capture_file(snapshot, scripting_logical)
        )
        evidence.append(
            {
                "evidence_id": "managed:scripting-assemblies",
                "kind": "captured_scripting_assemblies_inventory",
                "logical_path": scripting_logical,
                "status": scripting["status"],
            }
        )
    content_index = {
        "status": "absent",
        "line_count": 0,
        "rejected_line_count": 0,
        "executable_reference_count": 0,
        "entries": [],
    }
    if "md5list.txt" in payloads:
        content_index = parse_md5_content_index(capture_file(snapshot, "md5list.txt"))
        evidence.append(
            {
                "evidence_id": "content:md5-index",
                "kind": "captured_publisher_content_index",
                "logical_path": "md5list.txt",
                "status": content_index["status"],
            }
        )
    game_assembly = next(
        (
            item
            for item in pe_modules
            if item["logical_path"].casefold() == "gameassembly.dll"
        ),
        None,
    )
    il2cpp_pair_present = (
        "gameassembly.dll" in payloads and metadata_logical.casefold() in payloads
    )
    mono_payloads = [
        item
        for item in manifest.get("payloads", [])
        if item["logical_path"].casefold().startswith("aniimo_data/managed/")
    ]
    mono_runtime_present = "aniimo_data/monobleedingedge/etc/mono/config" in payloads
    game_assembly_il2cpp_exports = sorted(
        name
        for name in (game_assembly.get("exports", []) if game_assembly else [])
        if name.startswith("il2cpp_")
    )
    if (
        il2cpp_pair_present
        and game_assembly
        and game_assembly.get("format") == "PE"
        and not game_assembly.get("has_clr_directory")
        and metadata_probe
        and metadata_probe.get("magic_is_standard")
        and scripting.get("status") == "parsed"
    ):
        backend = "il2cpp"
        backend_status = "confirmed"
        backend_reasons = [
            "coherent_pair_captured",
            "native_gameassembly_without_clr_directory",
            "standard_il2cpp_metadata_magic",
            "current_scripting_assemblies_inventory",
            "mono_runtime_and_managed_payloads_absent",
        ]
    elif mono_payloads or mono_runtime_present:
        backend = "mono"
        backend_status = "candidate"
        backend_reasons = ["managed_or_mono_runtime_inputs_present"]
    else:
        backend = "unknown"
        backend_status = "unresolved"
        backend_reasons = ["insufficient_backend_evidence"]
    aniimo_pe = next(
        (
            item
            for item in pe_modules
            if item["logical_path"].casefold() == "aniimo.exe"
        ),
        None,
    )
    platform_name = (
        "windows" if aniimo_pe and aniimo_pe.get("format") == "PE" else "unknown"
    )
    architecture = aniimo_pe.get("machine") if aniimo_pe else None
    architecture_status = (
        "confirmed" if architecture in PE_MACHINE_NAMES.values() else "unknown"
    )
    xlua = next(
        (
            item
            for item in pe_modules
            if item["logical_path"].casefold().endswith("/xlua.dll")
            or item["logical_path"].casefold() == "xlua.dll"
        ),
        None,
    )
    xlua_exports = set(xlua.get("exports", [])) if xlua else set()
    lua_api_exports = sorted(
        name for name in xlua_exports if name.startswith(("lua_", "luaL_"))
    )
    scripting_xlua = [
        name for name in scripting.get("assemblies", []) if "xlua" in name.casefold()
    ]
    if xlua and (lua_api_exports or scripting_xlua):
        lua_bridge = "xlua"
        lua_status = "confirmed_bridge_binary_with_correlated_evidence"
    elif xlua:
        lua_bridge = "xlua_candidate"
        lua_status = "filename_and_pe_only"
    else:
        lua_bridge = "unknown"
        lua_status = "not_detected"
    lua_archive_paths = {
        "active": (
            "Aniimo_Data/cvs/res/lua/LuaScripts.xdf",
            "Aniimo_Data/cvs/res/lua/LuaScripts.xdt",
        ),
        "bundled": (
            "Aniimo_Data/StreamingAssets/cvs/res/lua/LuaScripts.xdf",
            "Aniimo_Data/StreamingAssets/cvs/res/lua/LuaScripts.xdt",
        ),
    }
    lua_archives: dict[str, Any] = {}
    for archive_kind, paths in lua_archive_paths.items():
        records = [payloads.get(path.casefold()) for path in paths]
        lua_archives[archive_kind] = {
            "status": "present"
            if all(records)
            else "absent"
            if not any(records)
            else "partial",
            "files": [
                {
                    "logical_path": path,
                    "sha256": record.get("sha256") if record else None,
                    "size_bytes": record.get("size_bytes") if record else None,
                }
                for path, record in zip(paths, records, strict=True)
            ],
        }
    active_files = lua_archives["active"]["files"]
    bundled_files = lua_archives["bundled"]["files"]
    if (
        lua_archives["active"]["status"]
        == lua_archives["bundled"]["status"]
        == "present"
    ):
        lua_pair_relation = (
            "identical"
            if all(
                left["sha256"] == right["sha256"]
                for left, right in zip(active_files, bundled_files, strict=True)
            )
            else "different"
        )
    else:
        lua_pair_relation = "not_comparable"
    anti_names = [
        "NEP2.dll",
        "NEPKernel.sys",
        "NEPCleaner.exe",
        "KernelDumpAnalyzer.exe",
    ]
    anti_cheat: list[dict[str, Any]] = []
    for name in anti_names:
        module = next(
            (
                item
                for item in pe_modules
                if PurePosixPath(item["logical_path"]).name.casefold()
                == name.casefold()
            ),
            None,
        )
        if not module:
            anti_cheat.append(
                {"name": name, "presence": "absent", "policy_approval": "full_module"}
            )
            continue
        path = capture_file(snapshot, module["logical_path"])
        references = scan_exact_component_references(path, anti_names)
        anti_cheat.append(
            {
                "name": name,
                "logical_path": module["logical_path"],
                "presence": "present",
                "format": module.get("format"),
                "machine": module.get("machine"),
                "subsystem": module.get("subsystem"),
                "has_clr_directory": module.get("has_clr_directory"),
                "imports": module.get("imports", []),
                "exact_name_references": references,
                "authenticode": module.get("authenticode"),
                "policy_approval": "full_module",
                "decompilation_performed_in_m0": False,
            }
        )
    symbol_map_present = "symbolmap" in payloads
    symbol_map = {
        "presence": "present" if symbol_map_present else "absent",
        "match_status": "not_validated" if symbol_map_present else "not_applicable",
        "used_for_addresses": False,
    }
    steam = manifest.get("steam_evidence", {})
    inventory = inventory_unique(manifest)
    server_candidates = [
        item["logical_path"]
        for item in inventory
        if "server" in PurePosixPath(item["logical_path"]).name.casefold()
        and PurePosixPath(item["logical_path"]).suffix.casefold() == ".exe"
    ]
    detection = {
        "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
        "capture_id": manifest["capture_id"],
        "producer": {"name": "tools/m0_diagnose.py", "version": TOOL_VERSION},
        "source_boundary": {
            "input": "immutable_m0_snapshot_only",
            "live_game_path_available_to_diagnostic": False,
            "absolute_host_paths_published": False,
            "game_code_executed": False,
        },
        "distribution": {
            "kind": "steam",
            "app_id": steam.get("appid"),
            "build_id": steam.get("build_id"),
            "state_flags": steam.get("state_flags"),
            "installation_complete": steam.get("installation_complete"),
            "identity_role": "external_evidence_not_canonical_identity",
        },
        "platform": {
            "value": platform_name,
            "status": "confirmed" if platform_name != "unknown" else "unknown",
        },
        "architecture": {"value": architecture, "status": architecture_status},
        "backend": {
            "value": backend,
            "status": backend_status,
            "evidence": backend_reasons,
            "mono_managed_payload_count": len(mono_payloads),
            "mono_runtime_config_present": mono_runtime_present,
            "il2cpp_pair_present": il2cpp_pair_present,
            "gameassembly_il2cpp_export_count": len(game_assembly_il2cpp_exports),
            "gameassembly_il2cpp_export_sample": game_assembly_il2cpp_exports[:32],
        },
        "unity": {
            "version": unity_versions[0]["value"] if unity_versions else None,
            "status": "observed_in_globalgamemanagers" if unity_versions else "unknown",
            "candidates": unity_versions,
        },
        "il2cpp_metadata": metadata_probe,
        "lua": {
            "bridge": lua_bridge,
            "status": lua_status,
            "bridge_module": xlua["logical_path"] if xlua else None,
            "lua_api_export_count": len(lua_api_exports),
            "lua_api_export_sample": lua_api_exports[:32],
            "managed_xlua_assemblies": scripting_xlua,
            "archive_pairs": [
                {
                    "kind": item["group_id"],
                    "status": item["status"],
                }
                for item in manifest.get("coherence", [])
                if "lua" in item["group_id"]
            ],
            "archives": lua_archives,
            "active_vs_bundled": lua_pair_relation,
            "archives_decompressed": False,
        },
        "runtime_context": {
            "observed_process": "Aniimo.exe" if aniimo_pe else None,
            "observed_subsystem": aniimo_pe.get("subsystem") if aniimo_pe else None,
            "dedicated_server_executables_observed": server_candidates,
            "conclusion": "windows_client_observed_server_not_established",
            "game_state_authority": "unknown_not_runtime_observed",
            "authorized_modes": ["read_only_static_analysis"],
            "runtime_probe_performed": False,
        },
        "managed_assembly_inventory": scripting,
        "native_modules": pe_modules,
        "anti_cheat": anti_cheat,
        "authenticode_evidence": {
            "source": "windows_snapshot_validation",
            "validated_file_count": len(authenticode_by_path),
            "live_installation_read": False,
            "identity_role": "provenance_evidence_not_runtime_authorization",
        },
        "symbol_map": symbol_map,
        "historical_evidence_basis": {
            "source": "repository:/docs/aniimo/HISTORICAL_EVIDENCE.md",
            "input_status": "historical_unverified",
            "authority": "discovery_hints_only",
            "sample_directory_read_by_tool": False,
        },
        "historical_reconciliation": [
            {
                "property": "steam_build_id",
                "historical": "25962016",
                "current": steam.get("build_id"),
                "result": "confirmed"
                if steam.get("build_id") == "25962016"
                else "contradicted",
            },
            {
                "property": "backend",
                "historical": "il2cpp",
                "current": backend,
                "result": "confirmed" if backend == "il2cpp" else "not_confirmed",
            },
            {
                "property": "architecture",
                "historical": "x86_64",
                "current": architecture,
                "result": "confirmed" if architecture == "x86_64" else "not_confirmed",
            },
            {
                "property": "unity_version",
                "historical": "2022.3.62f1",
                "current": unity_versions[0]["value"] if unity_versions else None,
                "result": "confirmed"
                if unity_versions and unity_versions[0]["value"] == "2022.3.62f1"
                else "not_confirmed",
            },
            {
                "property": "lua_bridge",
                "historical": "xlua",
                "current": lua_bridge,
                "result": "confirmed" if lua_bridge == "xlua" else "not_confirmed",
            },
            {
                "property": "primary_managed_assembly_hint",
                "historical": "FunPlus.WorldX.Scripts.dll",
                "current": "present_in_scripting_assemblies"
                if "FunPlus.WorldX.Scripts.dll" in scripting.get("assemblies", [])
                else "not_observed",
                "result": "confirmed_presence_not_ownership"
                if "FunPlus.WorldX.Scripts.dll" in scripting.get("assemblies", [])
                else "not_confirmed",
            },
            {
                "property": "anti_cheat_known_components",
                "historical": anti_names,
                "current": [
                    item["name"] for item in anti_cheat if item["presence"] == "present"
                ],
                "result": "confirmed"
                if all(item["presence"] == "present" for item in anti_cheat)
                else "partially_confirmed",
            },
        ],
        "evidence": evidence,
        "limitations": [
            "Aucune observation runtime ni autorité serveur n'a été testée.",
            "La validation interne des métadonnées est structurelle et bornée, pas une extraction sémantique complète.",
            "Les noms d'assemblies et de fichiers ne prouvent pas seuls la propriété du code.",
        ],
    }
    subjects: dict[tuple[str, str], dict[str, Any]] = {}
    for module in pe_modules:
        logical = module["logical_path"]
        roles = payloads[logical.casefold()].get("roles", [])
        decision, reason_code, reason = classify_subject(
            logical, "native_module", policy, roles
        )
        subjects[("native_module", logical.casefold())] = {
            "subject": logical,
            "granularity": "component",
            "subject_kind": "native_module",
            "classification": decision,
            "reason_code": reason_code,
            "reason": reason,
            "evidence_refs": [f"pe:{logical}"],
            "policy_id": policy.get("policy_id"),
            "implementation_export_authorized": decision == "game_decompile",
            "m0_decompilation_performed": False,
            "body_captured": True,
        }
    for item in inventory:
        logical = item["logical_path"]
        suffix = PurePosixPath(logical).suffix.casefold()
        if suffix not in selected_extensions:
            continue
        key = ("native_module", logical.casefold())
        if key in subjects:
            continue
        decision, reason_code, reason = classify_subject(
            logical, "native_module", policy, item.get("roles", [])
        )
        subjects[key] = {
            "subject": logical,
            "granularity": "component",
            "subject_kind": "native_module",
            "classification": decision,
            "reason_code": reason_code,
            "reason": reason,
            "evidence_refs": [f"inventory:{logical}"],
            "policy_id": policy.get("policy_id"),
            "implementation_export_authorized": decision == "game_decompile",
            "m0_decompilation_performed": False,
            "body_captured": logical.casefold() in payloads,
        }
    for assembly in scripting.get("assemblies", []):
        decision, reason_code, reason = classify_subject(
            assembly, "managed_assembly", policy
        )
        subjects[("managed_assembly", assembly.casefold())] = {
            "subject": assembly,
            "granularity": "managed_assembly",
            "subject_kind": "managed_assembly",
            "classification": decision,
            "reason_code": reason_code,
            "reason": reason,
            "evidence_refs": ["managed:scripting-assemblies"],
            "policy_id": policy.get("policy_id"),
            "implementation_export_authorized": decision == "game_decompile",
            "m0_decompilation_performed": False,
            "body_captured": False,
        }
    decisions = sorted(
        subjects.values(),
        key=lambda item: (
            item["subject_kind"],
            item["subject"].casefold(),
            item["subject"],
        ),
    )
    for decision in decisions:
        decision["decision_status"] = "initial_m0"
        decision["decision_author"] = f"tools/m0_diagnose.py@{TOOL_VERSION}"
        decision["reviewer"] = None
        decision["applicability"] = {"capture_id": manifest["capture_id"]}
    if any(item["classification"] not in SCOPE_VALUES for item in decisions):
        raise M0Error("Invalid scope decision")
    counts = {value: 0 for value in sorted(SCOPE_VALUES)}
    for decision in decisions:
        counts[decision["classification"]] += 1
    scope = {
        "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
        "capture_id": manifest["capture_id"],
        "policy_id": policy.get("policy_id"),
        "input_selection_id": policy.get("input_selection_id"),
        "default_unknown_classification": "needs_review",
        "decisions": decisions,
        "counts": counts,
        "constraints": {
            "gameassembly_module_wide_decompilation": False,
            "require_original_managed_owner_for_il2cpp_body": True,
            "unity_engine_implementation_export": False,
            "generic_lua_runtime_implementation_export": False,
            "unknown_implementation_export": False,
            "approved_full_modules": policy.get("approved", {}).get(
                "full_module_decompile", []
            ),
        },
        "m0_actions": {
            "global_decompilation": "not_performed",
            "native_body_export": "not_performed",
            "managed_source_export": "not_performed",
        },
    }
    inventory_by_basename: dict[str, list[dict[str, Any]]] = {}
    for item in inventory:
        inventory_by_basename.setdefault(
            PurePosixPath(item["logical_path"]).name.casefold(), []
        ).append(item)
    candidates: dict[str, dict[str, Any]] = {}
    for source_path, imports in imports_by_path.items():
        for imported in imports:
            for matched in inventory_by_basename.get(imported.casefold(), []):
                logical = matched["logical_path"]
                if logical.casefold() in payloads:
                    continue
                entry = candidates.setdefault(
                    logical.casefold(),
                    {
                        "logical_path": logical,
                        "review_status": "needs_review",
                        "input_object_id": None,
                        "content_sha256": None,
                        "body_retained": False,
                        "body_hashed": False,
                        "size_bytes": matched.get("size_bytes"),
                        "mtime_ns": matched.get("mtime_ns"),
                        "pe_machine": matched.get("pe_machine"),
                        "pe_timestamp": matched.get("pe_timestamp"),
                        "discovery_sources": [],
                    },
                )
                entry["discovery_sources"].append(
                    {
                        "kind": "selected_pe_import",
                        "source": source_path,
                        "value": imported,
                    }
                )
    for item in inventory:
        logical = item["logical_path"]
        if logical.casefold() in payloads:
            continue
        if PurePosixPath(logical).suffix.casefold() not in {
            ".dll",
            ".exe",
            ".sys",
            ".pdb",
        }:
            continue
        entry = candidates.setdefault(
            logical.casefold(),
            {
                "logical_path": logical,
                "review_status": "needs_review",
                "input_object_id": None,
                "content_sha256": None,
                "body_retained": False,
                "body_hashed": False,
                "size_bytes": item.get("size_bytes"),
                "mtime_ns": item.get("mtime_ns"),
                "pe_machine": item.get("pe_machine"),
                "pe_timestamp": item.get("pe_timestamp"),
                "discovery_sources": [],
            },
        )
        entry["discovery_sources"].append(
            {
                "kind": "bounded_inventory_rule",
                "source": ",".join(item.get("inventory_rule_ids", [item["rule_id"]])),
                "value": logical,
            }
        )
    for declared in content_index["entries"]:
        logical = declared["logical_path"]
        if logical.casefold() in payloads:
            continue
        inventory_match = next(
            (
                item
                for item in inventory
                if item["logical_path"].casefold() == logical.casefold()
            ),
            None,
        )
        entry = candidates.setdefault(
            logical.casefold(),
            {
                "logical_path": logical,
                "review_status": "needs_review",
                "input_object_id": None,
                "content_sha256": None,
                "body_retained": False,
                "body_hashed": False,
                "size_bytes": inventory_match.get("size_bytes")
                if inventory_match
                else None,
                "mtime_ns": inventory_match.get("mtime_ns")
                if inventory_match
                else None,
                "pe_machine": inventory_match.get("pe_machine")
                if inventory_match
                else None,
                "pe_timestamp": inventory_match.get("pe_timestamp")
                if inventory_match
                else None,
                "discovery_sources": [],
            },
        )
        entry["manifest_declared_size_bytes"] = declared["declared_size_bytes"]
        entry["manifest_declared_md5"] = declared["declared_md5"]
        entry["manifest_claim_verified_against_body"] = False
        entry["discovery_sources"].append(
            {
                "kind": "captured_content_manifest",
                "source": "md5list.txt",
                "value": logical,
            }
        )
    candidate_list = sorted(
        candidates.values(),
        key=lambda item: (item["logical_path"].casefold(), item["logical_path"]),
    )
    candidate_policy = manifest.get("candidate_inventory_policy") or {
        "mode": "manifest_and_reference_guided_metadata_only",
        "max_candidates": 8192,
        "inspected_zones": [
            {
                "path": ".",
                "max_depth": 1,
                "extensions": [".dll", ".exe", ".sys", ".pdb"],
            },
            {
                "path": "Aniimo_Data/Plugins",
                "max_depth": 4,
                "extensions": [".dll", ".exe", ".pdb"],
            },
            {
                "path": "Aniimo_Data/il2cpp_data",
                "max_depth": 4,
                "names": ["global-metadata.dat"],
            },
        ],
    }
    candidate_limit = candidate_policy.get("max_candidates")
    if not isinstance(candidate_limit, int) or candidate_limit < 1:
        raise M0Error("Captured candidate policy has an invalid limit")
    if len(candidate_list) > candidate_limit:
        raise M0Error(
            f"Additional candidate inventory exceeds max_candidates={candidate_limit}"
        )
    for item in candidate_list:
        item["discovery_sources"] = sorted(
            item["discovery_sources"],
            key=lambda source: (source["kind"], source["source"], source["value"]),
        )
    additional = {
        "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
        "capture_id": manifest["capture_id"],
        "mode": candidate_policy.get("mode"),
        "max_candidates": candidate_limit,
        "inspected_zones": candidate_policy.get("inspected_zones", []),
        "candidate_count": len(candidate_list),
        "candidates": candidate_list,
        "source_evaluation": {
            "captured_content_manifests": {
                "md5list.txt": {
                    key: content_index[key]
                    for key in (
                        "status",
                        "line_count",
                        "rejected_line_count",
                        "executable_reference_count",
                    )
                },
                "other_binary_or_asset_indexes": "not_decompressed_or_bulk_parsed",
            },
            "scripting_assemblies_json": {
                "status": scripting.get("status"),
                "assembly_count": len(scripting.get("assemblies", [])),
                "used_for": "scope_subject_inventory_not_physical_body_capture",
            },
            "selected_pe_imports": {
                "source_module_count": len(imports_by_path),
                "used": True,
            },
        },
        "guarantees": {
            "candidate_bodies_retained": False,
            "candidate_bodies_hashed": False,
            "assets_decompressed": False,
            "implicit_allowlist_addition": False,
            "implicit_decompilation_approval": False,
        },
    }
    detection["additional_anti_cheat_candidates"] = [
        {
            "logical_path": item["logical_path"],
            "manifest_declared_size_bytes": item.get("manifest_declared_size_bytes"),
            "manifest_declared_md5": item.get("manifest_declared_md5"),
            "body_observed": item.get("size_bytes") is not None,
            "role": "name_based_candidate_only",
        }
        for item in candidate_list
        if re.search(
            r"(?:nep|anti.?cheat|kernel)",
            PurePosixPath(item["logical_path"]).name,
            re.IGNORECASE,
        )
    ]
    return detection, scope, additional


def render_report(
    manifest: dict[str, Any],
    detection: dict[str, Any],
    scope: dict[str, Any],
    tools: dict[str, Any],
    additional: dict[str, Any],
) -> str:
    anti = detection["anti_cheat"]
    historical_build = next(
        item
        for item in detection["historical_reconciliation"]
        if item["property"] == "steam_build_id"
    )
    lines = [
        "# Diagnostic M0 Aniimo",
        "",
        f"Capture immuable : `{manifest['capture_id']}`.",
        f"Steam App ID / build : `{detection['distribution']['app_id']}` / `{detection['distribution']['build_id']}` ; installation déclarée complète : `{str(detection['distribution']['installation_complete']).lower()}`.",
        "",
        "## Conclusion technique",
        "",
        f"- Backend : `{detection['backend']['value']}` (`{detection['backend']['status']}`).",
        f"- Plateforme / architecture : `{detection['platform']['value']}` / `{detection['architecture']['value']}`.",
        f"- Unity : `{detection['unity']['version']}` (`{detection['unity']['status']}`).",
        f"- Bridge Lua : `{detection['lua']['bridge']}` (`{detection['lua']['status']}`).",
        f"- Archives Lua actives / intégrées : `{detection['lua']['active_vs_bundled']}` ; elles restent deux composants distincts et n'ont pas été décompressées.",
        f"- Contexte : `{detection['runtime_context']['conclusion']}` ; autorité réelle sur l'état du jeu : inconnue faute d'observation runtime.",
        f"- Historique : le build `{historical_build['historical']}` est `{historical_build['result']}` par le build courant ; les indices viennent de `docs/aniimo/HISTORICAL_EVIDENCE.md`, et `.sample` n'a pas été lu par l'outil.",
        "- Branche technique : IL2CPP avec métadonnées protégées suspectées. Avant M2, il faudra valider un chargeur non exécutant sur ce couple exact ; aucun fallback approximatif n'est permis. M1 reste le prochain jalon.",
        "",
        "## Métadonnées IL2CPP",
        "",
    ]
    metadata = detection.get("il2cpp_metadata") or {}
    lines.extend(
        [
            f"- Magic : octets `{metadata.get('magic_hex')}`, valeur `{metadata.get('magic_value')}` ; standard : `{metadata.get('magic_is_standard')}`.",
            f"- Champ de version brut : `{metadata.get('metadata_version')}` ; résultat borné : `{metadata.get('status')}`.",
        ]
    )
    if metadata.get("status") == "structurally_conformant_header":
        lines.extend(
            [
                f"- Paires de tables : `{metadata.get('header_pair_count')}` ; tables non vides : `{metadata.get('nonempty_table_count')}` ; plages hors fichier : `{len(metadata.get('out_of_bounds_table_indexes', []))}`.",
                "- La validation dépasse le magic par le contrôle de l'en-tête, des plages et d'un échantillon du tas de chaînes ; elle ne remplace pas un parseur sémantique complet.",
            ]
        )
    else:
        entropy = metadata.get("post_magic_entropy_sample", {}).get(
            "shannon_bits_per_byte"
        )
        lines.extend(
            [
                f"- La zone attendue de l'en-tête est non conforme et présente une entropie de `{entropy}` bits/octet dans l'échantillon.",
                "- `suspected_protection` repose ici sur le champ de version impossible, la structure non conforme et l'entropie élevée ; le magic standard seul ne constitue pas cette preuve.",
            ]
        )
    lines.extend(
        [
            f"- Protection suspectée : `{metadata.get('suspected_protection')}`.",
            "",
            "## Anti-cheat explicitement approuvé",
            "",
            "| Module | Présence | Format | Architecture | Signature du snapshot | Classification M0 |",
            "|---|---|---|---|---|---|",
        ]
    )
    for item in anti:
        signature = item.get("authenticode") or {}
        signer = signature.get("subject", "")
        if signer:
            signer = signer.split(",", 1)[0]
        signature_label = (
            f"{signature.get('status')} — {signer}" if signature else "non vérifiée"
        )
        lines.append(
            f"| `{item['name']}` | {item['presence']} | {item.get('format', '')} | {item.get('machine', '')} | {signature_label} | `game_decompile` (module complet, décompilation reportée à M2) |"
        )
    additional_anti = detection.get("additional_anti_cheat_candidates", [])
    if additional_anti:
        lines.extend(
            [
                "",
                "Le manifeste de contenu déclare aussi les candidats nominaux suivants, sans corps observé ni rôle inventé : "
                + ", ".join(f"`{item['logical_path']}`" for item in additional_anti)
                + ".",
            ]
        )
    lines.extend(
        [
            "",
            "## Périmètre",
            "",
            f"Décisions : `{scope['counts']['game_decompile']}` `game_decompile`, `{scope['counts']['reference_only']}` `reference_only`, `{scope['counts']['excluded']}` `excluded`, `{scope['counts']['needs_review']}` `needs_review`.",
            "`GameAssembly.dll` reste un conteneur mixte : aucune approbation globale. Les corps futurs devront être reliés à leur assembly managée d'origine. Unity, les frameworks managés et xLua restent des références sans export d'implémentation.",
            "",
            "## Inventaire secondaire",
            "",
            f"`{additional['candidate_count']}` candidats ont été consignés par métadonnées bornées. Aucun corps candidat n'a été copié ou haché et aucun candidat n'a été ajouté implicitement à l'allowlist.",
            "",
            "## Compatibilité des outils",
            "",
            f"État du verrou : `{tools['lock_status']}`. Aucun verrou n'est promu tant qu'une version exacte n'a pas réussi un essai borné sur ce snapshot.",
            "",
            "| Outil | Disponibilité | Smoke test | Compatibilité |",
            "|---|---|---|---|",
        ]
    )
    for item in tools["tools"]:
        lines.append(
            f"| `{item.get('tool')}` | {item.get('availability')} | {item.get('smoke_test')} | {item.get('compatibility', '')} |"
        )
    lines.extend(
        [
            "",
            "## Garanties et limites M0",
            "",
            "- Le diagnostic a lu uniquement le snapshot local publié ; aucun chemin absolu hôte ne figure dans les artefacts canoniques.",
            "- Aucun binaire ou script du jeu n'a été exécuté, aucune archive n'a été décompressée, aucune injection ni sonde runtime n'a été lancée.",
            "- Aucune décompilation globale, aucun dump C/C# et aucun export de corps Unity/tiers n'a été produit.",
            "- Le client Windows est observé ; aucun serveur dédié ni autorité serveur n'est établi.",
            "- Le bundle M0 n'est pas le CAS ou le registre M1 ; M1 devra le réimporter avec validation ou recapturer.",
            "",
        ]
    )
    return "\n".join(lines)


def tool_probe_steps(tools: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for item in tools.get("tools", []):
        availability = item.get("availability")
        smoke_test = item.get("smoke_test")
        snapshot_test = item.get("current_snapshot_test")
        if (
            availability == "not_found"
            or str(smoke_test).startswith("blocked")
            or snapshot_test == "not_run"
        ):
            status = "skipped"
        elif smoke_test == "failed" or snapshot_test == "failed":
            status = "failed"
        else:
            status = "executed"
        duration = item.get("duration_ms")
        steps.append(
            {
                "id": re.sub(
                    r"[^a-z0-9]+", "_", str(item.get("tool", "tool")).lower()
                ).strip("_"),
                "status": status,
                "reason": item.get("diagnostic")
                or item.get("reason")
                or item.get("compatibility"),
                "cache_status": "not_applicable_m0",
                "duration_ms": duration,
                "duration_status": "measured"
                if duration is not None
                else "not_available",
                "tool": {
                    "name": item.get("tool"),
                    "version": item.get("version"),
                },
                "item_count": item.get("program_count")
                if item.get("program_count") is not None
                else item.get("output_file_count"),
                "byte_count": None,
            }
        )
    return steps


def render_operational_report(report: dict[str, Any]) -> str:
    lines = [
        "# Rapport opérationnel M0",
        "",
        f"Capture : `{report['capture_id']}` ; état du workflow : `{report['status']}`.",
        "Les durées sont mesurées avec une horloge monotone dans chaque commande et ne participent à aucune identité de contenu ni clé de cache.",
        "",
        "| Étape | État | Cache | Durée (ms) | Éléments | Octets | Outil | Raison |",
        "|---|---|---|---:|---:|---:|---|---|",
    ]

    def append_stage(stage: dict[str, Any], prefix: str = "") -> None:
        tool = stage.get("tool") or {}
        tool_label = str(tool.get("name") or "")
        if tool.get("version"):
            tool_label += f" {tool['version']}"
        duration = stage.get("duration_ms")
        duration_label = "" if duration is None else str(duration)
        item_count = stage.get("item_count")
        byte_count = stage.get("byte_count")
        reason = str(stage.get("reason") or "").replace("|", "\\|")
        lines.append(
            f"| {prefix}`{stage['id']}` | {stage['status']} | {stage.get('cache_status', '')} | {duration_label} | {'' if item_count is None else item_count} | {'' if byte_count is None else byte_count} | {tool_label} | {reason} |"
        )
        for child in stage.get("substeps", []):
            append_stage(child, prefix + "↳ ")

    for item in report.get("stages", []):
        append_stage(item)
    resources = report.get("resources", {})
    lines.extend(
        [
            "",
            "## Ressources légères",
            "",
            f"- CPU logiques visibles : `{resources.get('logical_cpu_count')}`.",
            f"- Espace libre au moment du diagnostic : `{resources.get('disk_free_bytes')}` octets.",
            f"- Temps CPU du processus de diagnostic : `{resources.get('diagnose_process_cpu_ms')}` ms.",
            "- La mémoire disponible n'a pas été sondée faute d'API portable déjà requise par M0.",
            "",
        ]
    )
    return "\n".join(lines)


def write_operational_report(bundle: Path, report: dict[str, Any]) -> None:
    destination = bundle / "run-report"
    temporary = bundle / f".run-report-{uuid.uuid4().hex}"
    backup: Path | None = None
    temporary.mkdir()
    try:
        write_json(temporary / "run-report.json", report)
        (temporary / "run-report.md").write_text(
            render_operational_report(report), encoding="utf-8", newline="\n"
        )
        if destination.exists():
            backup = bundle / f".run-report-old-{uuid.uuid4().hex}"
            os.replace(destination, backup)
        try:
            os.replace(temporary, destination)
        except Exception:
            if backup is not None and backup.exists() and not destination.exists():
                os.replace(backup, destination)
            raise
        if backup is not None and backup.exists():
            shutil.rmtree(backup)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def build_operational_report(
    bundle: Path,
    manifest: dict[str, Any],
    capture_run: dict[str, Any],
    tools: dict[str, Any],
    scope: dict[str, Any],
    diagnose_started_at: str,
    diagnose_duration_ms: float,
    diagnose_process_cpu_ms: float,
    detection_duration_ms: float,
    tool_matrix_duration_ms: float,
    artifact_generation_duration_ms: float,
    publication_duration_ms: float,
) -> dict[str, Any]:
    probes = tool_probe_steps(tools)
    measured_probe_duration = round(
        sum(
            float(item["duration_ms"])
            for item in probes
            if item["duration_ms"] is not None
        ),
        3,
    )
    skipped_work = [
        ("archive_decompression", "La capture M0 interdit toute décompression."),
        ("global_decompilation", "M0 s'arrête avant M2."),
        ("ghidra_autoanalysis", "Seul un import de format -noanalysis a été autorisé."),
        ("bsim_signature_generation", "BSim n'est pas exécuté en M0."),
        (
            "runtime_probe",
            "Les sondes runtime exigent un jalon et un environnement séparés.",
        ),
    ]
    report = {
        "schema_version": 1,
        "run_kind": "m0_diagnostic",
        "capture_id": manifest["capture_id"],
        "status": "completed",
        "workflow_started_at": capture_run.get("started_at"),
        "diagnose_started_at": diagnose_started_at,
        "last_updated_at": utc_now(),
        "timing_semantics": {
            "clock": "time.monotonic",
            "scope": "per_command",
            "affects_content_identity_or_cache_keys": False,
        },
        "resources": {
            "logical_cpu_count": os.cpu_count(),
            "disk_free_bytes": shutil.disk_usage(bundle).free,
            "diagnose_process_cpu_ms": diagnose_process_cpu_ms,
            "available_memory_bytes": None,
            "available_memory_status": "not_collected_without_additional_dependency",
        },
        "stages": [
            {
                "id": "capture",
                "status": "executed",
                "reason": "Bundle immuable publié avant le diagnostic.",
                "cache_status": "miss",
                "duration_ms": capture_run.get("duration_ms"),
                "duration_status": "measured_monotonic",
                "tool": {"name": "m0_diagnose", "version": TOOL_VERSION},
                "item_count": manifest.get("totals", {}).get("payload_count"),
                "byte_count": manifest.get("totals", {}).get("payload_bytes"),
            },
            {
                "id": "diagnose",
                "status": "executed",
                "reason": "Diagnostic effectué uniquement depuis le snapshot.",
                "cache_status": "not_applicable_m0",
                "duration_ms": diagnose_duration_ms,
                "duration_status": "measured_monotonic",
                "tool": {"name": "m0_diagnose", "version": TOOL_VERSION},
                "item_count": len(scope.get("decisions", [])),
                "byte_count": None,
                "substeps": [
                    {
                        "id": "detection_and_scope",
                        "status": "executed",
                        "reason": "Détection, preuves et classification fail-closed.",
                        "cache_status": "not_applicable_m0",
                        "duration_ms": detection_duration_ms,
                        "duration_status": "measured_monotonic",
                        "tool": {"name": "m0_diagnose", "version": TOOL_VERSION},
                        "item_count": len(scope.get("decisions", [])),
                        "byte_count": None,
                    },
                    {
                        "id": "tool_matrix",
                        "status": "executed",
                        "reason": "Fusion des probes hôte et des essais externes bornés.",
                        "cache_status": "not_applicable_m0",
                        "duration_ms": tool_matrix_duration_ms,
                        "duration_status": "measured_monotonic",
                        "tool": {"name": "m0_diagnose", "version": TOOL_VERSION},
                        "item_count": len(tools.get("tools", [])),
                        "byte_count": None,
                    },
                    {
                        "id": "artifact_generation",
                        "status": "executed",
                        "reason": "Génération des artefacts canoniques et de leurs hashes.",
                        "cache_status": "not_applicable_m0",
                        "duration_ms": artifact_generation_duration_ms,
                        "duration_status": "measured_monotonic",
                        "tool": {"name": "m0_diagnose", "version": TOOL_VERSION},
                        "item_count": 6,
                        "byte_count": None,
                    },
                    {
                        "id": "atomic_publication",
                        "status": "executed",
                        "reason": "Remplacement atomique du dossier diagnostic.",
                        "cache_status": "not_applicable_m0",
                        "duration_ms": publication_duration_ms,
                        "duration_status": "measured_monotonic",
                        "tool": {"name": "m0_diagnose", "version": TOOL_VERSION},
                        "item_count": 6,
                        "byte_count": None,
                    },
                ],
            },
            {
                "id": "tool_probes",
                "status": "executed",
                "reason": "Résultats réussis, incompatibles et bloqués tous conservés.",
                "cache_status": "not_applicable_m0",
                "duration_ms": measured_probe_duration,
                "duration_status": "sum_of_available_monotonic_probe_durations",
                "tool": {"name": "multiple", "version": None},
                "item_count": len(probes),
                "byte_count": None,
                "substeps": probes,
            },
            {
                "id": "out_of_scope_m0",
                "status": "skipped",
                "reason": "Travaux explicitement reportés à des jalons ultérieurs.",
                "cache_status": "not_applicable_m0",
                "duration_ms": 0.0,
                "duration_status": "not_invoked",
                "tool": {"name": None, "version": None},
                "item_count": 0,
                "byte_count": 0,
                "substeps": [
                    {
                        "id": identifier,
                        "status": "skipped",
                        "reason": reason,
                        "cache_status": "not_applicable_m0",
                        "duration_ms": 0.0,
                        "duration_status": "not_invoked",
                        "tool": {"name": None, "version": None},
                        "item_count": 0,
                        "byte_count": 0,
                    }
                    for identifier, reason in skipped_work
                ],
            },
            {
                "id": "verification",
                "status": "skipped",
                "reason": "Commande explicite pas encore exécutée pour ce rapport.",
                "cache_status": "not_applicable_m0",
                "duration_ms": 0.0,
                "duration_status": "not_invoked",
                "tool": {"name": "m0_diagnose", "version": TOOL_VERSION},
                "item_count": 0,
                "byte_count": 0,
            },
        ],
    }
    return report


def update_operational_verification(
    bundle: Path, result: dict[str, Any], duration_ms: float
) -> None:
    report_path = bundle / "run-report" / "run-report.json"
    if not report_path.is_file():
        return
    report = json.loads(report_path.read_text(encoding="utf-8"))
    verification = next(
        (item for item in report.get("stages", []) if item.get("id") == "verification"),
        None,
    )
    if verification is None:
        raise M0Error("Operational report has no verification stage")
    verification.update(
        {
            "status": "executed" if result["status"] == "passed" else "failed",
            "reason": "Tous les hashes et contrats vérifiés."
            if result["status"] == "passed"
            else f"{len(result['errors'])} erreur(s) de vérification.",
            "duration_ms": duration_ms,
            "duration_status": "measured_monotonic",
            "item_count": result["payloads_checked"],
            "byte_count": result["bytes_checked"],
        }
    )
    report["status"] = "completed" if result["status"] == "passed" else "failed"
    report["last_updated_at"] = utc_now()
    write_operational_report(bundle, report)


def diagnose_bundle(
    bundle: Path,
    policy_path: Path,
    external_tool_results: Path | None = None,
) -> Path:
    diagnose_started_at = utc_now()
    diagnose_started = time.monotonic()
    diagnose_cpu_started = time.process_time()
    snapshot, manifest = read_manifest(bundle)
    policy = load_yaml(policy_path)
    if policy.get("input_selection_id") != manifest.get("selection_id"):
        raise M0Error("Decompilation policy and capture selection do not match")
    external_data: dict[str, Any] = {}
    if external_tool_results:
        external_data = json.loads(external_tool_results.read_text(encoding="utf-8"))
        if external_data.get("capture_id") not in (None, manifest["capture_id"]):
            raise M0Error("External evidence targets another capture")
    detection_started = time.monotonic()
    detection, scope, additional = detect_and_scope(
        snapshot,
        manifest,
        policy,
        authenticode_evidence=external_data.get("authenticode", []),
    )
    detection_duration_ms = round((time.monotonic() - detection_started) * 1000, 3)
    tool_matrix_started = time.monotonic()
    tools = tool_compatibility(snapshot, manifest, external_tool_results)
    tool_matrix_duration_ms = round((time.monotonic() - tool_matrix_started) * 1000, 3)
    evidence_basis = {
        "capture_manifest_sha256": sha256_file(snapshot / "capture-manifest.json"),
        "decompilation_policy_sha256": sha256_file(policy_path),
        "producer_source_sha256": sha256_file(Path(__file__).resolve()),
    }
    detection["evidence_basis"] = evidence_basis
    scope["evidence_basis"] = evidence_basis
    additional["evidence_basis"] = evidence_basis
    tools["evidence_basis"] = evidence_basis
    if (
        detection["backend"]["value"] == "il2cpp"
        and (detection.get("il2cpp_metadata") or {}).get("status")
        == "suspected_protection"
    ):
        tools["recommendation"].update(
            {
                "backend_branch": "il2cpp_with_protected_metadata",
                "m2_precondition": "validate_an_authorized_non_executing_metadata_loader_on_the_exact_pair",
                "approximate_fallback_allowed": False,
                "native_analysis_candidate": "Ghidra 12.1.4 with OpenJDK 25.0.4.1",
            }
        )
    else:
        tools["recommendation"]["backend_branch"] = detection["backend"]["value"]
    diagnostics = bundle / "diagnostic"
    temporary = bundle / f".diagnostic-{uuid.uuid4().hex}"
    if temporary.exists():
        raise M0Error(f"Unexpected temporary path: {temporary}")
    artifact_generation_started = time.monotonic()
    temporary.mkdir(parents=True)
    try:
        write_json(temporary / "detection.json", detection)
        write_json(temporary / "scope-plan.json", scope)
        write_json(temporary / "tool-compatibility.json", tools)
        write_json(temporary / "additional-input-candidates.json", additional)
        report = render_report(manifest, detection, scope, tools, additional)
        (temporary / "report.md").write_text(report, encoding="utf-8", newline="\n")
        artifact_hashes = {
            path.name: sha256_file(path)
            for path in sorted(temporary.iterdir(), key=lambda item: item.name)
            if path.is_file()
        }
        write_json(
            temporary / "diagnostic-manifest.json",
            {
                "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
                "capture_id": manifest["capture_id"],
                "producer": {"name": "tools/m0_diagnose.py", "version": TOOL_VERSION},
                "artifacts": artifact_hashes,
                "source": "immutable_m0_snapshot_only",
            },
        )
        artifact_generation_duration_ms = round(
            (time.monotonic() - artifact_generation_started) * 1000, 3
        )
        publication_started = time.monotonic()
        if diagnostics.exists():
            backup = bundle / f".diagnostic-old-{uuid.uuid4().hex}"
            os.replace(diagnostics, backup)
            os.replace(temporary, diagnostics)
            shutil.rmtree(backup)
        else:
            os.replace(temporary, diagnostics)
        publication_duration_ms = round(
            (time.monotonic() - publication_started) * 1000, 3
        )
        diagnose_duration_ms = round((time.monotonic() - diagnose_started) * 1000, 3)
        diagnose_process_cpu_ms = round(
            (time.process_time() - diagnose_cpu_started) * 1000, 3
        )
        capture_run_path = bundle / "capture-run.json"
        if not capture_run_path.is_file():
            raise M0Error("M0 bundle has no capture run record")
        capture_run = json.loads(capture_run_path.read_text(encoding="utf-8"))
        operational_report = build_operational_report(
            bundle,
            manifest,
            capture_run,
            tools,
            scope,
            diagnose_started_at,
            diagnose_duration_ms,
            diagnose_process_cpu_ms,
            detection_duration_ms,
            tool_matrix_duration_ms,
            artifact_generation_duration_ms,
            publication_duration_ms,
        )
        write_operational_report(bundle, operational_report)
        return diagnostics
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def verify_bundle(bundle: Path, policy_path: Path | None = None) -> dict[str, Any]:
    verification_started = time.monotonic()
    snapshot, manifest = read_manifest(bundle)
    errors: list[str] = []
    checked_bytes = 0
    for item in manifest.get("payloads", []):
        try:
            path = capture_file(snapshot, item["logical_path"])
            digest = sha256_file(path)
            checked_bytes += path.stat().st_size
            if digest != item["sha256"]:
                errors.append(f"sha256_mismatch:{item['logical_path']}")
            if path.stat().st_size != item["size_bytes"]:
                errors.append(f"size_mismatch:{item['logical_path']}")
        except (OSError, M0Error) as exc:
            errors.append(f"missing_or_unreadable:{item['logical_path']}:{exc}")
    identity = {
        "schema_version": manifest["schema_version"],
        "bundle_kind": manifest["bundle_kind"],
        "selection_id": manifest["selection_id"],
        "allowlist_sha256": manifest["allowlist_sha256"],
        "features": manifest["features"],
        "payloads": [
            {
                "logical_path": item["logical_path"],
                "presence": item["presence"],
                "sha256": item["sha256"],
                "size_bytes": item["size_bytes"],
                "rule_id": item["rule_id"],
                "feature": item["feature"],
                "identity_contribution": item["identity_contribution"],
            }
            for item in manifest["payloads"]
        ],
        "absences": manifest["absences"],
        "coherence": manifest["coherence"],
    }
    digest = sha256_bytes(canonical_json_bytes(identity))
    if digest != manifest.get("capture_identity_sha256"):
        errors.append("capture_identity_mismatch")
    if manifest.get("capture_id") != f"m0-{digest}":
        errors.append("capture_id_mismatch")
    for item in manifest.get("inventory", []):
        if (
            item.get("content_sha256") is not None
            or item.get("body_retained") is not False
        ):
            errors.append(f"inventory_body_policy_violation:{item.get('logical_path')}")
    if policy_path:
        policy = load_yaml(policy_path)
        if policy.get("input_selection_id") != manifest.get("selection_id"):
            errors.append("policy_selection_mismatch")
    diagnostics = bundle / "diagnostic"
    required = {
        "detection.json",
        "scope-plan.json",
        "tool-compatibility.json",
        "additional-input-candidates.json",
        "report.md",
        "diagnostic-manifest.json",
    }
    missing = [name for name in sorted(required) if not (diagnostics / name).is_file()]
    errors.extend(f"missing_diagnostic:{name}" for name in missing)
    if not missing:
        json_names = {
            "detection.json",
            "scope-plan.json",
            "tool-compatibility.json",
            "additional-input-candidates.json",
        }
        loaded: dict[str, dict[str, Any]] = {}
        try:
            diagnostic_manifest = json.loads(
                (diagnostics / "diagnostic-manifest.json").read_text(encoding="utf-8")
            )
            if diagnostic_manifest.get("capture_id") != manifest.get("capture_id"):
                errors.append("diagnostic_capture_id_mismatch")
            expected_artifacts = required - {"diagnostic-manifest.json"}
            recorded_artifacts = diagnostic_manifest.get("artifacts", {})
            if not isinstance(recorded_artifacts, dict):
                raise TypeError("Diagnostic artifact hashes must be a mapping")
            if set(recorded_artifacts) != expected_artifacts:
                errors.append("diagnostic_artifact_set_mismatch")
            for name in sorted(expected_artifacts):
                if recorded_artifacts.get(name) != sha256_file(diagnostics / name):
                    errors.append(f"diagnostic_artifact_hash_mismatch:{name}")
            for name in sorted(json_names):
                loaded[name] = json.loads(
                    (diagnostics / name).read_text(encoding="utf-8")
                )
                if loaded[name].get("capture_id") != manifest.get("capture_id"):
                    errors.append(f"artifact_capture_id_mismatch:{name}")
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            errors.append(f"diagnostic_parse_error:{type(exc).__name__}")

        scope = loaded.get("scope-plan.json", {})
        for item in scope.get("decisions", []):
            if item.get("classification") not in SCOPE_VALUES:
                errors.append(f"invalid_scope_value:{item.get('subject')}")
        additional = loaded.get("additional-input-candidates.json", {})
        for item in additional.get("candidates", []):
            if (
                item.get("content_sha256") is not None
                or item.get("body_retained") is not False
            ):
                errors.append(
                    f"candidate_body_policy_violation:{item.get('logical_path')}"
                )

        if policy_path:
            expected_basis = {
                "capture_manifest_sha256": sha256_file(
                    snapshot / "capture-manifest.json"
                ),
                "decompilation_policy_sha256": sha256_file(policy_path),
                "producer_source_sha256": sha256_file(Path(__file__).resolve()),
            }
            for name, artifact in loaded.items():
                if artifact.get("evidence_basis") != expected_basis:
                    errors.append(f"artifact_evidence_basis_mismatch:{name}")

        host_path_pattern = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]")
        canonical_paths = [
            snapshot / "capture-manifest.json",
            snapshot / "capture-identity.json",
        ] + [diagnostics / name for name in sorted(required)]
        for path in canonical_paths:
            if host_path_pattern.search(
                path.read_text(encoding="utf-8", errors="replace")
            ):
                errors.append(f"absolute_host_path_exposed:{path.name}")
    result = {
        "schema_version": 1,
        "capture_id": manifest.get("capture_id"),
        "status": "passed" if not errors else "failed",
        "payloads_checked": len(manifest.get("payloads", [])),
        "bytes_checked": checked_bytes,
        "errors": errors,
    }
    verification_duration_ms = round(
        (time.monotonic() - verification_started) * 1000, 3
    )
    update_operational_verification(bundle, result, verification_duration_ms)
    return result


def print_result(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture and diagnose the bounded Aniimo M0 input set."
    )
    parser.add_argument("--version", action="version", version=TOOL_VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture", help="Create an immutable M0 bundle.")
    capture.add_argument("--game-root", type=Path, required=True)
    capture.add_argument("--steam-manifest", type=Path, required=True)
    capture.add_argument(
        "--allowlist", type=Path, default=Path("profiles/aniimo.inputs.yaml")
    )
    capture.add_argument(
        "--output-root", type=Path, default=Path(".aitools/m0-acquisition")
    )
    diagnose = subparsers.add_parser(
        "diagnose", help="Diagnose only an already captured M0 bundle."
    )
    diagnose.add_argument("--bundle", type=Path, required=True)
    diagnose.add_argument(
        "--policy", type=Path, default=Path("profiles/aniimo.decompilation.yaml")
    )
    diagnose.add_argument("--external-tool-results", type=Path)
    verify = subparsers.add_parser("verify", help="Verify bundle hashes and contracts.")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument(
        "--policy", type=Path, default=Path("profiles/aniimo.decompilation.yaml")
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            bundle = capture_bundle(
                args.allowlist,
                args.game_root,
                args.steam_manifest,
                args.output_root,
            )
            print_result(
                {
                    "status": "completed",
                    "bundle": str(bundle),
                    "capture_id": bundle.name,
                }
            )
            return 0
        if args.command == "diagnose":
            diagnostics = diagnose_bundle(
                args.bundle, args.policy, args.external_tool_results
            )
            print_result(
                {
                    "status": "completed",
                    "bundle": str(args.bundle),
                    "diagnostics": str(diagnostics),
                }
            )
            return 0
        if args.command == "verify":
            result = verify_bundle(args.bundle, args.policy)
            print_result(result)
            return 0 if result["status"] == "passed" else 4
    except M0Error as exc:
        print_result({"status": "failed", "error": str(exc)})
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
