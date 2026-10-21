from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import struct
import tempfile
import uuid
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyzer import (
    _publish_artifact,
    _register_snapshot,
    assert_inputs_read_only,
    assert_no_live_source_environment,
)
from .capture import verify_snapshot
from .config import LoadedYaml
from .errors import ValidationError
from .luajit import (
    LuaJITParseError,
    OpcodeDialect,
    analyze_luajit_chunk,
    infer_opcode_dialect,
    parse_luajit_chunk,
)
from .native import _store_report_steps
from .pe import PeImage
from .registry import Registry, registry_writer_lock
from .reporting import RunReport, publish_report
from .util import (
    canonical_json_bytes,
    digest_json,
    fsync_directory,
    normalize_logical_path,
    object_path,
    pretty_json_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
)

LUA_PRODUCER = {"name": "modkit.lua", "version": "0.1.0"}
LUA_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class LuaRoots:
    inputs: Path
    state: Path
    artifacts: Path
    work: Path
    output: Path


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _producer_digest() -> str:
    paths = [Path(__file__), Path(__file__).with_name("luajit.py")]
    return digest_json({path.name: sha256_file(path)[0] for path in paths})


def _load_snapshot(
    roots: LuaRoots, snapshot_id: str, input_profile: LoadedYaml
) -> tuple[dict[str, Any], str]:
    manifest_path = roots.inputs / "snapshots" / snapshot_id / "capture-manifest.json"
    if not manifest_path.is_file():
        raise ValidationError(
            f"Snapshot Lua absent : {snapshot_id}", error_code="lua_snapshot_missing"
        )
    manifest = read_json(manifest_path)
    if manifest.get("snapshot_id") != snapshot_id:
        raise ValidationError(
            "Identité de snapshot Lua incohérente.",
            error_code="lua_snapshot_mismatch",
        )
    if manifest.get("selection_sha256") != input_profile.sha256:
        raise ValidationError(
            "Allowlist du snapshot Lua incompatible.",
            error_code="selection_digest_mismatch",
        )
    verify_snapshot(roots.inputs, snapshot_id, full_hash=False)
    return manifest, sha256_file(manifest_path)[0]


def _payloads(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["logical_path"]): item for item in manifest.get("payloads", [])}


def _archive_specs(profile: LoadedYaml) -> list[dict[str, str]]:
    lua = profile.data.get("lua", {})
    result: list[dict[str, str]] = []
    for role, key in (
        ("active", "active_archive_pair"),
        ("bundled", "bundled_archive_pair"),
    ):
        pair = lua.get(key)
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValidationError(
                f"Paire d'archives Lua invalide : {key}",
                error_code="lua_profile_invalid",
            )
        xdf = next(
            (str(value) for value in pair if str(value).lower().endswith(".xdf")), None
        )
        xdt = next(
            (str(value) for value in pair if str(value).lower().endswith(".xdt")), None
        )
        if xdf is None or xdt is None:
            raise ValidationError(
                f"Paire XDF/XDT invalide : {key}", error_code="lua_profile_invalid"
            )
        result.append({"role": role, "xdf": xdf, "xdt": xdt})
    return result


def _md5_file(path: Path) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _zip_data_offset(path: Path, info: zipfile.ZipInfo) -> int:
    with path.open("rb") as stream:
        stream.seek(info.header_offset)
        header = stream.read(30)
    if len(header) != 30 or header[:4] != b"PK\x03\x04":
        raise ValidationError(
            "En-tête local ZIP invalide.", error_code="lua_archive_invalid"
        )
    name_length, extra_length = struct.unpack_from("<HH", header, 26)
    return info.header_offset + 30 + name_length + extra_length


def _safe_archive_name(value: str) -> str:
    try:
        return normalize_logical_path(value)
    except Exception as exc:
        raise ValidationError(
            "Chemin dangereux dans l'archive Lua.",
            error_code="lua_archive_unsafe_path",
        ) from exc


def _load_index(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValidationError(
            "Index XDT trop volumineux.", error_code="lua_index_too_large"
        )
    try:
        value = read_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError(
            "Index XDT JSON invalide.", error_code="lua_index_parse_error"
        ) from exc
    required = {
        "CMSign",
        "CMVersion",
        "CMToolVer",
        "CMCompress",
        "CMDataLen",
        "CMDataMD5",
        "CMEntryNum",
        "CMList",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValidationError(
            "Schéma XDT non pris en charge.", error_code="lua_index_unsupported"
        )
    entries = value.get("CMList")
    if not isinstance(entries, list) or len(entries) != value.get("CMEntryNum"):
        raise ValidationError(
            "Nombre d'entrées XDT incohérent.", error_code="lua_index_invalid"
        )
    if len(entries) > 20_000:
        raise ValidationError(
            "Trop d'entrées dans l'archive Lua.", error_code="lua_archive_too_large"
        )
    return value


def _module_name(logical_path: str) -> str:
    value = logical_path
    prefix = "xfs/luascripts/"
    if value.casefold().startswith(prefix):
        value = value[len(prefix) :]
    if value.lower().endswith(".lua"):
        value = value[:-4]
    return value.replace("/", ".")


def _dialect_to_value(dialect: OpcodeDialect | None) -> dict[str, Any]:
    if dialect is None:
        return {"status": "unsupported"}
    return {"status": "inferred_bounded_subset", **asdict(dialect)}


def _dialect_from_value(value: dict[str, Any]) -> OpcodeDialect | None:
    if value.get("status") != "inferred_bounded_subset":
        return None
    return OpcodeDialect(
        gget=int(value["gget"]),
        kstr=int(value["kstr"]),
        call=int(value["call"]),
        fnew=int(value["fnew"]),
        tsets=int(value["tsets"]),
        tgets=int(value["tgets"]) if value.get("tgets") is not None else None,
        evidence=dict(value.get("evidence", {})),
    )


def _get_dialect(
    *,
    db: Any,
    zip_file: zipfile.ZipFile,
    lua_infos: list[zipfile.ZipInfo],
    xdf_sha256: str,
    parser_digest: str,
    analysis_id: str,
) -> tuple[OpcodeDialect | None, str]:
    row = db.execute(
        """SELECT mapping_json,status FROM lua_opcode_dialects
           WHERE xdf_sha256=? AND parser_digest=?""",
        (xdf_sha256, parser_digest),
    ).fetchone()
    if row is not None:
        return _dialect_from_value(json.loads(row["mapping_json"])), "hit"

    chunks = []
    for info in lua_infos[:256]:
        data = zip_file.read(info)
        try:
            chunks.append(parse_luajit_chunk(data))
        except LuaJITParseError:
            continue
    dialect = infer_opcode_dialect(chunks)
    value = _dialect_to_value(dialect)
    dialect_id = f"lua-opcode-dialect:{digest_json([xdf_sha256, parser_digest])}"
    db.execute(
        """INSERT INTO lua_opcode_dialects(
               opcode_dialect_id,xdf_sha256,parser_digest,mapping_json,
               evidence_json,status,created_by_analysis_id
           ) VALUES(?,?,?,?,?,?,?)""",
        (
            dialect_id,
            xdf_sha256,
            parser_digest,
            canonical_json_bytes(value).decode("utf-8"),
            canonical_json_bytes(value.get("evidence", {})).decode("utf-8"),
            value["status"],
            analysis_id,
        ),
    )
    return dialect, "miss"


def _script_cache_key(
    script_sha256: str, parser_digest: str, dialect_digest: str
) -> str:
    return f"lua-script:{digest_json([script_sha256, parser_digest, dialect_digest])}"


def _analyze_script(
    *,
    db: Any,
    roots: LuaRoots,
    data: bytes,
    script_sha256: str,
    parser_digest: str,
    dialect: OpcodeDialect | None,
    analysis_id: str,
) -> tuple[dict[str, Any], str]:
    dialect_value = _dialect_to_value(dialect)
    dialect_digest = digest_json(dialect_value)
    key = _script_cache_key(script_sha256, parser_digest, dialect_digest)
    row = db.execute(
        "SELECT analysis_artifact_sha256 FROM lua_script_cache WHERE script_cache_key=?",
        (key,),
    ).fetchone()
    if row is not None:
        path = object_path(roots.artifacts, str(row[0]))
        if path.is_file() and sha256_file(path)[0] == row[0]:
            return json.loads(path.read_bytes()), "hit"

    if not data.startswith(b"\x1bLJ"):
        result = {
            "bindings": [],
            "bytecode_format": "unknown",
            "dependencies": [],
            "error_code": "unsupported_bytecode_format",
            "instruction_semantics": {"status": "unsupported_opcode_dialect"},
            "parse_status": "unsupported",
            "prototypes": [],
        }
    else:
        try:
            chunk = parse_luajit_chunk(data)
            recovered = analyze_luajit_chunk(chunk, dialect)
            result = {
                **recovered,
                "bytecode_format": f"luajit-v{chunk.version}",
                "chunk_name_is_absolute": chunk.chunk_name_is_absolute,
                "chunk_name_sha256": chunk.chunk_name_sha256,
                "dump_flags": chunk.flags,
                "parse_status": "parsed",
            }
        except LuaJITParseError as exc:
            result = {
                "bindings": [],
                "bytecode_format": "luajit-unknown",
                "dependencies": [],
                "error_code": exc.code,
                "error": str(exc)[:512],
                "instruction_semantics": {"status": "unsupported_opcode_dialect"},
                "parse_status": (
                    "unsupported"
                    if exc.code.startswith("unsupported")
                    else "parse_error"
                ),
                "prototypes": [],
            }
    artifact_digest, _, _ = _publish_artifact(
        roots.artifacts, pretty_json_bytes(result)
    )
    db.execute(
        """INSERT OR REPLACE INTO lua_script_cache(
               script_cache_key,script_sha256,parser_digest,dialect_digest,
               analysis_artifact_sha256,parse_status,created_by_analysis_id
           ) VALUES(?,?,?,?,?,?,?)""",
        (
            key,
            script_sha256,
            parser_digest,
            dialect_digest,
            artifact_digest,
            result["parse_status"],
            analysis_id,
        ),
    )
    return result, "miss"


def _validate_and_analyze_archive(
    *,
    registry: Registry,
    roots: LuaRoots,
    xdf_path: Path,
    xdt_path: Path,
    xdf_sha256: str,
    xdt_sha256: str,
    archive_role: str,
    parser_digest: str,
    analysis_id: str,
    report: RunReport,
) -> dict[str, Any]:
    context = {
        "parser_digest": parser_digest,
        "producer": LUA_PRODUCER,
        "xdf_sha256": xdf_sha256,
        "xdt_sha256": xdt_sha256,
    }
    cache_key = f"lua-archive:{digest_json(context)}"
    cached = registry.cache_entry(cache_key)
    if cached is not None:
        path = object_path(roots.artifacts, str(cached["artifact_sha256"]))
        if path.is_file() and sha256_file(path)[0] == cached["artifact_sha256"]:
            report.add_step(
                f"lua.archive.{archive_role}.{xdf_sha256[:12]}",
                "lua_archive_extraction",
                category="analysis",
                status="cache_hit",
                reason="complete_archive_key_match",
                cache_status="hit",
                tool_name=LUA_PRODUCER["name"],
                tool_version=LUA_PRODUCER["version"],
                input_item_count=2,
                input_bytes=xdf_path.stat().st_size + xdt_path.stat().st_size,
            )
            return json.loads(path.read_bytes())

    with report.step(
        f"lua.archive.{archive_role}.{xdf_sha256[:12]}",
        "lua_archive_extraction",
        category="analysis",
        cache_status="miss",
        tool_name=LUA_PRODUCER["name"],
        tool_version=LUA_PRODUCER["version"],
    ) as step:
        step.input_item_count = 2
        step.input_bytes = xdf_path.stat().st_size + xdt_path.stat().st_size
        index = _load_index(xdt_path)
        if int(index["CMDataLen"]) != xdf_path.stat().st_size:
            raise ValidationError(
                "Taille XDF incohérente avec XDT.", error_code="lua_pair_inconsistent"
            )
        if str(index["CMDataMD5"]).lower() != _md5_file(xdf_path):
            raise ValidationError(
                "MD5 XDF incohérent avec XDT.", error_code="lua_pair_inconsistent"
            )

        try:
            archive = zipfile.ZipFile(xdf_path)
        except zipfile.BadZipFile as exc:
            raise ValidationError(
                "Conteneur XDF ZIP invalide.", error_code="lua_archive_invalid"
            ) from exc
        with archive:
            infos = archive.infolist()
            entries = index["CMList"]
            if len(infos) != len(entries):
                raise ValidationError(
                    "Nombre d'entrées XDF/XDT incohérent.",
                    error_code="lua_pair_inconsistent",
                )
            names: set[str] = set()
            casefolded: set[str] = set()
            entry_by_name: dict[str, dict[str, Any]] = {}
            total_uncompressed = 0
            for ordinal, (info, raw_entry) in enumerate(
                zip(infos, entries, strict=True)
            ):
                if not isinstance(raw_entry, dict):
                    raise ValidationError(
                        "Entrée XDT invalide.", error_code="lua_index_invalid"
                    )
                name = _safe_archive_name(str(raw_entry.get("CEName", "")))
                if name != _safe_archive_name(info.filename) or name in names:
                    raise ValidationError(
                        "Ordre, nom ou unicité XDF/XDT incohérent.",
                        error_code="lua_pair_inconsistent",
                    )
                if name.casefold() in casefolded:
                    raise ValidationError(
                        "Collision de casse dans l'archive Lua.",
                        error_code="lua_archive_case_collision",
                    )
                names.add(name)
                casefolded.add(name.casefold())
                entry_by_name[name] = raw_entry
                total_uncompressed += info.file_size
                if info.flag_bits & 1:
                    raise ValidationError(
                        "Entrée Lua chiffrée non prise en charge.",
                        error_code="lua_archive_encrypted",
                    )
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise ValidationError(
                        "Compression Lua non prise en charge.",
                        error_code="lua_archive_compression_unsupported",
                    )
                expected = {
                    "CEIndex": ordinal,
                    "CEOffset": _zip_data_offset(xdf_path, info),
                    "CECSize": info.compress_size,
                    "CESize": info.file_size,
                    "CEContainer": 0,
                }
                if any(
                    int(raw_entry.get(key, -1)) != value
                    for key, value in expected.items()
                ):
                    raise ValidationError(
                        "Métadonnées d'entrée XDF/XDT incohérentes.",
                        error_code="lua_pair_inconsistent",
                    )
            if total_uncompressed > 1024 * 1024 * 1024:
                raise ValidationError(
                    "Archive Lua décompressée trop volumineuse.",
                    error_code="lua_archive_too_large",
                )

            lua_infos = [
                info for info in infos if info.filename.lower().endswith(".lua")
            ]
            dialect, dialect_cache = _get_dialect(
                db=registry.db,
                zip_file=archive,
                lua_infos=lua_infos,
                xdf_sha256=xdf_sha256,
                parser_digest=parser_digest,
                analysis_id=analysis_id,
            )
            scripts: list[dict[str, Any]] = []
            script_hits = 0
            script_misses = 0
            for info in lua_infos:
                logical_path = _safe_archive_name(info.filename)
                raw_entry = entry_by_name[logical_path]
                data = archive.read(info)
                md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
                if md5.lower() != str(raw_entry.get("CEMD5", "")).lower():
                    raise ValidationError(
                        "MD5 d'un script Lua incohérent.",
                        error_code="lua_pair_inconsistent",
                    )
                script_sha256 = sha256_bytes(data)
                extracted_digest, _, _ = _publish_artifact(roots.artifacts, data)
                analyzed, cache_status = _analyze_script(
                    db=registry.db,
                    roots=roots,
                    data=data,
                    script_sha256=script_sha256,
                    parser_digest=parser_digest,
                    dialect=dialect,
                    analysis_id=analysis_id,
                )
                script_hits += cache_status == "hit"
                script_misses += cache_status == "miss"
                scripts.append(
                    {
                        "analysis": analyzed,
                        "compressed_size": info.compress_size,
                        "extracted_artifact_sha256": extracted_digest,
                        "logical_path": logical_path,
                        "module_name": _module_name(logical_path),
                        "script_sha256": script_sha256,
                        "size_bytes": len(data),
                    }
                )

        bundle = {
            "archive": {
                "content_md5": str(index["CMDataMD5"]).lower(),
                "content_version": str(index["CMVersion"]),
                "entry_count": len(infos),
                "index_compression": int(index["CMCompress"]),
                "lua_entry_count": len(lua_infos),
                "non_lua_entry_count": len(infos) - len(lua_infos),
                "total_uncompressed_bytes": total_uncompressed,
                "validation_status": "validated",
                "xdf_sha256": xdf_sha256,
                "xdt_sha256": xdt_sha256,
            },
            "dialect": _dialect_to_value(dialect),
            "dialect_cache_status": dialect_cache,
            "schema_version": 1,
            "script_cache": {"hits": script_hits, "misses": script_misses},
            "scripts": scripts,
        }
        bundle_digest, _, _ = _publish_artifact(
            roots.artifacts, pretty_json_bytes(bundle)
        )
        registry.put_cache_entry(
            key=cache_key,
            stage_name="lua_archive_extraction",
            artifact_sha256=bundle_digest,
            artifact_logical_path=f"artifact:/objects/sha256/{bundle_digest[:2]}/{bundle_digest}",
            producer_name=LUA_PRODUCER["name"],
            producer_version=LUA_PRODUCER["version"],
            context=context,
            analysis_id=analysis_id,
        )
        step.output_item_count = len(scripts)
        step.output_bytes = sum(int(item["size_bytes"]) for item in scripts)
        step.reason = (
            f"script_cache_hits={script_hits};script_cache_misses={script_misses}"
        )
        return bundle


def _component_revision(role: str, xdf_sha256: str, xdt_sha256: str) -> str:
    return f"component-revision:{digest_json({'kind': 'lua_archive_pair', 'role': role, 'xdf': xdf_sha256, 'xdt': xdt_sha256})}"


def _script_id(logical_path: str) -> str:
    return f"lua-script:{digest_json({'logical_path': logical_path})}"


def _symbol_id(script_id: str, stable_key: str) -> str:
    return f"lua-symbol:{digest_json([script_id, stable_key])}"


def _signature(prototype: dict[str, Any]) -> str:
    parts = [f"{name}: any" for name in prototype.get("parameter_names", [])]
    if prototype.get("is_vararg"):
        parts.append("...")
    return f"fun({', '.join(parts)}): any"


def _binding_classification(path: str) -> tuple[str, str]:
    reference_prefixes = (
        "CS.System",
        "CS.Microsoft",
        "CS.Unity",
        "CS.XLua",
        "CS.Mono",
    )
    if path == "CS" or path.startswith(reference_prefixes):
        return "reference_only", "external_runtime_or_engine_reference"
    if path.startswith("CS.FunPlus.WorldX"):
        return "needs_review", "game_namespace_name_is_evidence_only"
    return "needs_review", "managed_owner_unresolved"


def _ingest_lua_result(
    *,
    registry: Registry,
    manifest: dict[str, Any],
    lua_analysis_id: str,
    analysis_id: str,
    archive_results: list[dict[str, Any]],
) -> dict[str, int]:
    db = registry.db
    build_id = str(manifest["build_id"])
    counts = {
        "bindings": 0,
        "dependencies": 0,
        "observations": 0,
        "symbols": 0,
    }
    module_names = {
        script["module_name"]
        for item in archive_results
        for script in item["bundle"]["scripts"]
    }
    for item in archive_results:
        role = item["role"]
        revision_id = item["component_revision_id"]
        component_id = f"component:lua:{role}"
        bundle = item["bundle"]
        archive = bundle["archive"]
        db.execute(
            "INSERT OR IGNORE INTO components(component_id,logical_name,component_kind) VALUES(?,?,?)",
            (component_id, f"Aniimo Lua archive ({role})", "lua_archive_pair"),
        )
        db.execute(
            """INSERT OR IGNORE INTO component_revisions(
                   component_revision_id,component_id,content_sha256,source_artifact_id,provenance_json
               ) VALUES(?,?,?,?,?)""",
            (
                revision_id,
                component_id,
                digest_json(
                    {
                        "role": role,
                        "xdf": item["xdf_sha256"],
                        "xdt": item["xdt_sha256"],
                    }
                ),
                None,
                canonical_json_bytes(
                    {
                        "archive_role": role,
                        "classification": "game_decompile",
                        "source": "captured_xdf_xdt_pair",
                    }
                ).decode("utf-8"),
            ),
        )
        db.execute(
            "INSERT OR IGNORE INTO build_components(build_id,component_revision_id,role) VALUES(?,?,?)",
            (build_id, revision_id, f"lua_{role}"),
        )
        archive_observation_id = (
            f"lua-archive-observation:{digest_json([lua_analysis_id, role])}"
        )
        db.execute(
            """INSERT INTO lua_archive_observations(
                   lua_archive_observation_id,lua_analysis_id,build_id,
                   component_revision_id,archive_role,xdf_logical_path,xdf_sha256,
                   xdt_logical_path,xdt_sha256,content_version,validation_status,
                   entry_count,lua_entry_count,evidence_json
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                archive_observation_id,
                lua_analysis_id,
                build_id,
                revision_id,
                role,
                item["xdf_logical_path"],
                item["xdf_sha256"],
                item["xdt_logical_path"],
                item["xdt_sha256"],
                archive["content_version"],
                archive["validation_status"],
                archive["entry_count"],
                archive["lua_entry_count"],
                canonical_json_bytes(
                    {
                        "dialect": bundle["dialect"],
                        "non_lua_entries_indexed_only": archive["non_lua_entry_count"],
                        "script_cache": bundle["script_cache"],
                    }
                ).decode("utf-8"),
            ),
        )
        for script in bundle["scripts"]:
            script_id = _script_id(script["logical_path"])
            db.execute(
                "INSERT OR IGNORE INTO lua_scripts(lua_script_id,logical_path,created_at) VALUES(?,?,?)",
                (script_id, script["logical_path"], _utc_now()),
            )
            analysis = script["analysis"]
            observation_id = f"lua-observation:{digest_json([lua_analysis_id, revision_id, script_id])}"
            db.execute(
                """INSERT INTO lua_observations(
                       lua_observation_id,lua_analysis_id,lua_script_id,build_id,
                       component_revision_id,script_sha256,extracted_artifact_sha256,
                       bytecode_format,parse_status,module_name,prototype_count,provenance_json
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    observation_id,
                    lua_analysis_id,
                    script_id,
                    build_id,
                    revision_id,
                    script["script_sha256"],
                    script["extracted_artifact_sha256"],
                    analysis["bytecode_format"],
                    analysis["parse_status"],
                    script["module_name"],
                    len(analysis["prototypes"]),
                    canonical_json_bytes(
                        {
                            "chunk_name_is_absolute": analysis.get(
                                "chunk_name_is_absolute"
                            ),
                            "chunk_name_sha256": analysis.get("chunk_name_sha256"),
                            "instruction_semantics": analysis.get(
                                "instruction_semantics"
                            ),
                        }
                    ).decode("utf-8"),
                ),
            )
            counts["observations"] += 1

            module_stable_key = "module"
            module_symbol_id = _symbol_id(script_id, module_stable_key)
            db.execute(
                "INSERT OR IGNORE INTO lua_symbols(lua_symbol_id,lua_script_id,stable_key,created_at) VALUES(?,?,?,?)",
                (module_symbol_id, script_id, module_stable_key, _utc_now()),
            )
            db.execute(
                """INSERT INTO lua_symbol_observations(
                       lua_symbol_observation_id,lua_symbol_id,lua_analysis_id,build_id,
                       component_revision_id,lua_path,symbol_kind,signature,name_source,
                       signature_source,observation_status,evidence_json
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    f"lua-symbol-observation:{digest_json([lua_analysis_id, revision_id, module_symbol_id])}",
                    module_symbol_id,
                    lua_analysis_id,
                    build_id,
                    revision_id,
                    script["module_name"],
                    "module",
                    None,
                    "archive_path",
                    "not_applicable",
                    "recovered",
                    canonical_json_bytes(
                        {"scope_classification": "game_decompile"}
                    ).decode("utf-8"),
                ),
            )
            counts["symbols"] += 1

            for prototype in analysis["prototypes"]:
                stable_key = f"prototype:{int(prototype['parse_index']):06d}"
                symbol_id = _symbol_id(script_id, stable_key)
                name = prototype.get("prototype_name")
                lua_path = (
                    f"{script['module_name']}.{name}"
                    if name
                    else f"{script['module_name']}#{stable_key}"
                )
                db.execute(
                    "INSERT OR IGNORE INTO lua_symbols(lua_symbol_id,lua_script_id,stable_key,created_at) VALUES(?,?,?,?)",
                    (symbol_id, script_id, stable_key, _utc_now()),
                )
                db.execute(
                    """INSERT INTO lua_symbol_observations(
                           lua_symbol_observation_id,lua_symbol_id,lua_analysis_id,build_id,
                           component_revision_id,lua_path,symbol_kind,signature,name_source,
                           signature_source,observation_status,evidence_json
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        f"lua-symbol-observation:{digest_json([lua_analysis_id, revision_id, symbol_id])}",
                        symbol_id,
                        lua_analysis_id,
                        build_id,
                        revision_id,
                        lua_path,
                        "function",
                        _signature(prototype),
                        "inferred" if name else "unknown",
                        "luajit_debug_metadata",
                        "inferred" if name else "recovered",
                        canonical_json_bytes(
                            {
                                "aliases": prototype.get("aliases", []),
                                "first_line": prototype.get("first_line"),
                                "return_type": {
                                    "source": "unknown",
                                    "value": "any",
                                },
                                "scope_classification": "game_decompile",
                            }
                        ).decode("utf-8"),
                    ),
                )
                counts["symbols"] += 1

            for dependency in analysis["dependencies"]:
                status = "resolved" if dependency in module_names else "unresolved"
                dependency_id = f"lua-dependency:{digest_json([lua_analysis_id, revision_id, script_id, dependency])}"
                db.execute(
                    """INSERT INTO lua_dependencies(
                           lua_dependency_id,lua_analysis_id,build_id,component_revision_id,
                           source_lua_script_id,required_module,resolution_status,evidence_json
                       ) VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        dependency_id,
                        lua_analysis_id,
                        build_id,
                        revision_id,
                        script_id,
                        dependency,
                        status,
                        canonical_json_bytes(
                            {
                                "instruction_semantics": "inferred_bounded_subset",
                                "source": "luajit_require_call_pattern",
                            }
                        ).decode("utf-8"),
                    ),
                )
                counts["dependencies"] += 1

            for binding in analysis["bindings"]:
                classification, reason = _binding_classification(binding["lua_path"])
                binding_id = f"lua-binding:{digest_json([lua_analysis_id, revision_id, script_id, binding['lua_path'], binding['binding_role']])}"
                db.execute(
                    """INSERT INTO lua_bindings(
                           lua_binding_id,lua_analysis_id,build_id,component_revision_id,
                           lua_script_id,lua_path,managed_symbol_id,native_body_id,bridge,
                           binding_role,mapping_status,scope_classification,evidence_json
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        binding_id,
                        lua_analysis_id,
                        build_id,
                        revision_id,
                        script_id,
                        binding["lua_path"],
                        None,
                        None,
                        "xlua",
                        binding["binding_role"],
                        "reference_only"
                        if classification == "reference_only"
                        else "unresolved",
                        classification,
                        canonical_json_bytes(
                            {
                                "managed_metadata_status": "suspected_protection",
                                "reason": reason,
                                "signature": (
                                    "fun(...): any"
                                    if binding["binding_role"] == "callable_reference"
                                    else None
                                ),
                            }
                        ).decode("utf-8"),
                    ),
                )
                counts["bindings"] += 1
    return counts


LUA_KEYWORDS = {
    "and",
    "break",
    "do",
    "else",
    "elseif",
    "end",
    "false",
    "for",
    "function",
    "goto",
    "if",
    "in",
    "local",
    "nil",
    "not",
    "or",
    "repeat",
    "return",
    "then",
    "true",
    "until",
    "while",
}


def _parameter_name(value: str, ordinal: int) -> str:
    return (
        value
        if LUA_IDENTIFIER.fullmatch(value) and value not in LUA_KEYWORDS
        else f"arg{ordinal}"
    )


def _definition_bytes(module: str, analysis: dict[str, Any]) -> bytes:
    lines = [
        "---@meta",
        "",
        "-- Generated editor metadata. Never load this file in the game runtime.",
        f"---@class {module}",
        "local M = {}",
    ]
    emitted: set[str] = set()
    for prototype in analysis.get("prototypes", []):
        raw_name = prototype.get("prototype_name")
        if not raw_name:
            continue
        name = str(raw_name).rsplit(".", 1)[-1]
        if (
            not LUA_IDENTIFIER.fullmatch(name)
            or name in LUA_KEYWORDS
            or name in emitted
        ):
            continue
        emitted.add(name)
        lines.append("")
        parameters: list[str] = []
        for ordinal, raw_parameter in enumerate(
            prototype.get("parameter_names", []), start=1
        ):
            parameter = _parameter_name(str(raw_parameter), ordinal)
            parameters.append(parameter)
            lines.append(f"---@param {parameter} any")
        if prototype.get("is_vararg"):
            parameters.append("...")
            lines.append("---@param ... any")
        lines.append("---@return any")
        lines.append(f"function M.{name}({', '.join(parameters)}) end")
    lines.extend(["", "return M", ""])
    return "\n".join(lines).encode("utf-8")


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _build_output(
    *,
    destination: Path,
    manifest: dict[str, Any],
    analysis_id: str,
    lua_analysis_id: str,
    analysis_key: str,
    archive_results: list[dict[str, Any]],
    bridge: dict[str, Any],
    counts: dict[str, int],
) -> tuple[dict[str, Any], str, int, int]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent)
    )
    try:
        build_id = str(manifest["build_id"])
        symbol_rows: list[dict[str, Any]] = []
        binding_rows: list[dict[str, Any]] = []
        dependency_rows: list[dict[str, Any]] = []
        module_rows: list[dict[str, Any]] = []
        archive_rows: list[dict[str, Any]] = []
        definitions: dict[str, tuple[str, dict[str, Any]]] = {}
        parse_counts: dict[str, int] = {}
        script_hashes: set[str] = set()
        unique_bindings: set[tuple[str, str, str]] = set()

        for item in archive_results:
            revision_id = item["component_revision_id"]
            role = item["role"]
            bundle = item["bundle"]
            archive = bundle["archive"]
            archive_rows.append(
                {
                    "archive_role": role,
                    "component_revision_id": revision_id,
                    "content_version": archive["content_version"],
                    "entry_count": archive["entry_count"],
                    "lua_entry_count": archive["lua_entry_count"],
                    "validation_status": archive["validation_status"],
                    "xdf_sha256": item["xdf_sha256"],
                    "xdt_sha256": item["xdt_sha256"],
                }
            )
            for script in bundle["scripts"]:
                script_id = _script_id(script["logical_path"])
                observation_id = f"lua-observation:{digest_json([lua_analysis_id, revision_id, script_id])}"
                script_hashes.add(script["script_sha256"])
                analysis = script["analysis"]
                parse_status = str(analysis["parse_status"])
                parse_counts[parse_status] = parse_counts.get(parse_status, 0) + 1
                module_rows.append(
                    {
                        "archive_role": role,
                        "bytecode_format": analysis["bytecode_format"],
                        "component_revision_id": revision_id,
                        "logical_path": script["logical_path"],
                        "module_name": script["module_name"],
                        "parse_status": parse_status,
                        "prototype_count": len(analysis["prototypes"]),
                        "script_sha256": script["script_sha256"],
                    }
                )
                module_symbol_id = _symbol_id(script_id, "module")
                symbol_rows.append(
                    {
                        "schema_version": 1,
                        "build_id": build_id,
                        "component_revision_id": revision_id,
                        "analysis_id": analysis_id,
                        "lua_symbol_id": module_symbol_id,
                        "lua_path": script["module_name"],
                        "kind": "module",
                        "signature": "",
                        "name_source": "archive_path",
                        "signature_source": "",
                        "availability_context": role,
                        "ownership_status": "game_archive_observed",
                        "scope_classification": "game_decompile",
                        "observation_status": "recovered",
                        "evidence_id": observation_id,
                    }
                )
                for prototype in analysis["prototypes"]:
                    stable_key = f"prototype:{int(prototype['parse_index']):06d}"
                    symbol_id = _symbol_id(script_id, stable_key)
                    name = prototype.get("prototype_name")
                    lua_path = (
                        f"{script['module_name']}.{name}"
                        if name
                        else f"{script['module_name']}#{stable_key}"
                    )
                    symbol_rows.append(
                        {
                            "schema_version": 1,
                            "build_id": build_id,
                            "component_revision_id": revision_id,
                            "analysis_id": analysis_id,
                            "lua_symbol_id": symbol_id,
                            "lua_path": lua_path,
                            "kind": "function",
                            "signature": _signature(prototype),
                            "name_source": "inferred" if name else "unknown",
                            "signature_source": "luajit_debug_metadata",
                            "availability_context": role,
                            "ownership_status": "game_archive_observed",
                            "scope_classification": "game_decompile",
                            "observation_status": "inferred" if name else "recovered",
                            "evidence_id": observation_id,
                        }
                    )
                for dependency in analysis["dependencies"]:
                    dependency_rows.append(
                        {
                            "archive_role": role,
                            "component_revision_id": revision_id,
                            "required_module": dependency,
                            "source_module": script["module_name"],
                            "source_script_sha256": script["script_sha256"],
                            "status": "observed_require_pattern",
                        }
                    )
                for binding in analysis["bindings"]:
                    classification, _ = _binding_classification(binding["lua_path"])
                    key = (revision_id, script_id, binding["lua_path"])
                    if key in unique_bindings:
                        continue
                    unique_bindings.add(key)
                    binding_rows.append(
                        {
                            "schema_version": 1,
                            "build_id": build_id,
                            "component_revision_id": revision_id,
                            "analysis_id": analysis_id,
                            "lua_symbol_id": module_symbol_id,
                            "lua_path": binding["lua_path"],
                            "managed_symbol_id": "",
                            "native_body_id": "",
                            "bridge": "xlua",
                            "binding_role": binding["binding_role"],
                            "mapping_status": (
                                "reference_only"
                                if classification == "reference_only"
                                else "unresolved"
                            ),
                            "evidence_id": observation_id,
                        }
                    )
                definitions.setdefault(
                    script["logical_path"], (script["module_name"], analysis)
                )

        symbol_fields = [
            "schema_version",
            "build_id",
            "component_revision_id",
            "analysis_id",
            "lua_symbol_id",
            "lua_path",
            "kind",
            "signature",
            "name_source",
            "signature_source",
            "availability_context",
            "ownership_status",
            "scope_classification",
            "observation_status",
            "evidence_id",
        ]
        binding_fields = [
            "schema_version",
            "build_id",
            "component_revision_id",
            "analysis_id",
            "lua_symbol_id",
            "lua_path",
            "managed_symbol_id",
            "native_body_id",
            "bridge",
            "binding_role",
            "mapping_status",
            "evidence_id",
        ]
        _write_csv(staging / "lua_symbols.csv", symbol_fields, symbol_rows)
        _write_csv(staging / "lua_bindings.csv", binding_fields, binding_rows)
        _write_csv(
            staging / "lua_modules.csv",
            [
                "archive_role",
                "component_revision_id",
                "logical_path",
                "module_name",
                "script_sha256",
                "bytecode_format",
                "parse_status",
                "prototype_count",
            ],
            module_rows,
        )
        _write_csv(
            staging / "lua_dependencies.csv",
            [
                "archive_role",
                "component_revision_id",
                "source_module",
                "required_module",
                "source_script_sha256",
                "status",
            ],
            dependency_rows,
        )
        _write_csv(
            staging / "lua_archives.csv",
            [
                "archive_role",
                "component_revision_id",
                "xdf_sha256",
                "xdt_sha256",
                "content_version",
                "validation_status",
                "entry_count",
                "lua_entry_count",
            ],
            archive_rows,
        )

        for logical_path, (module, analysis) in sorted(definitions.items()):
            relative = logical_path.removeprefix("xfs/luascripts/")
            if relative.lower().endswith(".lua"):
                relative = relative[:-4] + ".d.lua"
            target = staging / "definitions" / Path(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_definition_bytes(module, analysis))

        game_binding_count = sum(
            1 for row in binding_rows if row["lua_path"].startswith("CS.FunPlus.WorldX")
        )
        external_binding_count = sum(
            1 for row in binding_rows if row["mapping_status"] == "reference_only"
        )
        coverage = {
            "archive_component_count": len(archive_results),
            "binding_count": len(binding_rows),
            "discovery_complete": False,
            "external_reference_binding_count": external_binding_count,
            "game_binding_candidate_count": game_binding_count,
            "lua_entry_observation_count": len(module_rows),
            "parse_status_counts": parse_counts,
            "runtime_scenario_count": 0,
            "runtime_status": "not_tested",
            "schema_version": 1,
            "signature_unknown_count": sum(
                1 for row in binding_rows if row["binding_role"] == "callable_reference"
            ),
            "unique_script_count": len(script_hashes),
        }
        summary = {
            "analysis_id": analysis_id,
            "analysis_key": analysis_key,
            "bridge": bridge,
            "build_id": build_id,
            "counts": {**counts, **coverage},
            "lua_analysis_id": lua_analysis_id,
            "producer": LUA_PRODUCER,
            "runtime_probe": {
                "executed": False,
                "reason": "static_milestone_runtime_probe_requires_authorized_game_process",
                "status": "not_tested",
            },
            "schema_version": 1,
            "snapshot_id": manifest["snapshot_id"],
        }
        (staging / "lua-analysis.json").write_bytes(pretty_json_bytes(summary))
        (staging / "lua-coverage.json").write_bytes(pretty_json_bytes(coverage))
        (staging / "runtime-probe-status.json").write_bytes(
            pretty_json_bytes(summary["runtime_probe"])
        )
        (staging / "README.md").write_text(
            "# Analyse Lua générée\n\n"
            "Ces fichiers décrivent des preuves statiques. Les définitions LuaLS "
            "servent uniquement à l'éditeur et ne doivent jamais être chargées dans le jeu.\n\n"
            "Les chemins `CS.*` sans identité managée résolue restent des candidats ou "
            "des références externes. Une signature `fun(...): any` indique explicitement "
            "qu'aucun type métier n'est établi.\n",
            encoding="utf-8",
        )

        files: list[dict[str, Any]] = []
        for path in sorted(staging.rglob("*"), key=lambda value: value.as_posix()):
            if path.is_file() and path.name != "output-manifest.json":
                digest, size = sha256_file(path)
                files.append(
                    {
                        "path": path.relative_to(staging).as_posix(),
                        "sha256": digest,
                        "size_bytes": size,
                    }
                )
        output_manifest = {
            "analysis_key": analysis_key,
            "build_id": build_id,
            "files": files,
            "lua_analysis_id": lua_analysis_id,
            "schema_version": 1,
            "snapshot_id": manifest["snapshot_id"],
        }
        manifest_bytes = pretty_json_bytes(output_manifest)
        (staging / "output-manifest.json").write_bytes(manifest_bytes)
        manifest_sha256 = sha256_bytes(manifest_bytes)
        file_count = len(files) + 1
        byte_count = sum(int(item["size_bytes"]) for item in files) + len(
            manifest_bytes
        )
        if destination.exists():
            raise ValidationError(
                "Destination Lua déjà présente sans cache valide.",
                error_code="lua_output_conflict",
            )
        os.replace(staging, destination)
        fsync_directory(destination.parent)
        return summary, manifest_sha256, file_count, byte_count
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _analyze_bridge(
    *, roots: LuaRoots, manifest: dict[str, Any], registry: Registry
) -> dict[str, Any]:
    candidates = [
        item
        for item in manifest.get("payloads", [])
        if "lua_bridge_reference" in item.get("roles", [])
    ]
    if len(candidates) != 1:
        raise ValidationError(
            "Bridge Lua capturé absent ou ambigu.", error_code="lua_bridge_missing"
        )
    payload = candidates[0]
    digest = str(payload["sha256"])
    path = object_path(roots.inputs, digest)
    pe = PeImage(path)
    exports = pe.export_names()
    lua_exports = [name for name in exports if name.startswith(("lua_", "luaL_"))]
    if not lua_exports:
        raise ValidationError(
            "Le module de bridge ne présente pas l'API Lua attendue.",
            error_code="lua_bridge_unconfirmed",
        )
    component_id = "component:lua-bridge:xlua"
    revision_id = f"component-revision:{digest_json([component_id, digest])}"
    registry.db.execute(
        "INSERT OR IGNORE INTO components(component_id,logical_name,component_kind) VALUES(?,?,?)",
        (component_id, "xLua native bridge", "lua_bridge_reference"),
    )
    registry.db.execute(
        """INSERT OR IGNORE INTO component_revisions(
               component_revision_id,component_id,content_sha256,source_artifact_id,provenance_json
           ) VALUES(?,?,?,?,?)""",
        (
            revision_id,
            component_id,
            digest,
            None,
            canonical_json_bytes(
                {
                    "classification": "reference_only",
                    "implementation_exported": False,
                    "reason": "generic_lua_runtime_bridge",
                }
            ).decode("utf-8"),
        ),
    )
    registry.db.execute(
        "INSERT OR IGNORE INTO build_components(build_id,component_revision_id,role) VALUES(?,?,?)",
        (manifest["build_id"], revision_id, "lua_bridge_reference"),
    )
    return {
        "architecture": pe.architecture,
        "classification": "reference_only",
        "component_revision_id": revision_id,
        "implementation_exported": False,
        "lua_api_export_count": len(lua_exports),
        "module_logical_path": payload["logical_path"],
        "module_sha256": digest,
        "name": "xlua",
        "official_documentation": "https://github.com/Tencent/xLua",
        "pe_export_count": len(exports),
    }


def _valid_cached_output(destination: Path, expected_sha256: str | None) -> bool:
    manifest_path = destination / "output-manifest.json"
    if not expected_sha256 or not manifest_path.is_file():
        return False
    return sha256_file(manifest_path)[0] == expected_sha256


def analyze_lua_snapshot(
    *,
    roots: LuaRoots,
    snapshot_id: str,
    profile: LoadedYaml,
    input_profile: LoadedYaml,
    migrations_root: Path,
    enforce_read_only_inputs: bool,
    workflow_run_id: str | None = None,
) -> dict[str, Any]:
    """Analyze captured Lua archives without loading any game script."""
    assert_no_live_source_environment()
    if enforce_read_only_inputs:
        assert_inputs_read_only(roots.inputs)
    manifest, manifest_digest = _load_snapshot(roots, snapshot_id, input_profile)
    payloads = _payloads(manifest)
    specs = _archive_specs(profile)
    for spec in specs:
        for key in ("xdf", "xdt"):
            if spec[key] not in payloads:
                raise ValidationError(
                    f"Entrée Lua absente du snapshot : {spec[key]}",
                    error_code="lua_archive_missing",
                )
    bridge_payloads = [
        item
        for item in manifest.get("payloads", [])
        if "lua_bridge_reference" in item.get("roles", [])
    ]
    if len(bridge_payloads) != 1:
        raise ValidationError(
            "Bridge Lua capturé absent ou ambigu.", error_code="lua_bridge_missing"
        )

    parser_digest = sha256_file(Path(__file__).with_name("luajit.py"))[0]
    producer_digest = _producer_digest()
    basis = {
        "archives": [
            {
                "role": spec["role"],
                "xdf": payloads[spec["xdf"]]["sha256"],
                "xdt": payloads[spec["xdt"]]["sha256"],
            }
            for spec in specs
        ],
        "bridge_sha256": bridge_payloads[0]["sha256"],
        "parser_digest": parser_digest,
        "producer_digest": producer_digest,
        "profile_sha256": profile.sha256,
        "snapshot_id": snapshot_id,
    }
    analysis_key = f"m4-{digest_json(basis)}"
    lua_analysis_id = f"lua-analysis:{analysis_key}"
    destination = (
        roots.output
        / "builds"
        / str(manifest["build_id"])
        / f"lua-{analysis_key[3:23]}"
    )
    run_id = workflow_run_id or f"run-m4-{uuid.uuid4().hex}"
    analysis_id = f"analysis:{uuid.uuid4()}"
    report = RunReport(run_id, "lua-static-analysis")
    report.snapshot_id = snapshot_id
    report.metadata = {
        "analysis_key": analysis_key,
        "build_id": manifest["build_id"],
        "lua_analysis_id": lua_analysis_id,
        "runtime_probe_status": "not_tested",
    }

    with (
        registry_writer_lock(roots.state),
        Registry(roots.state / "registry.sqlite", migrations_root) as registry,
    ):
        registry.transaction()
        try:
            _register_snapshot(registry, manifest, manifest_digest, run_id)
            registry.db.execute(
                """INSERT INTO analysis_runs(
                           analysis_id,workflow_run_id,snapshot_id,analysis_key,status,started_at
                       ) VALUES(?,?,?,?,?,?)""",
                (
                    analysis_id,
                    run_id,
                    snapshot_id,
                    analysis_key,
                    "running",
                    report.started_at,
                ),
            )
            cached = registry.db.execute(
                """SELECT output_manifest_sha256 FROM lua_analyses
                       WHERE lua_analysis_key=? AND status='completed'""",
                (analysis_key,),
            ).fetchone()
            if cached is not None and _valid_cached_output(destination, cached[0]):
                report.add_step(
                    "lua.analysis",
                    "lua_static_analysis",
                    category="analysis",
                    status="cache_hit",
                    reason="complete_lua_analysis_key_match",
                    cache_status="hit",
                    tool_name=LUA_PRODUCER["name"],
                    tool_version=LUA_PRODUCER["version"],
                )
                report.add_step(
                    "lua.documentation",
                    "lua_documentation",
                    category="publication",
                    status="cache_hit",
                    reason="content_identical_no_rewrite",
                    cache_status="hit",
                    tool_name=LUA_PRODUCER["name"],
                    tool_version=LUA_PRODUCER["version"],
                )
                report.finish("completed")
                registry.db.execute(
                    "UPDATE analysis_runs SET status='completed',ended_at=? WHERE analysis_id=?",
                    (report.ended_at, analysis_id),
                )
                _store_report_steps(registry.db, analysis_id=analysis_id, report=report)
                registry.commit()
                publish_report(roots.output, report.public())
                result = read_json(destination / "lua-analysis.json")
                result["cache_status"] = "hit"
                result["output_root"] = destination.relative_to(roots.output).as_posix()
                result["workflow_run_id"] = run_id
                return result

            registry.db.execute(
                """INSERT INTO lua_analyses(
                           lua_analysis_id,lua_analysis_key,analysis_id,build_id,
                           producer_digest,profile_digest,status,created_at
                       ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    lua_analysis_id,
                    analysis_key,
                    analysis_id,
                    manifest["build_id"],
                    producer_digest,
                    profile.sha256,
                    "partial",
                    _utc_now(),
                ),
            )

            archive_results: list[dict[str, Any]] = []
            for spec in specs:
                xdf_payload = payloads[spec["xdf"]]
                xdt_payload = payloads[spec["xdt"]]
                xdf_sha256 = str(xdf_payload["sha256"])
                xdt_sha256 = str(xdt_payload["sha256"])
                bundle = _validate_and_analyze_archive(
                    registry=registry,
                    roots=roots,
                    xdf_path=object_path(roots.inputs, xdf_sha256),
                    xdt_path=object_path(roots.inputs, xdt_sha256),
                    xdf_sha256=xdf_sha256,
                    xdt_sha256=xdt_sha256,
                    archive_role=spec["role"],
                    parser_digest=parser_digest,
                    analysis_id=analysis_id,
                    report=report,
                )
                archive_results.append(
                    {
                        "bundle": bundle,
                        "component_revision_id": _component_revision(
                            spec["role"], xdf_sha256, xdt_sha256
                        ),
                        "role": spec["role"],
                        "xdf_logical_path": spec["xdf"],
                        "xdf_sha256": xdf_sha256,
                        "xdt_logical_path": spec["xdt"],
                        "xdt_sha256": xdt_sha256,
                    }
                )

            with report.step(
                "lua.bridge",
                "lua_bridge_reference",
                category="analysis",
                cache_status="not_applicable",
                tool_name="modkit.pe",
                tool_version=LUA_PRODUCER["version"],
            ) as bridge_step:
                bridge = _analyze_bridge(
                    roots=roots, manifest=manifest, registry=registry
                )
                bridge_step.input_item_count = 1
                bridge_step.input_bytes = int(bridge_payloads[0]["size_bytes"])
                bridge_step.output_item_count = int(bridge["lua_api_export_count"])

            counts = _ingest_lua_result(
                registry=registry,
                manifest=manifest,
                lua_analysis_id=lua_analysis_id,
                analysis_id=analysis_id,
                archive_results=archive_results,
            )
            with report.step(
                "lua.documentation",
                "lua_documentation",
                category="publication",
                cache_status="miss",
                tool_name=LUA_PRODUCER["name"],
                tool_version=LUA_PRODUCER["version"],
            ) as publication_step:
                summary, output_manifest_sha256, file_count, byte_count = _build_output(
                    destination=destination,
                    manifest=manifest,
                    analysis_id=analysis_id,
                    lua_analysis_id=lua_analysis_id,
                    analysis_key=analysis_key,
                    archive_results=archive_results,
                    bridge=bridge,
                    counts=counts,
                )
                publication_step.input_item_count = counts["observations"]
                publication_step.output_item_count = file_count
                publication_step.output_bytes = byte_count

            report.finish("completed")
            registry.db.execute(
                """UPDATE lua_analyses SET status='completed',output_manifest_sha256=?,completed_at=?
                       WHERE lua_analysis_id=?""",
                (output_manifest_sha256, report.ended_at, lua_analysis_id),
            )
            registry.db.execute(
                "UPDATE analysis_runs SET status='completed',ended_at=? WHERE analysis_id=?",
                (report.ended_at, analysis_id),
            )
            _store_report_steps(registry.db, analysis_id=analysis_id, report=report)
            registry.commit()
        except BaseException:
            registry.rollback()
            raise

    publish_report(roots.output, report.public())
    summary["cache_status"] = "miss"
    summary["output_root"] = destination.relative_to(roots.output).as_posix()
    summary["workflow_run_id"] = run_id
    return summary


def import_runtime_observations(
    *,
    roots: LuaRoots,
    observation_path: Path,
    migrations_root: Path,
) -> dict[str, Any]:
    """Validate and import a probe result produced in an authorized process."""
    data = observation_path.read_bytes()
    if len(data) > 64 * 1024 * 1024:
        raise ValidationError(
            "Observation runtime trop volumineuse.",
            error_code="lua_runtime_observation_too_large",
        )
    try:
        value = json.loads(data)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError(
            "Observation runtime JSON invalide.",
            error_code="lua_runtime_observation_invalid",
        ) from exc
    required = {
        "schema_version",
        "snapshot_id",
        "build_id",
        "probe_version",
        "bridge",
        "vm_identity",
        "module_sha256",
        "scenario",
        "observations",
        "coverage",
    }
    if not isinstance(value, dict) or not required.issubset(value):
        raise ValidationError(
            "Observation runtime incomplète.",
            error_code="lua_runtime_observation_invalid",
        )
    if value["schema_version"] != 1:
        raise ValidationError(
            "Version d'observation runtime non prise en charge.",
            error_code="lua_runtime_observation_unsupported",
        )
    observations = value["observations"]
    scenario = value["scenario"]
    coverage = value["coverage"]
    if (
        not isinstance(observations, list)
        or len(observations) > 100_000
        or not isinstance(scenario, dict)
        or not {"name", "phase", "description"}.issubset(scenario)
        or any(
            not isinstance(scenario[field], str)
            or not scenario[field]
            or len(scenario[field]) > 4096
            for field in ("name", "phase", "description")
        )
        or not isinstance(coverage, dict)
        or coverage.get("exhaustive") is not False
        or any(
            coverage.get(field) != 0
            for field in (
                "getters_invoked",
                "modules_loaded",
                "unknown_functions_invoked",
            )
        )
    ):
        raise ValidationError(
            "Observation runtime hors limites.",
            error_code="lua_runtime_observation_invalid",
        )
    snapshot_id = str(value["snapshot_id"])
    manifest_path = roots.inputs / "snapshots" / snapshot_id / "capture-manifest.json"
    if not manifest_path.is_file():
        raise ValidationError(
            "Snapshot de l'observation runtime absent.",
            error_code="lua_runtime_snapshot_missing",
        )
    manifest = read_json(manifest_path)
    if (
        manifest.get("snapshot_id") != snapshot_id
        or manifest.get("build_id") != value["build_id"]
    ):
        raise ValidationError(
            "Observation Lua provenant d'un autre build.",
            error_code="lua_runtime_build_mismatch",
        )
    bridge_payloads = [
        item
        for item in manifest.get("payloads", [])
        if "lua_bridge_reference" in item.get("roles", [])
    ]
    if len(bridge_payloads) != 1 or value["module_sha256"] != bridge_payloads[0].get(
        "sha256"
    ):
        raise ValidationError(
            "Observation Lua liée à un autre module runtime.",
            error_code="lua_runtime_module_mismatch",
        )
    source_sha256 = sha256_bytes(data)
    import_id = f"lua-runtime-import:{source_sha256}"
    scenario_id = f"lua-scenario:{digest_json([scenario['name'], scenario['phase'], value['probe_version']])}"
    with (
        registry_writer_lock(roots.state),
        Registry(roots.state / "registry.sqlite", migrations_root) as registry,
    ):
        registry.transaction()
        try:
            _register_snapshot(
                registry,
                manifest,
                sha256_file(manifest_path)[0],
                f"lua-import-{source_sha256[:16]}",
            )
            existing = registry.db.execute(
                "SELECT runtime_observation_import_id FROM runtime_observation_imports WHERE source_sha256=?",
                (source_sha256,),
            ).fetchone()
            if existing is not None:
                registry.rollback()
                return {
                    "build_id": value["build_id"],
                    "cache_status": "hit",
                    "import_id": existing[0],
                    "observation_count": len(observations),
                    "status": "imported",
                }
            registry.db.execute(
                """INSERT OR IGNORE INTO observation_scenarios(
                           observation_scenario_id,name,phase,description,probe_version
                       ) VALUES(?,?,?,?,?)""",
                (
                    scenario_id,
                    str(scenario["name"]),
                    str(scenario["phase"]),
                    str(scenario["description"]),
                    str(value["probe_version"]),
                ),
            )
            registry.db.execute(
                """INSERT INTO runtime_observation_imports(
                           runtime_observation_import_id,build_id,snapshot_id,probe_version,
                           bridge,vm_identity,source_sha256,status,imported_at
                       ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    import_id,
                    value["build_id"],
                    snapshot_id,
                    str(value["probe_version"]),
                    str(value["bridge"]),
                    str(value["vm_identity"]),
                    source_sha256,
                    "imported",
                    _utc_now(),
                ),
            )
            for ordinal, observation in enumerate(observations):
                if not isinstance(observation, dict) or not {
                    "lua_path",
                    "value_kind",
                }.issubset(observation):
                    raise ValidationError(
                        "Entrée d'observation Lua invalide.",
                        error_code="lua_runtime_observation_invalid",
                    )
                lua_path = str(observation["lua_path"])
                if not lua_path or len(lua_path) > 4096 or "\0" in lua_path:
                    raise ValidationError(
                        "Chemin d'observation Lua invalide.",
                        error_code="lua_runtime_observation_invalid",
                    )
                value_kind = str(observation["value_kind"])
                if value_kind not in {
                    "boolean",
                    "function",
                    "nil",
                    "number",
                    "string",
                    "table",
                    "table_cycle",
                    "thread",
                    "userdata",
                }:
                    raise ValidationError(
                        "Type d'observation Lua invalide.",
                        error_code="lua_runtime_observation_invalid",
                    )
                signature = (
                    "fun(...): any"
                    if value_kind in {"function", "c_function"}
                    else None
                )
                evidence = {
                    "argument_types_inferred": False,
                    "getter_invoked": False,
                    "nparams_observation": observation.get("nparams"),
                    "signature_source": "unknown",
                }
                registry.db.execute(
                    """INSERT INTO runtime_observations(
                               runtime_observation_id,runtime_observation_import_id,
                               observation_scenario_id,lua_path,value_kind,signature,
                               observation_status,evidence_json
                           ) VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        f"lua-runtime-observation:{digest_json([import_id, ordinal, lua_path])}",
                        import_id,
                        scenario_id,
                        lua_path,
                        value_kind,
                        signature,
                        "observed",
                        canonical_json_bytes(evidence).decode("utf-8"),
                    ),
                )
            registry.commit()
        except BaseException:
            registry.rollback()
            raise
    return {
        "build_id": value["build_id"],
        "cache_status": "miss",
        "import_id": import_id,
        "observation_count": len(observations),
        "status": "imported",
    }
