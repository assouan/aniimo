from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from modkit.capture import publish_snapshot
from modkit.config import load_yaml
from modkit.errors import ValidationError
from modkit.lua_analysis import (
    LuaRoots,
    analyze_lua_snapshot,
    import_runtime_observations,
)
from modkit.luajit import (
    LuaConstant,
    LuaJITChunk,
    LuaJITParseError,
    LuaPrototype,
    analyze_luajit_chunk,
    infer_opcode_dialect,
    parse_luajit_chunk,
)
from modkit.planner import build_capture_plan
from modkit.util import read_json

ROOT = Path(__file__).resolve().parents[1]


def _uleb(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def _debug_chunk() -> bytes:
    name = b"@C:\\private\\developer\\Ability.lua"
    debug = b"\x00alpha\x00\x00\x01beta\x00\x00\x01\x00"
    prototype = bytearray((0, 2, 3, 0, 0, 0, 1))
    prototype += _uleb(len(debug)) + _uleb(12) + _uleb(1)
    prototype += (0).to_bytes(4, "little")
    prototype += debug
    return (
        b"\x1bLJ\x02\x00"
        + _uleb(len(name))
        + name
        + _uleb(len(prototype))
        + prototype
        + b"\x00"
    )


def _instruction(opcode: int, register: int, operand: int) -> int:
    return opcode | (register << 8) | (operand << 16)


def _dialect_chunk() -> LuaJITChunk:
    child = LuaPrototype(
        parse_index=0,
        flags=0,
        num_params=0,
        frame_size=1,
        upvalue_count=0,
        instructions=(),
        constants=(),
        first_line=None,
        line_count=None,
        parameter_names=(),
    )
    constants = (
        LuaConstant("child", child),
        LuaConstant("string", b"AssignedName"),
        LuaConstant("string", b"game.module"),
        LuaConstant("string", b"require"),
    )
    parent = LuaPrototype(
        parse_index=1,
        flags=0,
        num_params=0,
        frame_size=8,
        upvalue_count=0,
        instructions=(
            _instruction(57, 1, 0),
            _instruction(39, 3, 1),
            _instruction(66, 1, 2),
            _instruction(50, 4, 3),
            _instruction(63, 4, 2),
        ),
        constants=constants,
        first_line=None,
        line_count=None,
        parameter_names=(),
    )
    return LuaJITChunk(
        version=2,
        flags=0x08,
        chunk_name_sha256=None,
        chunk_name_is_absolute=False,
        prototypes=(child, parent),
        root=parent,
    )


def _write_archive(path: Path, entries: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, data)


def _write_index(xdf: Path, xdt: Path, version: str) -> None:
    rows = []
    with zipfile.ZipFile(xdf) as archive:
        for ordinal, info in enumerate(archive.infolist()):
            with xdf.open("rb") as stream:
                stream.seek(info.header_offset + 26)
                name_length = int.from_bytes(stream.read(2), "little")
                extra_length = int.from_bytes(stream.read(2), "little")
            data = archive.read(info)
            rows.append(
                {
                    "CEName": info.filename,
                    "CEMD5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
                    "CESize": info.file_size,
                    "CEIndex": ordinal,
                    "CEOffset": info.header_offset + 30 + name_length + extra_length,
                    "CECSize": info.compress_size,
                    "CEContainer": 0,
                }
            )
    value = {
        "CMSign": "fixture",
        "CMVersion": version,
        "CMToolVer": "fixture",
        "CMCompress": 0,
        "CMDataLen": xdf.stat().st_size,
        "CMDataMD5": hashlib.md5(xdf.read_bytes(), usedforsecurity=False).hexdigest(),
        "CMEntryNum": len(rows),
        "CMList": rows,
    }
    xdt.parent.mkdir(parents=True, exist_ok=True)
    xdt.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


class LuaFixture:
    def __init__(self, root: Path) -> None:
        self.game = root / "game"
        self.inputs = root / "inputs"
        self.state = root / "state"
        self.artifacts = root / "artifacts"
        self.work = root / "work"
        self.output = root / "output"
        self.steam = root / "appmanifest.acf"
        (self.game / "Aniimo_Data").mkdir(parents=True)
        (self.game / "Aniimo.exe").write_bytes(b"fixture")
        (self.game / "Aniimo_Data/globalgamemanagers").write_bytes(
            b"2022.3.62f1\0fixture"
        )
        bridge = self.game / "Aniimo_Data/Plugins/x86_64/xlua.dll"
        bridge.parent.mkdir(parents=True)
        bridge.write_bytes(b"fixture-xlua-reference")
        entries = {
            "xfs/luascripts/Ability.lua": _debug_chunk(),
            "xfs/luascripts/Unknown.lua": b"unsupported-vendor-bytecode",
            "xfs/config.json": b'{"fixture":true}',
        }
        active_xdf = self.game / "Aniimo_Data/cvs/res/lua/LuaScripts.xdf"
        active_xdt = self.game / "Aniimo_Data/cvs/res/lua/LuaScripts.xdt"
        bundled_xdf = (
            self.game / "Aniimo_Data/StreamingAssets/cvs/res/lua/LuaScripts.xdf"
        )
        bundled_xdt = (
            self.game / "Aniimo_Data/StreamingAssets/cvs/res/lua/LuaScripts.xdt"
        )
        _write_archive(active_xdf, entries)
        bundled_xdf.parent.mkdir(parents=True)
        bundled_xdf.write_bytes(active_xdf.read_bytes())
        _write_index(active_xdf, active_xdt, "active-fixture")
        _write_index(bundled_xdf, bundled_xdt, "bundled-fixture")
        self.steam.write_text(
            '"AppState"\n{\n"appid" "4126040"\n"StateFlags" "4"\n'
            '"buildid" "m4-fixture"\n}\n',
            encoding="utf-8",
        )
        self.profile = load_yaml(ROOT / "profiles/aniimo.yaml")
        self.selection = load_yaml(ROOT / "profiles/aniimo.inputs.yaml")
        captured = publish_snapshot(
            build_capture_plan(self.selection, self.game, self.steam),
            self.inputs,
            workflow_run_id="capture-m4-fixture",
        )
        self.snapshot_id = str(captured["snapshot_id"])

    @property
    def roots(self) -> LuaRoots:
        return LuaRoots(
            inputs=self.inputs,
            state=self.state,
            artifacts=self.artifacts,
            work=self.work,
            output=self.output,
        )

    def analyze(self, run_id: str) -> dict[str, object]:
        def fake_bridge(*, roots, manifest, registry):
            del roots
            payload = next(
                item
                for item in manifest["payloads"]
                if "lua_bridge_reference" in item["roles"]
            )
            digest = payload["sha256"]
            component_id = "component:lua-bridge:fixture-xlua"
            revision_id = f"component-revision:{digest}"
            registry.db.execute(
                "INSERT OR IGNORE INTO components(component_id,logical_name,component_kind) VALUES(?,?,?)",
                (component_id, "Fixture xLua bridge", "lua_bridge_reference"),
            )
            registry.db.execute(
                """INSERT OR IGNORE INTO component_revisions(
                       component_revision_id,component_id,content_sha256,
                       source_artifact_id,provenance_json
                   ) VALUES(?,?,?,?,?)""",
                (revision_id, component_id, digest, None, "{}"),
            )
            registry.db.execute(
                "INSERT OR IGNORE INTO build_components(build_id,component_revision_id,role) VALUES(?,?,?)",
                (manifest["build_id"], revision_id, "lua_bridge_reference"),
            )
            return {
                "architecture": "x86_64",
                "classification": "reference_only",
                "component_revision_id": revision_id,
                "implementation_exported": False,
                "lua_api_export_count": 1,
                "module_logical_path": payload["logical_path"],
                "module_sha256": digest,
                "name": "xlua",
                "official_documentation": "https://github.com/Tencent/xLua",
                "pe_export_count": 1,
            }

        with mock.patch("modkit.lua_analysis._analyze_bridge", side_effect=fake_bridge):
            return analyze_lua_snapshot(
                roots=self.roots,
                snapshot_id=self.snapshot_id,
                profile=self.profile,
                input_profile=self.selection,
                migrations_root=ROOT / "migrations",
                enforce_read_only_inputs=False,
                workflow_run_id=run_id,
            )


class LuaJITParserTests(unittest.TestCase):
    def test_debug_metadata_is_bounded_and_source_path_is_only_hashed(self) -> None:
        chunk = parse_luajit_chunk(_debug_chunk())
        self.assertTrue(chunk.chunk_name_is_absolute)
        self.assertEqual(len(chunk.chunk_name_sha256 or ""), 64)
        self.assertEqual(chunk.root.parameter_names, ("alpha", "beta"))
        self.assertEqual(chunk.root.first_line, 12)
        serialized = json.dumps(analyze_luajit_chunk(chunk))
        self.assertNotIn("private", serialized)
        self.assertNotIn("developer", serialized)

    def test_vendor_opcode_subset_requires_repeated_typed_patterns(self) -> None:
        chunks = [_dialect_chunk() for _ in range(8)]
        dialect = infer_opcode_dialect(chunks)
        self.assertIsNotNone(dialect)
        assert dialect is not None
        self.assertEqual(
            (dialect.gget, dialect.kstr, dialect.call, dialect.fnew, dialect.tsets),
            (57, 39, 66, 50, 63),
        )
        recovered = analyze_luajit_chunk(chunks[0], dialect)
        self.assertEqual(recovered["dependencies"], ["game.module"])
        self.assertEqual(recovered["prototypes"][0]["prototype_name"], "AssignedName")
        self.assertIsNone(infer_opcode_dialect(chunks[:7]))

    def test_unknown_bytecode_fails_closed(self) -> None:
        with self.assertRaises(LuaJITParseError) as raised:
            parse_luajit_chunk(b"not-luajit")
        self.assertEqual(raised.exception.code, "unsupported_bytecode_format")


class M4IntegrationTests(unittest.TestCase):
    def test_archives_cache_output_and_runtime_provenance(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            fixture = LuaFixture(Path(temporary))
            first = fixture.analyze("run-m4-fixture-a")
            self.assertEqual(first["cache_status"], "miss")
            self.assertEqual(first["runtime_probe"]["status"], "not_tested")
            output = fixture.output / str(first["output_root"])
            manifest_path = output / "output-manifest.json"
            before = (manifest_path.stat().st_mtime_ns, manifest_path.read_bytes())
            second = fixture.analyze("run-m4-fixture-b")
            after = (manifest_path.stat().st_mtime_ns, manifest_path.read_bytes())
            self.assertEqual(second["cache_status"], "hit")
            self.assertEqual(before, after)
            self.assertTrue((output / "definitions/Ability.d.lua").is_file())
            self.assertNotIn(
                b"C:\\private",
                b"".join(
                    path.read_bytes() for path in output.rglob("*") if path.is_file()
                ),
            )

            registry_path = fixture.state / "registry.sqlite"
            with sqlite3.connect(registry_path) as db:
                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 9)
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                revisions = db.execute(
                    "SELECT COUNT(DISTINCT component_revision_id) FROM lua_archive_observations"
                ).fetchone()[0]
                self.assertEqual(revisions, 2)
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM lua_script_cache").fetchone()[0],
                    2,
                )
                parse_counts = dict(
                    db.execute(
                        "SELECT parse_status,COUNT(*) FROM lua_observations GROUP BY parse_status"
                    ).fetchall()
                )
                self.assertEqual(parse_counts, {"parsed": 2, "unsupported": 2})
                reasons = [
                    row[0]
                    for row in db.execute(
                        """SELECT sr.reason FROM stage_runs sr
                           JOIN analysis_runs ar ON ar.analysis_id=sr.analysis_id
                           WHERE ar.workflow_run_id='run-m4-fixture-a'
                             AND sr.stage_name='lua_archive_extraction'
                           ORDER BY sr.step_id"""
                    )
                ]
                self.assertIn("script_cache_hits=0;script_cache_misses=2", reasons)
                self.assertIn("script_cache_hits=2;script_cache_misses=0", reasons)

            manifest = read_json(
                fixture.inputs
                / "snapshots"
                / fixture.snapshot_id
                / "capture-manifest.json"
            )
            bridge_sha256 = next(
                item["sha256"]
                for item in manifest["payloads"]
                if "lua_bridge_reference" in item["roles"]
            )
            observation = {
                "schema_version": 1,
                "snapshot_id": fixture.snapshot_id,
                "build_id": manifest["build_id"],
                "probe_version": "1.0.0",
                "bridge": "xlua",
                "vm_identity": "fixture-main-state",
                "module_sha256": bridge_sha256,
                "scenario": {
                    "name": "menu",
                    "phase": "settled",
                    "description": "Fixture menu state",
                },
                "observations": [{"lua_path": "_G.fixture", "value_kind": "function"}],
                "coverage": {
                    "exhaustive": False,
                    "getters_invoked": 0,
                    "modules_loaded": 0,
                    "unknown_functions_invoked": 0,
                },
            }
            observation_path = Path(temporary) / "observation.json"
            observation_path.write_text(json.dumps(observation), encoding="utf-8")
            imported = import_runtime_observations(
                roots=fixture.roots,
                observation_path=observation_path,
                migrations_root=ROOT / "migrations",
            )
            self.assertEqual(imported["status"], "imported")
            with sqlite3.connect(registry_path) as db:
                signature = db.execute(
                    "SELECT signature FROM runtime_observations"
                ).fetchone()[0]
            self.assertEqual(signature, "fun(...): any")

            observation["build_id"] = "build-" + "b" * 64
            observation_path.write_text(json.dumps(observation), encoding="utf-8")
            with self.assertRaises(ValidationError) as raised:
                import_runtime_observations(
                    roots=fixture.roots,
                    observation_path=observation_path,
                    migrations_root=ROOT / "migrations",
                )
            self.assertEqual(raised.exception.error_code, "lua_runtime_build_mismatch")

    def test_probe_contract_prevents_implicit_discovery(self) -> None:
        probe = (ROOT / "runtime/lua-probe/probe.lua").read_text(encoding="utf-8")
        for forbidden in ("debug.getinfo", "getmetatable", "tostring", "require("):
            self.assertNotIn(forbidden, probe)
        for required in ("raw_next", "raw_rawget", "unknown_functions_invoked = 0"):
            self.assertIn(required, probe)
        config = read_json(ROOT / "runtime/lua-probe/probe-config.json")
        self.assertEqual(config["status"], "not_tested")


if __name__ == "__main__":
    unittest.main()
