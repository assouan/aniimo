from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from modkit.capture import publish_snapshot
from modkit.config import load_yaml
from modkit.ghidra_adapter import GhidraExport, load_export
from modkit.native import (
    NativeRoots,
    _slug,
    analyze_native_snapshot,
    body_attempt_context,
    body_attempt_key,
)
from modkit.planner import build_capture_plan
from modkit.util import read_json, sha256_file

ROOT = Path(__file__).resolve().parents[1]


def write_minimal_pe(path: Path, marker: int = 0) -> None:
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    section = optional + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200:0x206] = b"\x90\x90\x31\xc0\xc3\xcc"
    data[-1] = marker
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


class FakeGhidraAdapter:
    def __init__(self, work: Path, statuses: tuple[str, ...] = ("c_and_asm",)) -> None:
        self.work = work
        self.statuses = statuses
        self.calls: list[str] = []
        self.script = ROOT / "ghidra/ExportApprovedFunctions.java"

    def context(self) -> dict[str, object]:
        return {
            "exporter": "fixture",
            "maximum_primary_timeouts": 16,
            "primary_timeout_seconds": 15,
            "tool": "Ghidra fixture",
        }

    def export_module(
        self, *, module_path: Path, module_logical_path: str, module_sha256: str
    ) -> GhidraExport:
        self.calls.append(module_logical_path)
        root = self.work / module_logical_path
        (root / "asm").mkdir(parents=True, exist_ok=True)
        (root / "c").mkdir(parents=True, exist_ok=True)
        bodies: list[dict[str, object]] = []
        references: list[dict[str, object]] = []
        for ordinal, status in enumerate(self.statuses):
            rva = 0x1000 + ordinal * 0x10
            stem = f"function-{ordinal:08d}"
            asm_path = f"asm/{stem}.asm" if status != "disassembly_failed" else None
            c_path = f"c/{stem}.c" if status == "c_and_asm" else None
            if asm_path:
                (root / asm_path).write_text(f"{rva:016x}  90  NOP\n", encoding="utf-8")
            if c_path:
                (root / c_path).write_text(
                    f"void FUN_{rva:x}(void) {{ return; }}\n", encoding="utf-8"
                )
            body: dict[str, object] = {
                "ordinal": ordinal,
                "entry_address": f"14000{rva:04x}",
                "rva": f"0x{rva:x}",
                "name": f"FUN_{0x140000000 + rva:x}",
                "namespace": "Global",
                "symbol_source": "default",
                "calling_convention": "__fastcall",
                "native_prototype": f"void __fastcall FUN_{rva:x}(void)",
                "raw_body_hash": hashlib.sha256(
                    f"{module_sha256}:{rva}".encode()
                ).hexdigest(),
                "instruction_count": 1 if asm_path else 0,
                "body_byte_count": 1 if asm_path else 0,
                "reference_count": 1 if ordinal == 0 else 0,
                "unresolved_call_count": 1 if ordinal == 0 else 0,
                "body_output_status": status,
                "asm_path": asm_path,
                "c_path": c_path,
                "diagnostic": None if status == "c_and_asm" else f"fixture_{status}",
            }
            if ordinal == 0 and module_logical_path == "NEP2.dll":
                body["managed_symbols"] = [
                    {
                        "assembly": "Game.Tests",
                        "type": "Game.Tests.SharedType",
                        "method": "First",
                        "managed_signature": "instance System.Void Game.Tests.SharedType::First()",
                        "signature_key": "v1|Game.Tests|Game.Tests.SharedType|First|0|instance||System.Void",
                        "static_kind": "instance",
                    },
                    {
                        "assembly": "Game.Tests",
                        "type": "Game.Tests.SharedType",
                        "method": "Second",
                        "managed_signature": "instance System.Void Game.Tests.SharedType::Second()",
                        "signature_key": "v1|Game.Tests|Game.Tests.SharedType|Second|0|instance||System.Void",
                        "static_kind": "instance",
                    },
                ]
            bodies.append(body)
            if ordinal == 0:
                oversized_target = module_logical_path == "NEP2.dll"
                references.append(
                    {
                        "source_ordinal": 0,
                        "source_instruction_rva": f"0x{rva:x}",
                        "kind": "unresolved_call",
                        "target_address": (
                            "ffffffffffffffff" if oversized_target else None
                        ),
                        "target_rva": (
                            "0xffffffffffffffff" if oversized_target else None
                        ),
                        "raw_operand": "CALL RAX",
                    }
                )
        counts = {
            status: self.statuses.count(status)
            for status in (
                "c_and_asm",
                "asm_only",
                "disassembly_failed",
                "pending",
            )
        }
        summary = {
            "schema_version": 1,
            "program_name": module_logical_path,
            "executable_sha256": module_sha256,
            "language_id": "x86:LE:64:default",
            "compiler_spec_id": "windows",
            "image_base": "140000000",
            "function_count": len(bodies),
            **counts,
            "primary_timeout_count": counts["asm_only"],
        }
        return GhidraExport(
            output_root=root,
            summary=summary,
            bodies=tuple(bodies),
            references=tuple(references),
            unattributed_ranges=(
                {"start_rva": "0x1100", "end_rva": "0x110f", "size_bytes": 16},
            ),
            project_uri=f"ghidra:/fixture/{module_logical_path}",
            command_log=root / "ghidra.log",
        )


class NativeFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.game = root / "game"
        self.inputs = root / "inputs"
        self.state = root / "state"
        self.artifacts = root / "artifacts"
        self.ghidra = root / "ghidra"
        self.work = root / "work"
        self.output = root / "output"
        self.steam = root / "appmanifest.acf"
        write_minimal_pe(self.game / "Aniimo.exe", 1)
        write_minimal_pe(self.game / "GameAssembly.dll", 2)
        for marker, name in enumerate(
            ("NEP2.dll", "NEPKernel.sys", "NEPCleaner.exe", "KernelDumpAnalyzer.exe"),
            10,
        ):
            write_minimal_pe(self.game / name, marker)
        (self.game / "Aniimo_Data").mkdir(exist_ok=True)
        (self.game / "Aniimo_Data/globalgamemanagers").write_bytes(
            b"2022.3.62f1\0fixture"
        )
        metadata = bytes(range(256)) * 16
        metadata = struct.pack("<II", 0xFAB11BAF, len(metadata)) + metadata[8:]
        metadata_path = (
            self.game / "Aniimo_Data/il2cpp_data/Metadata/global-metadata.dat"
        )
        metadata_path.parent.mkdir(parents=True)
        metadata_path.write_bytes(metadata)
        self.steam.write_text(
            '"AppState"\n{\n"appid" "4126040"\n"StateFlags" "4"\n"buildid" "m2-fixture"\n}\n',
            encoding="utf-8",
        )
        self.profile = load_yaml(ROOT / "profiles/aniimo.yaml")
        self.selection = load_yaml(ROOT / "profiles/aniimo.inputs.yaml")
        self.policy = load_yaml(ROOT / "profiles/aniimo.decompilation.yaml")
        plan = build_capture_plan(self.selection, self.game, self.steam)
        captured = publish_snapshot(
            plan, self.inputs, workflow_run_id="capture-m2-fixture"
        )
        self.snapshot_id = str(captured["snapshot_id"])

    @property
    def roots(self) -> NativeRoots:
        return NativeRoots(
            inputs=self.inputs,
            state=self.state,
            artifacts=self.artifacts,
            ghidra=self.ghidra,
            work=self.work,
            output=self.output,
        )

    def analyze(self, adapter: FakeGhidraAdapter, run_id: str) -> dict[str, object]:
        return analyze_native_snapshot(
            roots=self.roots,
            snapshot_id=self.snapshot_id,
            profile=self.profile,
            input_profile=self.selection,
            policy=self.policy,
            tools_lock=read_json(ROOT / "tools.lock.json"),
            migrations_root=ROOT / "migrations",
            adapter=adapter,  # type: ignore[arg-type]
            enforce_read_only_inputs=False,
            workflow_run_id=run_id,
        )


class M2NativeTests(unittest.TestCase):
    def test_portable_slug_bounds_long_native_names_without_collision(self) -> None:
        first = "Concurrency::" + "very_long_template_name<" * 40 + "A"
        second = "Concurrency::" + "very_long_template_name<" * 40 + "B"
        first_slug = _slug(first)
        self.assertLessEqual(len(first_slug.encode("utf-8")), 80)
        self.assertEqual(first_slug, _slug(first))
        self.assertNotEqual(first_slug, _slug(second))

    def test_attempt_cache_key_includes_semantic_dependencies(self) -> None:
        body = {
            "body_byte_count": 3,
            "raw_body_hash": "a" * 64,
            "rva": "0x1000",
            "native_prototype": "void f(int)",
        }
        base = body_attempt_context(
            body=body,
            module_sha256="b" * 64,
            load_context_hash="c" * 64,
            tool_context={"tool": "fixture"},
            reference_context_hash="d" * 64,
            managed_signature="static System.Void T::F(System.Int32)",
            layout_hash="e" * 64,
            budget_class="primary",
        )
        self.assertEqual(body_attempt_key(base), body_attempt_key(dict(base)))
        for field, value in (
            ("layout_hash", "f" * 64),
            ("reference_context_hash", "0" * 64),
            ("managed_signature", "instance System.Void T::F(System.Int32)"),
            ("budget_class", "difficult"),
        ):
            changed = dict(base)
            changed[field] = value
            self.assertNotEqual(body_attempt_key(base), body_attempt_key(changed))
        changed_body = json.loads(json.dumps(base))
        changed_body["body"]["raw_body_hash"] = "1" * 64
        self.assertNotEqual(body_attempt_key(base), body_attempt_key(changed_body))

    def test_load_export_enforces_all_four_exclusive_states(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adapter = FakeGhidraAdapter(
                root / "exports",
                ("c_and_asm", "asm_only", "disassembly_failed", "pending"),
            )
            module = root / "module.exe"
            module.write_bytes(b"fixture")
            digest = sha256_file(module)[0]
            export = adapter.export_module(
                module_path=module,
                module_logical_path="module.exe",
                module_sha256=digest,
            )
            (export.output_root / "summary.json").write_text(
                json.dumps(export.summary), encoding="utf-8"
            )
            for name, values in (
                ("bodies.ndjson", export.bodies),
                ("references.ndjson", export.references),
                ("unattributed-ranges.ndjson", export.unattributed_ranges),
            ):
                (export.output_root / name).write_text(
                    "".join(json.dumps(item) + "\n" for item in values),
                    encoding="utf-8",
                )
            loaded = load_export(export.output_root, digest)
            self.assertEqual(len(loaded.bodies), 4)
            (export.output_root / str(export.bodies[0]["c_path"])).write_text(
                "decompiler error", encoding="utf-8"
            )
            with self.assertRaisesRegex(Exception, "vide ou tronqué"):
                load_export(export.output_root, digest)

    def test_real_registry_publication_and_second_run_module_cache(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            fixture = NativeFixture(Path(temporary))
            first_adapter = FakeGhidraAdapter(fixture.work / "fake-first")
            first = fixture.analyze(first_adapter, "run-m2-first")
            self.assertEqual(len(first_adapter.calls), 4)
            self.assertEqual(first["metadata_status"], "suspected_protection")
            coverage = first["coverage"]
            self.assertEqual(coverage["approved_body_count"], 4)
            self.assertEqual(coverage["body_status_counts"]["c_and_asm"], 4)
            self.assertTrue(coverage["exact_body_reconciliation"])
            self.assertFalse(coverage["discovery_complete"])
            output = fixture.output / str(first["output"])
            before = {
                path.relative_to(output).as_posix(): (
                    path.stat().st_mtime_ns,
                    sha256_file(path)[0],
                )
                for path in output.rglob("*")
                if path.is_file()
            }
            with sqlite3.connect(fixture.state / "registry.sqlite") as db:
                db.executescript(
                    """
                    CREATE TRIGGER reject_cached_body_reingestion
                    BEFORE INSERT ON body_observations
                    BEGIN
                        SELECT RAISE(FAIL, 'cached body was reingested');
                    END;
                    CREATE TRIGGER reject_cached_reference_reingestion
                    BEFORE INSERT ON native_references
                    BEGIN
                        SELECT RAISE(FAIL, 'cached reference was reingested');
                    END;
                    """
                )
            body_manifests = sorted(
                path
                for path in (output / "native/bodies").glob("body-*.json")
                if path.name.count(".") == 1
            )
            self.assertEqual(len(body_manifests), 4)
            shared = [
                read_json(path)
                for path in body_manifests
                if len(read_json(path)["symbols"]) == 3
            ]
            self.assertEqual(len(shared), 1)
            self.assertEqual(
                len(list((output / "native/index/by-managed-type").rglob("*.md"))),
                2,
            )
            second_adapter = FakeGhidraAdapter(fixture.work / "fake-second")
            second = fixture.analyze(second_adapter, "run-m2-second")
            self.assertEqual(second_adapter.calls, [])
            self.assertEqual(set(second["module_cache"].values()), {"hit"})
            self.assertEqual(second["analysis_key"], first["analysis_key"])
            after = {
                path.relative_to(output).as_posix(): (
                    path.stat().st_mtime_ns,
                    sha256_file(path)[0],
                )
                for path in output.rglob("*")
                if path.is_file()
            }
            self.assertEqual(before, after)
            with sqlite3.connect(fixture.state / "registry.sqlite") as db:
                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 9)
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                body_count = db.execute(
                    "SELECT COUNT(*) FROM native_bodies"
                ).fetchone()[0]
                link_count = db.execute(
                    "SELECT COUNT(*) FROM symbol_body_links"
                ).fetchone()[0]
                self.assertEqual(body_count, 4)
                self.assertEqual(link_count, 6)
                oversized = db.execute(
                    """SELECT target_raw,target_rva,resolution_status,evidence_json
                       FROM native_references
                       WHERE target_raw='ffffffffffffffff'"""
                ).fetchone()
                self.assertIsNotNone(oversized)
                self.assertIsNone(oversized[1])
                self.assertEqual(oversized[2], "unresolved")
                self.assertIn("0xffffffffffffffff", oversized[3])

    def test_cached_module_is_materialized_for_a_distinct_build(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            fixture = NativeFixture(Path(temporary))
            first_adapter = FakeGhidraAdapter(fixture.work / "fake-build-one")
            first = fixture.analyze(first_adapter, "run-m2-build-one")
            self.assertEqual(len(first_adapter.calls), 4)

            managers = fixture.game / "Aniimo_Data/globalgamemanagers"
            managers.write_bytes(managers.read_bytes() + b"-new-build")
            fixture.steam.write_text(
                '"AppState"\n{\n"appid" "4126040"\n"StateFlags" "4"\n'
                '"buildid" "m2-fixture-two"\n}\n',
                encoding="utf-8",
            )
            second_plan = build_capture_plan(
                fixture.selection, fixture.game, fixture.steam
            )
            second_capture = publish_snapshot(
                second_plan,
                fixture.inputs,
                workflow_run_id="capture-m2-fixture-two",
            )
            fixture.snapshot_id = str(second_capture["snapshot_id"])

            second_adapter = FakeGhidraAdapter(fixture.work / "fake-build-two")
            second = fixture.analyze(second_adapter, "run-m2-build-two")
            self.assertEqual(second_adapter.calls, [])
            self.assertEqual(set(second["module_cache"].values()), {"hit"})
            self.assertNotEqual(second["build_id"], first["build_id"])
            with sqlite3.connect(fixture.state / "registry.sqlite") as db:
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM native_bodies").fetchone()[0], 4
                )
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM body_observations").fetchone()[0],
                    8,
                )
                self.assertEqual(
                    db.execute(
                        "SELECT COUNT(DISTINCT build_id) FROM body_observations"
                    ).fetchone()[0],
                    2,
                )


if __name__ == "__main__":
    unittest.main()
