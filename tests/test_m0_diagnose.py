from __future__ import annotations

import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

import yaml

import tools.m0_diagnose as m0_module
from tools.m0_diagnose import (
    IL2CPP_MAGIC,
    PEReader,
    capture_bundle,
    classify_subject,
    parse_md5_content_index,
    probe_il2cpp_metadata,
    sha256_file,
    verify_bundle,
    write_operational_report,
)


def make_writable_and_remove(path: Path) -> None:
    if not path.exists():
        return
    for item in path.rglob("*"):
        try:
            item.chmod(0o700 if item.is_dir() else 0o600)
        except OSError:
            pass
    path.chmod(0o700)
    shutil.rmtree(path)


def write_minimal_pe(path: Path, machine: int = 0x8664, subsystem: int = 2) -> None:
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 123456, 0, 0, 0xF0, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<H", data, optional + 68, subsystem)
    struct.pack_into("<I", data, optional + 108, 16)
    section = optional + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_standard_metadata(path: Path) -> None:
    header_size = 8 + 32 * 8
    data = bytearray(header_size + 1024)
    struct.pack_into("<II", data, 0, IL2CPP_MAGIC, 31)
    cursor = header_size
    for index in range(32):
        if index < 10:
            count = 64 if index == 2 else 8
            struct.pack_into("<II", data, 8 + index * 8, cursor, count)
            if index == 2:
                data[cursor : cursor + count] = b"Assembly-CSharp.dll\0" + b"A" * 44
            cursor += count
        else:
            struct.pack_into("<II", data, 8 + index * 8, 0, 0)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data[:cursor])


class M0MetadataTests(unittest.TestCase):
    def test_structural_metadata_probe_checks_more_than_magic(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "global-metadata.dat"
            write_standard_metadata(path)
            result = probe_il2cpp_metadata(path)
        self.assertEqual(result["metadata_version"], 31)
        self.assertEqual(result["status"], "structurally_conformant_header")
        self.assertFalse(result["suspected_protection"])
        self.assertIn(
            "all_nonempty_table_ranges_in_bounds", result["structural_checks"]
        )

    def test_high_entropy_nonconforming_header_is_separate_protection_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "global-metadata.dat"
            path.write_bytes(struct.pack("<I", IL2CPP_MAGIC) + bytes(range(256)) * 64)
            result = probe_il2cpp_metadata(path)
        self.assertEqual(result["status"], "suspected_protection")
        self.assertTrue(result["suspected_protection"])
        self.assertGreater(
            result["post_magic_entropy_sample"]["shannon_bits_per_byte"], 7.5
        )


class M0PeAndScopeTests(unittest.TestCase):
    def test_bounded_pe_reader_detects_machine_without_loading_image(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.exe"
            write_minimal_pe(path, machine=0x014C, subsystem=3)
            result = PEReader(path).summary()
        self.assertEqual(result["format"], "PE")
        self.assertEqual(result["machine"], "x86")
        self.assertEqual(result["subsystem"], "windows_console")
        self.assertFalse(result["has_clr_directory"])

    def test_scope_fails_closed_but_honors_exact_approved_module(self) -> None:
        policy = {
            "approved": {"full_module_decompile": ["NEP2.dll"]},
        }
        approved = classify_subject("NEP2.dll", "native_module", policy)
        mixed = classify_subject("GameAssembly.dll", "native_module", policy)
        unity = classify_subject("UnityPlayer.dll", "native_module", policy)
        unknown = classify_subject("PlausibleGame.dll", "native_module", policy)
        self.assertEqual(approved[0], "game_decompile")
        self.assertEqual(mixed[0], "needs_review")
        self.assertEqual(unity[0], "reference_only")
        self.assertEqual(unknown[0], "needs_review")

    def test_content_index_only_retains_bounded_executable_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "md5list.txt"
            path.write_text(
                "0123456789abcdef0123456789abcdef,42,Plugins/Extra.dll\n"
                "fedcba9876543210fedcba9876543210,99,Assets/texture.bin\n"
                "0123456789abcdef0123456789abcdef,7,../escaped.exe\n"
                "not-md5,5,Broken.sys\n",
                encoding="utf-8",
            )
            result = parse_md5_content_index(path)
        self.assertEqual(result["line_count"], 4)
        self.assertEqual(result["rejected_line_count"], 2)
        self.assertEqual(result["executable_reference_count"], 1)
        self.assertEqual(result["entries"][0]["logical_path"], "Plugins/Extra.dll")
        self.assertNotIn("content_sha256", result["entries"][0])


class M0CaptureTests(unittest.TestCase):
    def test_capture_is_bounded_content_addressed_and_redacts_host_paths(self) -> None:
        temp_root = Path(tempfile.mkdtemp())
        try:
            game = temp_root / "live-game"
            game.mkdir()
            write_minimal_pe(game / "Aniimo.exe")
            (game / "Aniimo_Data").mkdir()
            (game / "Aniimo_Data" / "globalgamemanagers").write_bytes(b"2022.3.62f1\0")
            (game / "UnityPlayer.dll").write_bytes(b"inventory-only")
            (game / "ignored.bin").write_bytes(b"must-not-be-captured")
            steam = temp_root / "appmanifest.acf"
            steam.write_text(
                '"AppState"\n{\n"appid" "4126040"\n"StateFlags" "4"\n'
                '"buildid" "fixture"\n"installdir" "Aniimo"\n}\n',
                encoding="utf-8",
            )
            profile = {
                "schema_version": 3,
                "selection_id": "fixture-selection",
                "feature_sets": {
                    "default_enabled": ["core", "lua", "content_indexes", "anti_cheat"],
                    "available": {
                        name: {}
                        for name in ("core", "lua", "content_indexes", "anti_cheat")
                    },
                },
                "payload_rules": [
                    {
                        "id": "exe",
                        "feature": "core",
                        "selector": {"type": "exact", "path": "Aniimo.exe"},
                        "required": True,
                        "roles": ["launcher"],
                    },
                    {
                        "id": "unity",
                        "feature": "core",
                        "selector": {
                            "type": "exact",
                            "path": "Aniimo_Data/globalgamemanagers",
                        },
                        "required": True,
                        "roles": ["unity_version_evidence"],
                    },
                ],
                "external_payload_rules": [
                    {
                        "id": "steam",
                        "feature": "core",
                        "source": "steam_manifest",
                        "logical_path": "distribution/steam/appmanifest.acf",
                        "required": True,
                        "identity_contribution": "evidence_only",
                        "roles": ["distribution_manifest"],
                    }
                ],
                "inventory_rules": [
                    {
                        "id": "unity-player",
                        "selector": {"type": "exact", "path": "UnityPlayer.dll"},
                        "roles": ["unity_reference"],
                        "record": ["logical_path", "size_bytes", "mtime_ns"],
                    }
                ],
                "candidate_inventory": {
                    "enabled": True,
                    "mode": "manifest_and_reference_guided_metadata_only",
                    "sources": ["bounded_inventory_rules"],
                    "inspected_zones": [{"path": ".", "max_depth": 1}],
                    "max_candidates": 8,
                    "retain_file_bodies": False,
                    "hash_file_bodies": False,
                    "decompress_assets": False,
                },
                "coherence_groups": [],
                "always_excluded_paths": ["**/Logs/**"],
            }
            profile_path = temp_root / "inputs.yaml"
            profile_path.write_text(yaml.safe_dump(profile), encoding="utf-8")
            output = temp_root / "bundles"
            bundle = capture_bundle(profile_path, game, steam, output)
            manifest_text = (bundle / "snapshot" / "capture-manifest.json").read_text(
                encoding="utf-8"
            )
            manifest = json.loads(manifest_text)
            self.assertTrue(bundle.name.startswith("m0-"))
            self.assertEqual(
                manifest["features"],
                ["core", "lua", "content_indexes", "anti_cheat"],
            )
            self.assertNotIn(str(game), manifest_text)
            self.assertFalse((bundle / "snapshot" / "files" / "ignored.bin").exists())
            inventory = next(
                item
                for item in manifest["inventory"]
                if item["logical_path"] == "UnityPlayer.dll"
            )
            self.assertIsNone(inventory["content_sha256"])
            self.assertFalse(inventory["body_retained"])
            self.assertFalse(
                (bundle / "snapshot" / "files" / "UnityPlayer.dll").exists()
            )
            self.assertEqual(
                {item["read_attempts"] for item in manifest["payloads"]}, {1}
            )
            self.assertEqual(capture_bundle(profile_path, game, steam, output), bundle)

            policy_path = temp_root / "policy.yaml"
            policy_path.write_text(
                yaml.safe_dump({"input_selection_id": "fixture-selection"}),
                encoding="utf-8",
            )
            diagnostic = bundle / "diagnostic"
            diagnostic.mkdir()
            evidence_basis = {
                "capture_manifest_sha256": sha256_file(
                    bundle / "snapshot" / "capture-manifest.json"
                ),
                "decompilation_policy_sha256": sha256_file(policy_path),
                "producer_source_sha256": sha256_file(Path(m0_module.__file__)),
            }
            artifacts = {
                "detection.json": {
                    "capture_id": bundle.name,
                    "evidence_basis": evidence_basis,
                },
                "scope-plan.json": {
                    "capture_id": bundle.name,
                    "decisions": [],
                    "evidence_basis": evidence_basis,
                },
                "tool-compatibility.json": {
                    "capture_id": bundle.name,
                    "evidence_basis": evidence_basis,
                },
                "additional-input-candidates.json": {
                    "capture_id": bundle.name,
                    "candidates": [],
                    "evidence_basis": evidence_basis,
                },
            }
            for name, value in artifacts.items():
                (diagnostic / name).write_text(
                    json.dumps(value, sort_keys=True) + "\n", encoding="utf-8"
                )
            (diagnostic / "report.md").write_text("fixture report\n", encoding="utf-8")
            artifact_hashes = {
                path.name: sha256_file(path)
                for path in diagnostic.iterdir()
                if path.is_file()
            }
            (diagnostic / "diagnostic-manifest.json").write_text(
                json.dumps(
                    {
                        "capture_id": bundle.name,
                        "artifacts": artifact_hashes,
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            write_operational_report(
                bundle,
                {
                    "capture_id": bundle.name,
                    "status": "completed",
                    "resources": {
                        "logical_cpu_count": 1,
                        "disk_free_bytes": 1,
                        "diagnose_process_cpu_ms": 1.0,
                    },
                    "stages": [
                        {
                            "id": "verification",
                            "status": "skipped",
                            "cache_status": "not_applicable_m0",
                            "duration_ms": 0.0,
                            "tool": {"name": "m0_diagnose", "version": "fixture"},
                        }
                    ],
                },
            )
            self.assertEqual(verify_bundle(bundle, policy_path)["status"], "passed")
            run_report = json.loads(
                (bundle / "run-report" / "run-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(run_report["stages"][0]["status"], "executed")
            (diagnostic / "report.md").write_text("tampered\n", encoding="utf-8")
            tampered = verify_bundle(bundle, policy_path)
            self.assertEqual(tampered["status"], "failed")
            self.assertIn(
                "diagnostic_artifact_hash_mismatch:report.md", tampered["errors"]
            )
            failed_run_report = json.loads(
                (bundle / "run-report" / "run-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(failed_run_report["status"], "failed")
        finally:
            make_writable_and_remove(temp_root)


if __name__ == "__main__":
    unittest.main()
