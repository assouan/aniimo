from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from modkit.capture import publish_snapshot
from modkit.planner import build_capture_plan
from modkit.sdk import (
    SdkRoots,
    finalize_sdk_release,
    generate_sdk_release,
    package_sdk_release,
)
from modkit.util import read_json
from tests.test_m4_lua import LuaFixture

ROOT = Path(__file__).resolve().parents[1]


class M5SdkTests(unittest.TestCase):
    def test_same_package_and_mod_are_evaluated_for_two_exact_builds(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            root = Path(temporary)
            fixture = LuaFixture(root)
            first = fixture.analyze("run-m5-fixture-lua-a")
            first_build = str(first["build_id"])

            managers = fixture.game / "Aniimo_Data/globalgamemanagers"
            managers.write_bytes(managers.read_bytes() + b"-second-build")
            fixture.steam.write_text(
                '"AppState"\n{\n"appid" "4126040"\n"StateFlags" "4"\n'
                '"buildid" "m5-fixture-two"\n}\n',
                encoding="utf-8",
            )
            captured = publish_snapshot(
                build_capture_plan(fixture.selection, fixture.game, fixture.steam),
                fixture.inputs,
                workflow_run_id="capture-m5-fixture-two",
            )
            fixture.snapshot_id = str(captured["snapshot_id"])
            second = fixture.analyze("run-m5-fixture-lua-b")
            second_build = str(second["build_id"])
            self.assertNotEqual(first_build, second_build)

            roots = SdkRoots(state=fixture.state, output=fixture.output)
            generated = generate_sdk_release(
                roots=roots,
                build_ids=[first_build, second_build],
                sdk_version="1.0.0",
                adapter_version="1.0.0",
                migrations_root=ROOT / "migrations",
                workflow_run_id="run-m5-fixture-generate-a",
            )
            self.assertEqual(generated["cache_status"], "miss")
            generated_root = fixture.output / str(generated["output_root"])
            manifests = [
                read_json(path)
                for path in sorted((generated_root / "adapters").glob("*.json"))
            ]
            self.assertEqual(len(manifests), 2)
            self.assertEqual(
                len({item["capability_basis_id"] for item in manifests}), 1
            )
            self.assertEqual(len({item["catalog_sha256"] for item in manifests}), 1)
            self.assertTrue(
                all(
                    item["capability_status"] == "requires_validation"
                    for item in manifests
                )
            )
            output_manifest = generated_root / "output-manifest.json"
            before = (output_manifest.stat().st_mtime_ns, output_manifest.read_bytes())
            cached = generate_sdk_release(
                roots=roots,
                build_ids=[second_build, first_build],
                sdk_version="1.0.0",
                adapter_version="1.0.0",
                migrations_root=ROOT / "migrations",
                workflow_run_id="run-m5-fixture-generate-b",
            )
            self.assertEqual(cached["cache_status"], "hit")
            self.assertEqual(
                before,
                (output_manifest.stat().st_mtime_ns, output_manifest.read_bytes()),
            )

            compiled = root / "compiled"
            compiled.mkdir()
            for name in (
                "GameModAPI.Contracts.dll",
                "GameModAPI.Runtime.dll",
                "GameModAPI.Adapter.Aniimo.dll",
                "LuaCatalogExample.dll",
            ):
                (compiled / name).write_bytes(f"fixture:{name}".encode("ascii"))
            documentation = root / "README.md"
            documentation.write_text("fixture SDK\n", encoding="utf-8")
            package_a = root / "sdk-a.zip"
            package_b = root / "sdk-b.zip"
            packaged_a = package_sdk_release(
                compiled_root=compiled,
                generated_root=generated_root,
                documentation_path=documentation,
                destination=package_a,
            )
            packaged_b = package_sdk_release(
                compiled_root=compiled,
                generated_root=generated_root,
                documentation_path=documentation,
                destination=package_b,
            )
            self.assertEqual(packaged_a["package_sha256"], packaged_b["package_sha256"])
            with zipfile.ZipFile(package_a) as archive:
                names = set(archive.namelist())
            self.assertNotIn("GameAssembly.dll", names)
            self.assertTrue(all("LuaScripts" not in name for name in names))

            plugin_sha256 = hashlib.sha256(
                (compiled / "LuaCatalogExample.dll").read_bytes()
            ).hexdigest()
            test_report = {
                "build_ids": sorted([first_build, second_build]),
                "plugin_sha256": plugin_sha256,
                "results": [
                    {
                        "build_id": build_id,
                        "capability_basis_id": manifests[0]["capability_basis_id"],
                        "status": "passed",
                    }
                    for build_id in (first_build, second_build)
                ],
                "runtime_game_status": "not_tested",
                "same_plugin_binary": True,
                "schema_version": 1,
                "status": "passed",
            }
            test_report_path = root / "sdk-test-report.json"
            test_report_path.write_text(
                json.dumps(test_report, sort_keys=True), encoding="utf-8"
            )
            finalized = finalize_sdk_release(
                roots=roots,
                generated_root=generated_root,
                package_path=package_a,
                contract_path=compiled / "GameModAPI.Contracts.dll",
                test_report_path=test_report_path,
                migrations_root=ROOT / "migrations",
                workflow_run_id="run-m5-fixture-finalize",
            )
            self.assertEqual(finalized["offline_validation_status"], "passed")
            self.assertEqual(finalized["runtime_validation_status"], "not_tested")
            self.assertEqual(finalized["authorization"]["status"], "not_requested")
            with sqlite3.connect(fixture.state / "registry.sqlite") as db:
                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 9)
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                statuses = db.execute(
                    """SELECT validation_kind,validation_status,COUNT(*)
                       FROM capability_validations
                       GROUP BY validation_kind,validation_status"""
                ).fetchall()
                self.assertEqual(
                    statuses,
                    [
                        ("offline_adapter", "passed", 2),
                        ("runtime_game", "not_tested", 2),
                        ("static_contract", "passed", 2),
                    ],
                )


if __name__ == "__main__":
    unittest.main()
