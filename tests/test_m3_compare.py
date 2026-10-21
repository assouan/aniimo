from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from modkit.capture import publish_snapshot
from modkit.compare import (
    CompareRoots,
    classify_change,
    compare_builds,
    match_symbols,
)
from modkit.config import load_yaml
from modkit.planner import build_capture_plan
from modkit.util import read_json, sha256_file
from tests.test_m2_native import FakeGhidraAdapter, NativeFixture
from tools.audit_m2 import audit as audit_m2
from tools.audit_m3 import audit

ROOT = Path(__file__).resolve().parents[1]


def symbol(
    symbol_id: str,
    *,
    body_id: str,
    raw_hash: str = "a" * 64,
    signature_hash: str = "b" * 64,
    layout_hash: str | None = "c" * 64,
    call_hash: str = "d" * 64,
    data_hash: str = "e" * 64,
    rva: int = 0x1000,
    name: str = "GameMethod",
    signature_key: str | None = None,
) -> dict[str, object]:
    return {
        "fingerprint": {
            "call_targets_hash": call_hash,
            "layout_hash": layout_hash,
            "raw_body_hash": raw_hash,
            "referenced_data_hash": data_hash,
            "semantic_operands_hash": raw_hash,
            "signature_hash": signature_hash,
            "strict_semantic_hash": raw_hash,
        },
        "module_logical_path": "Game.dll",
        "name": name,
        "namespace": "Game",
        "native_body_id": body_id,
        "rva": rva,
        "signature_key": signature_key,
        "symbol_id": symbol_id,
        "symbol_kind": "managed_method" if signature_key else "native_function",
    }


class M3PureTests(unittest.TestCase):
    def test_risk_targeted_change_classification(self) -> None:
        base = symbol("symbol-1", body_id="body-1")

        relocated = symbol("symbol-1", body_id="body-1", rva=0x2000)
        flags, status, _ = classify_change(base, relocated, "confirmed")
        self.assertEqual(flags, ["relocated"])
        self.assertEqual(status, "invalidated")
        self.assertNotIn("renamed", flags)

        constant_changed = symbol("symbol-1", body_id="body-2", raw_hash="f" * 64)
        flags, status, reasons = classify_change(base, constant_changed, "confirmed")
        self.assertIn("body_changed", flags)
        self.assertIn("strict_body_or_semantic_operand_changed", reasons)
        self.assertEqual(status, "invalidated")

        layout_changed = symbol("symbol-1", body_id="body-2", layout_hash="1" * 64)
        flags, _, _ = classify_change(base, layout_changed, "confirmed")
        self.assertIn("layout_changed", flags)

        signature_changed = symbol(
            "symbol-1", body_id="body-2", signature_hash="4" * 64
        )
        flags, _, _ = classify_change(base, signature_changed, "confirmed")
        self.assertIn("signature_changed", flags)

        data_changed = symbol("symbol-1", body_id="body-2", data_hash="2" * 64)
        flags, _, _ = classify_change(base, data_changed, "confirmed")
        self.assertIn("referenced_data_changed", flags)

        target_changed = symbol("symbol-1", body_id="body-2", call_hash="3" * 64)
        flags, _, _ = classify_change(base, target_changed, "confirmed")
        self.assertIn("references_changed", flags)

    def test_persistent_and_managed_identity_survive_total_body_change(self) -> None:
        source = {
            "persistent": symbol("persistent", body_id="old", raw_hash="1" * 64),
            "old-managed": symbol(
                "old-managed",
                body_id="old-managed-body",
                raw_hash="2" * 64,
                signature_key="v1|Game|Game.Type|Run|0|instance||System.Void",
            ),
        }
        destination = {
            "persistent": symbol("persistent", body_id="new", raw_hash="9" * 64),
            "new-managed": symbol(
                "new-managed",
                body_id="new-managed-body",
                raw_hash="8" * 64,
                signature_key="v1|Game|Game.Type|Run|0|instance||System.Void",
            ),
        }
        matches = match_symbols(
            source,
            destination,
            {"reviews": [], "bsim_candidates": [], "layouts": []},
        )
        by_source = {
            item["source_symbol_id"]: item
            for item in matches
            if item["source_symbol_id"]
        }
        self.assertEqual(by_source["persistent"]["match_status"], "confirmed")
        self.assertEqual(
            by_source["persistent"]["match_method"], "persistent_symbol_identity"
        )
        self.assertEqual(by_source["old-managed"]["match_status"], "confirmed")
        self.assertEqual(
            by_source["old-managed"]["match_method"], "managed_signature_identity"
        )

    def test_bsim_and_raw_hash_remain_review_candidates(self) -> None:
        source = {"source": symbol("source", body_id="body-source")}
        destination = {"destination": symbol("destination", body_id="body-destination")}
        matches = match_symbols(
            source,
            destination,
            {
                "reviews": [],
                "layouts": [],
                "bsim_candidates": [
                    {
                        "source_symbol_id": "source",
                        "destination_symbol_id": "destination",
                        "score": 0.99,
                    }
                ],
            },
        )
        match = next(item for item in matches if item["source_symbol_id"] == "source")
        self.assertEqual(match["match_status"], "candidate")
        self.assertTrue(match["review_required"])
        self.assertNotEqual(match["match_status"], "confirmed")


class M3IntegrationTests(unittest.TestCase):
    def test_two_build_comparison_and_identical_second_run_do_not_rewrite(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
            fixture = NativeFixture(Path(temporary))
            source_snapshot = fixture.snapshot_id
            source_analysis = fixture.analyze(
                FakeGhidraAdapter(fixture.work / "m3-source"), "run-m3-source-native"
            )

            managers = fixture.game / "Aniimo_Data/globalgamemanagers"
            managers.write_bytes(managers.read_bytes() + b"-second-build")
            fixture.steam.write_text(
                '"AppState"\n{\n"appid" "4126040"\n"StateFlags" "4"\n'
                '"buildid" "m3-fixture-two"\n}\n',
                encoding="utf-8",
            )
            plan = build_capture_plan(fixture.selection, fixture.game, fixture.steam)
            captured = publish_snapshot(
                plan, fixture.inputs, workflow_run_id="capture-m3-destination"
            )
            destination_snapshot = str(captured["snapshot_id"])
            fixture.snapshot_id = destination_snapshot
            destination_adapter = FakeGhidraAdapter(fixture.work / "m3-destination")
            fixture.analyze(destination_adapter, "run-m3-destination-native")
            self.assertEqual(destination_adapter.calls, [])
            audited_m2 = audit_m2(
                fixture.state / "registry.sqlite",
                fixture.output / str(source_analysis["output"]),
                "run-m3-destination-native",
            )
            self.assertEqual(audited_m2["approved_body_count"], 4)

            roots = CompareRoots(
                inputs=fixture.inputs,
                state=fixture.state,
                artifacts=fixture.artifacts,
                output=fixture.output,
            )
            arguments = {
                "roots": roots,
                "source_snapshot_id": source_snapshot,
                "destination_snapshot_id": destination_snapshot,
                "input_profile": fixture.selection,
                "policy": fixture.policy,
                "annotations": load_yaml(ROOT / "profiles/aniimo.matching.yaml"),
                "migrations_root": ROOT / "migrations",
                "enforce_read_only_inputs": False,
            }
            first = compare_builds(**arguments, workflow_run_id="run-m3-first")
            self.assertEqual(first["cache_status"], "miss")
            self.assertEqual(first["summary"]["match_status_counts"], {"confirmed": 6})
            self.assertEqual(
                first["summary"]["invalidation_status_counts"], {"unchanged": 6}
            )
            output = fixture.output / str(first["output"])
            before = {
                path.relative_to(output).as_posix(): (
                    path.stat().st_mtime_ns,
                    sha256_file(path)[0],
                )
                for path in output.rglob("*")
                if path.is_file()
            }

            second = compare_builds(**arguments, workflow_run_id="run-m3-second")
            self.assertEqual(second["cache_status"], "hit")
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
                self.assertEqual(
                    db.execute("SELECT COUNT(*) FROM build_comparisons").fetchone()[0],
                    1,
                )
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                symbol_plan = " ".join(
                    str(row[3])
                    for row in db.execute(
                        """EXPLAIN QUERY PLAN
                           SELECT sbl.native_body_id,so.symbol_id
                           FROM symbol_body_links sbl
                           JOIN symbol_observations so
                             ON so.symbol_id=sbl.symbol_id
                            AND so.build_id=sbl.build_id
                            AND so.component_revision_id=sbl.component_revision_id
                           WHERE sbl.build_id=?
                           ORDER BY sbl.native_body_id,so.symbol_id""",
                        (first["source_build_id"],),
                    )
                )
                self.assertIn(
                    "symbol_observations_build_component_symbol_idx", symbol_plan
                )
            audited = audit(fixture.state / "registry.sqlite", output, "run-m3-second")
            self.assertEqual(audited["match_count"], 6)
            self.assertEqual(
                read_json(output / "comparison.json")["comparison_key"],
                first["comparison_key"],
            )


if __name__ == "__main__":
    unittest.main()
