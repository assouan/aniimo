from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_text(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


class RepositoryContractTests(unittest.TestCase):
    def test_private_paths_are_excluded_from_docker_context(self) -> None:
        patterns = {
            line.strip().rstrip("/")
            for line in read_text(".dockerignore").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        for required in {
            ".git",
            ".sample",
            ".ainotes",
            ".aitools",
            "/state",
            "/inputs",
            "/artifacts",
            "/ghidra-state",
            "/cache",
            "/work",
            "/output",
            "/dist",
        }:
            self.assertIn(required, patterns)

    def test_generated_state_is_git_ignored(self) -> None:
        ignore = read_text(".gitignore")
        for required in (
            ".env",
            "/state/",
            "/inputs/",
            "/artifacts/",
            "/output/",
            "/dist/",
        ):
            self.assertIn(required, ignore)
        for path in (
            ".env",
            "state/probe",
            "inputs/probe",
            "artifacts/probe",
            "output/probe",
            "dist/probe",
        ):
            result = subprocess.run(
                ["git", "check-ignore", "--quiet", "--no-index", path],
                cwd=ROOT,
                check=False,
            )
            self.assertEqual(result.returncode, 0, path)
        example = subprocess.run(
            ["git", "check-ignore", "--quiet", "--no-index", ".env.example"],
            cwd=ROOT,
            check=False,
        )
        self.assertEqual(example.returncode, 1)

    def test_compose_separates_capture_from_analysis_and_prefixes_volumes(self) -> None:
        compose = read_text("examples/compose.example.yaml")
        self.assertEqual(compose.count("${ANIIMO_VOLUME_PREFIX:-aniimo-}"), 6)
        for suffix in ("inputs", "state", "artifacts", "ghidra", "cache", "work"):
            self.assertIn(f"aniimo-}}{suffix}\"", compose)
        capture, analyzer = compose.split("\n  analyzer:", maxsplit=1)
        self.assertIn("${GAME_DIR:", capture)
        self.assertIn("${STEAM_APP_MANIFEST:", capture)
        self.assertNotIn("${GAME_DIR:", analyzer)
        self.assertNotIn("${STEAM_APP_MANIFEST:", analyzer)
        self.assertIn("source: modkit-inputs", capture)
        self.assertIn("source: modkit-inputs", analyzer)
        for forbidden in (
            "source: modkit-state",
            "source: modkit-artifacts",
            "source: modkit-ghidra",
            "source: modkit-cache",
            "source: modkit-work",
            "source: ./output",
        ):
            self.assertNotIn(forbidden, capture)
        self.assertIn("target: /inputs\n        read_only: true", analyzer)
        self.assertIn("dockerfile: docker/capture.Dockerfile", capture)
        self.assertIn("dockerfile: docker/analyzer.Dockerfile", analyzer)
        self.assertIn("condition: service_completed_successfully", analyzer)
        self.assertIn('mem_limit: "${CAPTURE_MEMORY_LIMIT:-4g}"', capture)
        self.assertIn('mem_limit: "${ANALYZER_MEMORY_LIMIT:-32g}"', compose)
        self.assertIn('MODKIT_GHIDRA_MAX_HEAP: "${GHIDRA_MAX_HEAP:-24G}"', compose)
        self.assertIn('MODKIT_UID: "${LOCAL_UID:-1000}"', compose)
        self.assertIn('MODKIT_GID: "${LOCAL_GID:-1000}"', compose)
        self.assertIn("XDG_CACHE_HOME: /cache/xdg", compose)
        self.assertIn("TMPDIR: /work/tmp", compose)

    def test_profiles_fail_closed_for_game_decompilation(self) -> None:
        generic = read_text("profiles/decompilation.example.yaml")
        policy = read_text("profiles/aniimo.decompilation.yaml")
        for profile in (generic, policy):
            self.assertIn("unknown_ownership: needs_review", profile)
            self.assertIn("require_evidence_for_game_decompile: true", profile)
        self.assertIn("game_decompile: []", generic)
        self.assertIn("full_module_decompile:", policy)
        for module in (
            "NEP2.dll",
            "NEPKernel.sys",
            "NEPCleaner.exe",
            "KernelDumpAnalyzer.exe",
        ):
            self.assertIn(module, policy)

    def test_input_allowlist_is_bounded_and_separate_from_scope(self) -> None:
        inputs = read_text("profiles/aniimo.inputs.yaml")
        profile = read_text("profiles/aniimo.yaml")
        decompilation = read_text("profiles/aniimo.decompilation.yaml")
        payloads = inputs.split("payload_rules:", maxsplit=1)[1].split(
            "external_payload_rules:", maxsplit=1
        )[0]
        self.assertIn("default_action: ignore", inputs)
        self.assertNotIn('path: "**/*"', inputs)
        self.assertIn("path: GameAssembly.dll", inputs)
        self.assertIn("logical_path: distribution/steam/appmanifest.acf", inputs)
        self.assertNotIn("fingerprint_only_rules:", inputs)
        self.assertIn(
            "default_enabled: [core, lua, content_indexes, anti_cheat]", inputs
        )
        self.assertIn("stable_read_passes: 1", inputs)
        self.assertIn("unchanged_object_action: reuse_without_copy", inputs)
        self.assertIn("decompress_during_capture: false", inputs)
        self.assertNotIn("path: UnityPlayer.dll", payloads)
        for module in (
            "NEP2.dll",
            "NEPKernel.sys",
            "NEPCleaner.exe",
            "KernelDumpAnalyzer.exe",
        ):
            self.assertIn(f"path: {module}", payloads)
            self.assertIn(module, decompilation)
        self.assertIn('path: "NEP*.pdb"', payloads)
        self.assertIn("path: KernelDumpAnalyzer.pdb", payloads)
        self.assertIn(
            "external_implementations: explicit_approved_modules_only",
            decompilation,
        )
        self.assertIn("ghidra: enabled", profile)
        self.assertIn("bsim: enabled", profile)
        self.assertIn(
            "native_decompile_scope: approved_game_integration_and_anti_cheat",
            profile,
        )
        self.assertIn("execute_enabled_stages_only_when_invalidated: true", profile)
        self.assertIn("default_command: update", profile)
        self.assertIn("cached_doctor_checks:", profile)
        self.assertIn("capture_plan: enabled", profile)
        self.assertIn("reuse_plan_in_same_run: true", profile)
        self.assertIn("dry_run_behavior: stop_after_plan_before_write", profile)
        self.assertIn("granularity: stage_and_substep", profile)
        self.assertTrue((ROOT / "examples/csv/stage_timings.csv").is_file())
        rule_ids = [
            line.split(":", maxsplit=1)[1].strip()
            for line in inputs.splitlines()
            if line.strip().startswith("- id:")
        ]
        self.assertGreater(len(rule_ids), 20)
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        self.assertIn("input_selection: /config/aniimo.inputs.yaml", profile)
        self.assertIn(
            "decompilation_policy: /config/aniimo.decompilation.yaml", profile
        )

    def test_volume_prefix_includes_separator(self) -> None:
        environment = read_text(".env.example")
        self.assertIn("ANIIMO_VOLUME_PREFIX=aniimo-", environment)

    def test_historical_evidence_is_not_current_detection(self) -> None:
        profile = read_text("profiles/aniimo.yaml")
        self.assertIn("status: unverified_for_current_installation", profile)
        self.assertIn("source_document: docs/aniimo/HISTORICAL_EVIDENCE.md", profile)

    def test_tool_lock_is_explicitly_unresolved(self) -> None:
        lock = json.loads(read_text("tools.lock.json"))
        self.assertEqual(lock["lock_status"], "unresolved")
        self.assertEqual(lock["tools"], [])
        self.assertEqual(lock["image_digests"], {"capture": None, "analyzer": None})

    def test_next_milestone_is_m0_only(self) -> None:
        prompt = read_text("CODEX_PROMPT.md")
        self.assertIn("Travail immédiat : M0 uniquement", prompt)
        self.assertIn("Commence et termine M0 uniquement", prompt)

    def test_sample_is_not_tracked(self) -> None:
        result = subprocess.run(
            ["git", "ls-files", ".sample"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
