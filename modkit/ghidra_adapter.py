from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ModkitError, ValidationError
from .util import atomic_write_bytes, digest_json, read_json, sha256_file

BODY_STATUSES = {"c_and_asm", "asm_only", "disassembly_failed", "pending"}
SAFE_STEM = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass(frozen=True)
class GhidraExport:
    output_root: Path
    summary: dict[str, Any]
    bodies: tuple[dict[str, Any], ...]
    references: tuple[dict[str, Any], ...]
    unattributed_ranges: tuple[dict[str, Any], ...]
    project_uri: str
    command_log: Path
    bsim_signature: Path | None = None
    bsim_log: Path | None = None
    bsim_config: str | None = None
    resumed: bool = False


def _ndjson(path: Path) -> tuple[dict[str, Any], ...]:
    values: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValidationError(
                    f"NDJSON Ghidra invalide ({path.name}:{line_number}).",
                    error_code="ghidra_output_invalid",
                ) from exc
            if not isinstance(value, dict):
                raise ValidationError(
                    f"Entrée NDJSON Ghidra invalide ({path.name}:{line_number}).",
                    error_code="ghidra_output_invalid",
                )
            values.append(value)
    return tuple(values)


def load_export(output_root: Path, expected_sha256: str) -> GhidraExport:
    required = (
        "summary.json",
        "bodies.ndjson",
        "references.ndjson",
        "unattributed-ranges.ndjson",
    )
    if any(not (output_root / name).is_file() for name in required):
        raise ValidationError(
            "Export Ghidra incomplet.", error_code="ghidra_output_incomplete"
        )
    summary = read_json(output_root / "summary.json")
    if summary.get("executable_sha256") != expected_sha256:
        raise ValidationError(
            "Digest du programme Ghidra différent du module remis.",
            error_code="ghidra_program_digest_mismatch",
        )
    bodies = _ndjson(output_root / "bodies.ndjson")
    references = _ndjson(output_root / "references.ndjson")
    ranges = _ndjson(output_root / "unattributed-ranges.ndjson")
    if summary.get("function_count") != len(bodies):
        raise ValidationError(
            "Décompte des fonctions Ghidra incohérent.",
            error_code="ghidra_output_inconsistent",
        )
    ordinals: set[int] = set()
    rvas: set[int] = set()
    status_counts = {status: 0 for status in BODY_STATUSES}
    for body in bodies:
        try:
            ordinal = int(body["ordinal"])
            rva = int(str(body["rva"]), 0)
            status = str(body["body_output_status"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(
                "Corps Ghidra incomplet.", error_code="ghidra_output_invalid"
            ) from exc
        if ordinal in ordinals or rva in rvas or status not in BODY_STATUSES:
            raise ValidationError(
                "Identité ou état de corps Ghidra invalide.",
                error_code="ghidra_output_invalid",
            )
        ordinals.add(ordinal)
        rvas.add(rva)
        status_counts[status] += 1
        asm_path = body.get("asm_path")
        c_path = body.get("c_path")
        if status in {"c_and_asm", "asm_only", "pending"} and (
            not asm_path or not (output_root / str(asm_path)).is_file()
        ):
            raise ValidationError(
                "ASM obligatoire absent.", error_code="ghidra_asm_missing"
            )
        if status == "c_and_asm":
            if not c_path or not (output_root / str(c_path)).is_file():
                raise ValidationError(
                    "Pseudocode C déclaré mais absent.",
                    error_code="ghidra_c_missing",
                )
            c_text = (output_root / str(c_path)).read_text(
                encoding="utf-8", errors="replace"
            )
            if not c_text.strip() or "{" not in c_text or "}" not in c_text:
                raise ValidationError(
                    "Pseudocode C vide ou tronqué.", error_code="ghidra_c_invalid"
                )
        elif c_path is not None:
            raise ValidationError(
                "C présent pour un état qui ne l'autorise pas.",
                error_code="ghidra_output_inconsistent",
            )
    for status, count in status_counts.items():
        if int(summary.get(status, -1)) != count:
            raise ValidationError(
                "Décompte d'état Ghidra incohérent.",
                error_code="ghidra_output_inconsistent",
            )
    return GhidraExport(
        output_root=output_root,
        summary=summary,
        bodies=bodies,
        references=references,
        unattributed_ranges=ranges,
        project_uri="",
        command_log=output_root / "ghidra.log",
    )


class GhidraAdapter:
    def __init__(
        self,
        *,
        executable: Path,
        script: Path,
        project_root: Path,
        work_root: Path,
        timeout_seconds: int,
        maximum_primary_timeouts: int,
        difficult_timeout_seconds: int = 120,
        maximum_difficult_bodies: int = 2,
        maximum_difficult_wall_seconds: int = 240,
        analysis_timeout_seconds: int = 3600,
        bsim_executable: Path | None = None,
        bsim_enabled: bool = True,
    ) -> None:
        self.executable = executable
        self.script = script
        self.project_root = project_root
        self.work_root = work_root
        self.timeout_seconds = timeout_seconds
        self.maximum_primary_timeouts = maximum_primary_timeouts
        self.difficult_timeout_seconds = difficult_timeout_seconds
        self.maximum_difficult_bodies = maximum_difficult_bodies
        self.maximum_difficult_wall_seconds = maximum_difficult_wall_seconds
        self.analysis_timeout_seconds = analysis_timeout_seconds
        self.bsim_executable = bsim_executable
        self.bsim_enabled = bsim_enabled

    def context(self) -> dict[str, Any]:
        script_sha256, _ = sha256_file(self.script)
        return {
            "analysis_timeout_seconds": self.analysis_timeout_seconds,
            "exporter_sha256": script_sha256,
            "difficult_timeout_seconds": self.difficult_timeout_seconds,
            "maximum_difficult_bodies": self.maximum_difficult_bodies,
            "maximum_difficult_wall_seconds": self.maximum_difficult_wall_seconds,
            "maximum_primary_timeouts": self.maximum_primary_timeouts,
            "primary_timeout_seconds": self.timeout_seconds,
            "tool": "Ghidra 12.1.4 PUBLIC",
            "bsim": {
                "enabled": self.bsim_enabled,
                "tool": "Ghidra BSim 12.1.4 PUBLIC",
            },
        }

    def export_module(
        self, *, module_path: Path, module_logical_path: str, module_sha256: str
    ) -> GhidraExport:
        if not self.executable.is_file() or not os.access(self.executable, os.X_OK):
            raise ModkitError(
                "Exécutable Ghidra indisponible.",
                exit_code=6,
                error_code="ghidra_missing",
            )
        if not self.script.is_file():
            raise ModkitError(
                "Script d'export Ghidra absent.",
                exit_code=6,
                error_code="ghidra_script_missing",
            )
        context_digest = digest_json(
            {
                **self.context(),
                "module_sha256": module_sha256,
            }
        )
        stem = SAFE_STEM.sub("-", Path(module_logical_path).name).strip(".-")
        project_parent = self.project_root / context_digest
        project_parent.mkdir(parents=True, exist_ok=True)
        project_name = f"{stem}-{module_sha256[:12]}"
        output_root = self.work_root / context_digest / stem
        output_root.mkdir(parents=True, exist_ok=True)
        project_uri = f"ghidra:{project_parent.as_posix()}/{project_name}"
        try:
            resumed_export = load_export(output_root, module_sha256)
        except (OSError, ValidationError):
            resumed_export = None
        if resumed_export is not None:
            signatures = sorted(
                path
                for path in (output_root / "bsim").glob("sigs_*")
                if path.is_file() and path.stat().st_size > 0
            )
            if not self.bsim_enabled or len(signatures) == 1:
                bsim_config = (
                    "medium_64"
                    if ":64:" in str(resumed_export.summary.get("language_id"))
                    else "medium_32"
                )
                return GhidraExport(
                    output_root=resumed_export.output_root,
                    summary=resumed_export.summary,
                    bodies=resumed_export.bodies,
                    references=resumed_export.references,
                    unattributed_ranges=resumed_export.unattributed_ranges,
                    project_uri=project_uri,
                    command_log=output_root / "ghidra.log",
                    bsim_signature=signatures[0] if signatures else None,
                    bsim_log=output_root / "bsim.log",
                    bsim_config=bsim_config if self.bsim_enabled else None,
                    resumed=True,
                )
        command = [
            str(self.executable),
            str(project_parent),
            project_name,
            "-import",
            str(module_path),
            "-overwrite",
            "-max-cpu",
            "1",
            "-analysisTimeoutPerFile",
            str(self.analysis_timeout_seconds),
            "-scriptPath",
            str(self.script.parent),
            "-postScript",
            self.script.name,
            str(output_root),
            str(self.timeout_seconds),
            str(self.maximum_primary_timeouts),
            str(self.difficult_timeout_seconds),
            str(self.maximum_difficult_bodies),
            str(self.maximum_difficult_wall_seconds),
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=self.analysis_timeout_seconds + 600,
        )
        log = (
            f"exit_code={completed.returncode}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}\n"
        ).encode("utf-8", errors="replace")
        log_path = output_root / "ghidra.log"
        atomic_write_bytes(log_path, log)
        if completed.returncode != 0 or "SCRIPT ERROR" in completed.stdout:
            raise ModkitError(
                f"Échec Ghidra pour {module_logical_path}; voir le journal privé.",
                exit_code=6,
                error_code="ghidra_failed",
            )
        export = load_export(output_root, module_sha256)
        bsim_signature = None
        bsim_log = None
        bsim_config = None
        if self.bsim_enabled:
            if (
                self.bsim_executable is None
                or not self.bsim_executable.is_file()
                or not os.access(self.bsim_executable, os.X_OK)
            ):
                raise ModkitError(
                    "Exécutable BSim indisponible.",
                    exit_code=6,
                    error_code="bsim_missing",
                )
            bsim_config = (
                "medium_64"
                if ":64:" in str(export.summary.get("language_id"))
                else "medium_32"
            )
            bsim_root = output_root / "bsim"
            bsim_root.mkdir(parents=True, exist_ok=True)
            bsim_command = [
                str(self.bsim_executable),
                "generatesigs",
                project_uri,
                str(bsim_root),
                "--config",
                bsim_config,
                "--overwrite",
            ]
            bsim_completed = subprocess.run(
                bsim_command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.analysis_timeout_seconds + 600,
            )
            bsim_log = output_root / "bsim.log"
            atomic_write_bytes(
                bsim_log,
                (
                    f"exit_code={bsim_completed.returncode}\n"
                    f"stdout:\n{bsim_completed.stdout}\n"
                    f"stderr:\n{bsim_completed.stderr}\n"
                ).encode("utf-8", errors="replace"),
            )
            signatures = sorted(
                path
                for path in bsim_root.glob("sigs_*")
                if path.is_file() and path.stat().st_size > 0
            )
            if bsim_completed.returncode != 0 or len(signatures) != 1:
                raise ModkitError(
                    f"Échec BSim pour {module_logical_path}; voir le journal privé.",
                    exit_code=6,
                    error_code="bsim_failed",
                )
            bsim_signature = signatures[0]
        return GhidraExport(
            output_root=export.output_root,
            summary=export.summary,
            bodies=export.bodies,
            references=export.references,
            unattributed_ranges=export.unattributed_ranges,
            project_uri=project_uri,
            command_log=log_path,
            bsim_signature=bsim_signature,
            bsim_log=bsim_log,
            bsim_config=bsim_config,
        )
