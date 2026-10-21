from __future__ import annotations

import csv
import io
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .util import atomic_write_bytes, atomic_write_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _peak_rss_bytes() -> int | None:
    try:
        import resource

        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if os.uname().sysname == "Darwin" else value * 1024)
    except (ImportError, AttributeError, OSError):
        return None


@dataclass
class Step:
    step_id: str
    stage_name: str
    parent_step_id: str | None = None
    substep_name: str | None = None
    category: str = "pipeline"
    component_id: str | None = None
    status: str = "completed"
    reason: str | None = None
    cache_status: str = "not_applicable"
    tool_name: str | None = None
    tool_version: str | None = None
    started_at: str = field(default_factory=_utc_now)
    ended_at: str | None = None
    duration_ms: float = 0.0
    input_item_count: int = 0
    input_bytes: int = 0
    output_item_count: int = 0
    output_bytes: int = 0
    cpu_time_ms: float | None = None
    peak_rss_bytes: int | None = None
    error_code: str | None = None
    _start_monotonic: float = field(default_factory=time.monotonic, repr=False)
    _start_cpu: float = field(default_factory=time.process_time, repr=False)

    def finish(self) -> None:
        self.ended_at = _utc_now()
        self.duration_ms = round((time.monotonic() - self._start_monotonic) * 1000, 3)
        self.cpu_time_ms = round((time.process_time() - self._start_cpu) * 1000, 3)
        self.peak_rss_bytes = _peak_rss_bytes()

    def public(self) -> dict[str, Any]:
        fields = (
            "step_id",
            "parent_step_id",
            "stage_name",
            "substep_name",
            "category",
            "component_id",
            "status",
            "reason",
            "cache_status",
            "tool_name",
            "tool_version",
            "started_at",
            "ended_at",
            "duration_ms",
            "input_item_count",
            "input_bytes",
            "output_item_count",
            "output_bytes",
            "cpu_time_ms",
            "peak_rss_bytes",
            "error_code",
        )
        return {name: getattr(self, name) for name in fields}


class RunReport:
    def __init__(self, workflow_run_id: str, phase: str) -> None:
        self.workflow_run_id = workflow_run_id
        self.phase = phase
        self.steps: list[Step] = []
        self.started_at = _utc_now()
        self._start_monotonic = time.monotonic()
        self.ended_at: str | None = None
        self.duration_ms = 0.0
        self.status = "running"
        self.snapshot_id: str | None = None
        self.metadata: dict[str, Any] = {}

    @contextmanager
    def step(self, step_id: str, stage_name: str, **kwargs: Any) -> Iterator[Step]:
        step = Step(step_id=step_id, stage_name=stage_name, **kwargs)
        self.steps.append(step)
        try:
            yield step
        except BaseException as exc:
            step.status = "failed"
            step.reason = str(exc)
            step.error_code = getattr(exc, "error_code", type(exc).__name__)
            raise
        finally:
            step.finish()

    def add_step(self, step_id: str, stage_name: str, **kwargs: Any) -> Step:
        step = Step(step_id=step_id, stage_name=stage_name, **kwargs)
        step.finish()
        self.steps.append(step)
        return step

    def finish(self, status: str = "completed") -> None:
        self.status = status
        self.ended_at = _utc_now()
        self.duration_ms = round((time.monotonic() - self._start_monotonic) * 1000, 3)

    def public(self) -> dict[str, Any]:
        step_duration_sum_ms = round(sum(step.duration_ms for step in self.steps), 3)
        critical_path_ms = round(
            sum(step.duration_ms for step in self.steps if step.parent_step_id is None),
            3,
        )
        return {
            "critical_path_ms": critical_path_ms,
            "duration_ms": self.duration_ms,
            "ended_at": self.ended_at,
            "metadata": self.metadata,
            "phase": self.phase,
            "schema_version": 1,
            "snapshot_id": self.snapshot_id,
            "started_at": self.started_at,
            "status": self.status,
            "step_duration_sum_ms": step_duration_sum_ms,
            "steps": [step.public() for step in self.steps],
            "workflow_run_id": self.workflow_run_id,
        }


TIMING_FIELDS = [
    "step_id",
    "parent_step_id",
    "stage_name",
    "substep_name",
    "category",
    "component_id",
    "status",
    "reason",
    "cache_status",
    "tool_name",
    "tool_version",
    "started_at",
    "ended_at",
    "duration_ms",
    "input_item_count",
    "input_bytes",
    "output_item_count",
    "output_bytes",
    "cpu_time_ms",
    "peak_rss_bytes",
    "error_code",
]


def merge_reports(
    capture: dict[str, Any] | None, analysis: RunReport
) -> dict[str, Any]:
    analysis_value = analysis.public()
    capture_steps = list(capture.get("steps", [])) if capture else []
    steps = capture_steps + analysis_value["steps"]
    start_candidates = [
        value
        for value in (
            capture.get("started_at") if capture else None,
            analysis_value["started_at"],
        )
        if value
    ]
    phase_duration = float(analysis_value.get("duration_ms") or 0)
    if capture:
        phase_duration += float(capture.get("duration_ms") or 0)
    step_duration_sum = sum(float(item.get("duration_ms") or 0) for item in steps)
    critical_path = sum(
        float(item.get("duration_ms") or 0)
        for item in steps
        if item.get("parent_step_id") is None
    )
    return {
        "critical_path_ms": round(critical_path, 3),
        "duration_ms": round(phase_duration, 3),
        "ended_at": analysis_value["ended_at"],
        "metadata": {
            "capture": capture.get("metadata", {}) if capture else None,
            "analysis": analysis_value["metadata"],
        },
        "phase": "capture_and_analysis" if capture else "analysis",
        "schema_version": 1,
        "snapshot_id": analysis_value["snapshot_id"],
        "started_at": min(start_candidates),
        "status": analysis_value["status"],
        "step_duration_sum_ms": round(step_duration_sum, 3),
        "steps": steps,
        "workflow_run_id": analysis_value["workflow_run_id"],
    }


def report_markdown(report: dict[str, Any]) -> bytes:
    steps = report["steps"]
    cache_hits = [step for step in steps if step.get("cache_status") == "hit"]
    failures = [step for step in steps if step.get("status") == "failed"]
    slowest = sorted(
        steps, key=lambda step: float(step.get("duration_ms") or 0), reverse=True
    )[:10]
    lines = [
        "# Rapport d’exécution",
        "",
        f"- Run : `{report['workflow_run_id']}`",
        f"- Snapshot : `{report.get('snapshot_id')}`",
        f"- Statut : `{report['status']}`",
        f"- Durée mesurée : {report['duration_ms']:.3f} ms",
        f"- Somme des étapes : {float(report.get('step_duration_sum_ms') or 0):.3f} ms",
        f"- Chemin critique calculé : {float(report.get('critical_path_ms') or 0):.3f} ms",
        f"- Étapes : {len(steps)} ({len(cache_hits)} cache hit, {len(failures)} échec)",
        "",
        "## Étapes les plus lentes",
        "",
        "| Étape | Statut | Cache | Durée (ms) | Entrée (octets) | Sortie (octets) |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for step in slowest:
        lines.append(
            f"| `{step['step_id']}` | {step['status']} | {step.get('cache_status') or ''} | "
            f"{float(step.get('duration_ms') or 0):.3f} | {int(step.get('input_bytes') or 0)} | {int(step.get('output_bytes') or 0)} |"
        )
    if failures:
        lines.extend(["", "## Échecs", ""])
        for step in failures:
            lines.append(
                f"- `{step['step_id']}` : {step.get('error_code')} — {step.get('reason')}"
            )
    lines.extend(
        [
            "",
            "> Les durées proviennent d’une horloge monotone. Leur somme n’est pas assimilée au temps mural en cas de chevauchement.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def timings_csv(report: dict[str, Any]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream, fieldnames=TIMING_FIELDS, extrasaction="ignore", lineterminator="\n"
    )
    writer.writeheader()
    for step in report["steps"]:
        writer.writerow(step)
    return stream.getvalue().encode("utf-8")


def publish_report(root: Path, report: dict[str, Any]) -> Path:
    report_root = root / "reports" / report["workflow_run_id"]
    atomic_write_json(report_root / "run-report.json", report)
    atomic_write_bytes(report_root / "report.md", report_markdown(report))
    atomic_write_bytes(report_root / "timings.csv", timings_csv(report))
    pointer = {
        "report": f"reports/{report['workflow_run_id']}/run-report.json",
        "schema_version": 1,
        "snapshot_id": report.get("snapshot_id"),
        "workflow_run_id": report["workflow_run_id"],
    }
    atomic_write_json(root / "reports" / "latest.json", pointer)
    return report_root
