from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import ModkitError
from .handoff import publish_handoff
from .util import atomic_write_json, read_json, validate_slot


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@contextmanager
def capture_watch_lock(inputs_root: Path, slot: str) -> Iterator[Path]:
    """Prevent overlapping watchers for one handoff slot."""
    slot = validate_slot(slot)
    lock_root = inputs_root / "watch"
    lock_root.mkdir(parents=True, exist_ok=True)
    lock = lock_root / f"{slot}.lock"
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ModkitError(
            f"Un watcher détient déjà le slot {slot!r}.",
            exit_code=3,
            error_code="watch_slot_locked",
        ) from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(str(os.getpid()))
            stream.flush()
            os.fsync(stream.fileno())
        yield lock
    finally:
        lock.unlink(missing_ok=True)


def _current_snapshot(inputs_root: Path) -> str | None:
    pointer = inputs_root / "current.json"
    if not pointer.is_file():
        return None
    try:
        return str(read_json(pointer)["snapshot_id"])
    except (OSError, KeyError, TypeError, ValueError):
        return None


def _pending_is_same(handoff_root: Path, slot: str, snapshot_id: str) -> bool:
    pending = handoff_root / "pending" / f"{slot}.json"
    if not pending.is_file():
        return False
    try:
        return str(read_json(pending).get("snapshot_id")) == snapshot_id
    except (OSError, TypeError, ValueError):
        return False


def watch_capture(
    *,
    inputs_root: Path,
    handoff_root: Path,
    handoff_slot: str,
    interval_seconds: float,
    capture_once: Callable[[], dict[str, Any]],
    stop_event: threading.Event | None = None,
    once: bool = False,
    max_iterations: int | None = None,
    continue_on_error: bool = True,
) -> dict[str, Any]:
    """Poll with full capture semantics and dispatch only changed snapshots."""
    slot = validate_slot(handoff_slot)
    if interval_seconds <= 0:
        raise ModkitError(
            "L’intervalle du watcher doit être positif.",
            exit_code=2,
            error_code="watch_interval_invalid",
        )
    if max_iterations is not None and max_iterations < 1:
        raise ModkitError(
            "Le nombre maximal d’itérations doit être positif.",
            exit_code=2,
            error_code="watch_iterations_invalid",
        )
    stop = stop_event or threading.Event()
    state_root = inputs_root / "watch"
    state_path = state_root / f"{slot}.json"
    existing = read_json(state_path) if state_path.is_file() else {}
    baseline = _current_snapshot(inputs_root)
    last_dispatched = existing.get("last_dispatched_snapshot_id", baseline)
    iterations = 0
    captures_succeeded = 0
    dispatches = 0
    failures = 0
    errors: list[dict[str, str]] = []

    with capture_watch_lock(inputs_root, slot):
        while not stop.is_set():
            iterations += 1
            try:
                result = capture_once()
                captures_succeeded += 1
                snapshot_id = str(result["snapshot_id"])
                if snapshot_id != last_dispatched:
                    record = {
                        "capture_report": (
                            f"run-reports/{result['workflow_run_id']}.json"
                        ),
                        "schema_version": 1,
                        "snapshot_id": snapshot_id,
                        "snapshot_manifest_sha256": str(result["manifest_sha256"]),
                        "workflow_run_id": str(result["workflow_run_id"]),
                    }
                    if not _pending_is_same(handoff_root, slot, snapshot_id):
                        publish_handoff(handoff_root, slot, record)
                    last_dispatched = snapshot_id
                    dispatches += 1
                atomic_write_json(
                    state_path,
                    {
                        "captures_succeeded": captures_succeeded,
                        "dispatches": dispatches,
                        "failures": failures,
                        "handoff_slot": slot,
                        "iterations": iterations,
                        "last_dispatched_snapshot_id": last_dispatched,
                        "last_error": None,
                        "last_snapshot_id": snapshot_id,
                        "schema_version": 1,
                        "updated_at": _utc_now(),
                    },
                )
            except (ModkitError, OSError, KeyError, TypeError, ValueError) as exc:
                failures += 1
                error = {
                    "error": str(exc),
                    "error_code": getattr(exc, "error_code", type(exc).__name__),
                }
                errors.append(error)
                errors = errors[-20:]
                atomic_write_json(
                    state_path,
                    {
                        "captures_succeeded": captures_succeeded,
                        "dispatches": dispatches,
                        "failures": failures,
                        "handoff_slot": slot,
                        "iterations": iterations,
                        "last_dispatched_snapshot_id": last_dispatched,
                        "last_error": error,
                        "schema_version": 1,
                        "updated_at": _utc_now(),
                    },
                )
                if once or not continue_on_error:
                    raise

            if once or (max_iterations is not None and iterations >= max_iterations):
                break
            stop.wait(interval_seconds)

    return {
        "captures_succeeded": captures_succeeded,
        "dispatches": dispatches,
        "errors": errors,
        "failures": failures,
        "handoff_slot": slot,
        "interval_seconds": interval_seconds,
        "iterations": iterations,
        "last_dispatched_snapshot_id": last_dispatched,
        "state": state_path.relative_to(inputs_root).as_posix(),
        "status": "completed" if once or max_iterations is not None else "stopped",
    }
