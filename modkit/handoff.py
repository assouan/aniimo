from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import CaptureError, ValidationError
from .util import atomic_create_json, fsync_directory, read_json, validate_slot


@dataclass(frozen=True)
class HandoffClaim:
    record: dict[str, Any]
    path: Path
    completed_root: Path

    def complete(self) -> Path:
        destination = self.completed_root / self.path.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise ValidationError(
                f"Archive de remise déjà présente : {destination.name}",
                error_code="handoff_archive_conflict",
            )
        os.replace(self.path, destination)
        fsync_directory(destination.parent)
        return destination

    def release(self) -> Path:
        pending = self.path.parents[1] / "pending" / self.path.name.split("--", 1)[-1]
        if pending.exists():
            raise ValidationError(
                "Impossible de libérer la remise : slot occupé.",
                error_code="handoff_slot_conflict",
            )
        os.replace(self.path, pending)
        return pending

    def fail(self) -> Path:
        destination = self.path.parents[1] / "failed" / self.path.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise ValidationError(
                "Archive de remise échouée déjà présente.",
                error_code="handoff_archive_conflict",
            )
        os.replace(self.path, destination)
        fsync_directory(destination.parent)
        return destination


def publish_handoff(root: Path, slot: str, record: dict[str, Any]) -> Path:
    slot = validate_slot(slot)
    pending = root / "pending" / f"{slot}.json"
    try:
        atomic_create_json(pending, record)
    except FileExistsError as exc:
        raise CaptureError(
            f"Le slot de remise {slot!r} est déjà occupé.",
            error_code="handoff_slot_occupied",
        ) from exc
    return pending


def claim_handoff(root: Path, slot: str) -> HandoffClaim:
    slot = validate_slot(slot)
    pending = root / "pending" / f"{slot}.json"
    if not pending.is_file():
        raise ValidationError(
            f"Remise requise absente pour le slot {slot!r}.",
            error_code="handoff_missing",
        )
    record = read_json(pending)
    run_id = str(record.get("workflow_run_id", "invalid"))
    claimed = root / "claimed" / f"{run_id}--{slot}.json"
    claimed.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(pending, claimed)
    except FileNotFoundError as exc:
        raise ValidationError(
            "La remise a déjà été revendiquée.", error_code="handoff_claim_race"
        ) from exc
    return HandoffClaim(record=record, path=claimed, completed_root=root / "completed")
