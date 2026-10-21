from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Self

from .errors import ModkitError, ValidationError
from .util import canonical_json_bytes


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Registry:
    def __init__(self, path: Path, migrations_root: Path) -> None:
        self.path = path
        self.migrations_root = migrations_root
        self.connection: sqlite3.Connection | None = None
        self.applied_migrations: list[int] = []
        self.backup_path: Path | None = None

    def __enter__(self) -> Self:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.is_file() and self.path.stat().st_size > 0
        self.connection = sqlite3.connect(self.path, timeout=30.0)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        if existed:
            integrity = self.connection.execute("PRAGMA quick_check").fetchone()[0]
            if integrity != "ok":
                raise ValidationError(
                    f"Registre SQLite incohérent : {integrity}",
                    error_code="registry_integrity",
                )
        self._migrate(existed)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    @property
    def db(self) -> sqlite3.Connection:
        if self.connection is None:
            raise RuntimeError("Registry is not open")
        return self.connection

    def _migration_files(self) -> list[tuple[int, Path]]:
        files: list[tuple[int, Path]] = []
        for path in sorted(self.migrations_root.glob("[0-9][0-9][0-9][0-9]_*.sql")):
            files.append((int(path.name.split("_", 1)[0]), path))
        if not files:
            raise ValidationError(
                "Aucune migration SQLite versionnée.", error_code="missing_migrations"
            )
        expected = list(range(1, len(files) + 1))
        if [version for version, _ in files] != expected:
            raise ValidationError(
                "La séquence des migrations SQLite n'est pas contiguë.",
                error_code="migration_sequence",
            )
        return files

    def _migrate(self, existed: bool) -> None:
        files = self._migration_files()
        current = int(self.db.execute("PRAGMA user_version").fetchone()[0])
        pending = [(version, path) for version, path in files if version > current]
        if not pending:
            return
        if existed:
            backup_root = self.path.parent / "backups"
            backup_root.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            self.backup_path = (
                backup_root / f"{self.path.stem}-v{current}-{stamp}.sqlite"
            )
            backup = sqlite3.connect(self.backup_path)
            try:
                self.db.backup(backup)
            finally:
                backup.close()
        try:
            for version, path in pending:
                sql = path.read_text(encoding="utf-8")
                digest = hashlib.sha256(sql.encode("utf-8")).hexdigest()
                script = (
                    "BEGIN IMMEDIATE;\n"
                    + sql
                    + "\nINSERT INTO schema_migrations(version,name,sha256,applied_at) VALUES("
                    + f"{version},{json.dumps(path.name)},{json.dumps(digest)},{json.dumps(_utc_now())});\n"
                    + f"PRAGMA user_version={version};\nCOMMIT;"
                )
                self.db.executescript(script)
                self.applied_migrations.append(version)
        except BaseException:
            self.db.rollback()
            self.db.close()
            self.connection = None
            if self.backup_path is not None:
                shutil.copyfile(self.backup_path, self.path)
            else:
                self.path.unlink(missing_ok=True)
            raise

    def transaction(self) -> sqlite3.Connection:
        self.db.execute("BEGIN IMMEDIATE")
        return self.db

    def commit(self) -> None:
        self.db.commit()

    def rollback(self) -> None:
        self.db.rollback()

    def cache_entry(self, key: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT * FROM cache_entries WHERE cache_key=?", (key,)
        ).fetchone()
        return dict(row) if row is not None else None

    def put_cache_entry(
        self,
        *,
        key: str,
        stage_name: str,
        artifact_sha256: str,
        artifact_logical_path: str,
        producer_name: str,
        producer_version: str,
        context: dict[str, Any],
        analysis_id: str,
    ) -> None:
        self.db.execute(
            """INSERT INTO cache_entries(
                cache_key,stage_name,artifact_sha256,artifact_logical_path,
                producer_name,producer_version,context_json,created_by_analysis_id
            ) VALUES(?,?,?,?,?,?,?,?)""",
            (
                key,
                stage_name,
                artifact_sha256,
                artifact_logical_path,
                producer_name,
                producer_version,
                canonical_json_bytes(context).decode("utf-8"),
                analysis_id,
            ),
        )


@contextmanager
def registry_writer_lock(state_root: Path) -> Iterator[Path]:
    """Fail closed when another analyzer owns the single-writer registry."""
    state_root.mkdir(parents=True, exist_ok=True)
    lock = state_root / "registry.writer.lock"
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ModkitError(
            "Un autre analyseur détient le verrou du registre.",
            exit_code=3,
            error_code="registry_locked",
        ) from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(str(os.getpid()))
            stream.flush()
            os.fsync(stream.fileno())
        yield lock
    finally:
        lock.unlink(missing_ok=True)
