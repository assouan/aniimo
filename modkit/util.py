from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any, BinaryIO

from .errors import ConfigurationError

CHUNK_SIZE = 4 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_SLOT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def pretty_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def stream_hash(
    source: BinaryIO, destination: BinaryIO | None = None
) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
        digest.update(chunk)
        size += len(chunk)
        if destination is not None:
            destination.write(chunk)
    if destination is not None:
        destination.flush()
        os.fsync(destination.fileno())
    return digest.hexdigest(), size


def digest_json(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def atomic_write_bytes(path: Path, data: bytes, *, overwrite: bool = True) -> bool:
    """Atomically publish bytes and return whether content changed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and path.read_bytes() == data:
        return False
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if not overwrite and path.exists():
            raise FileExistsError(path)
        os.replace(temporary, path)
        fsync_directory(path.parent)
        return True
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_json(
    path: Path, value: Any, *, pretty: bool = True, overwrite: bool = True
) -> bool:
    data = pretty_json_bytes(value) if pretty else canonical_json_bytes(value)
    return atomic_write_bytes(path, data, overwrite=overwrite)


def atomic_create_json(path: Path, value: Any) -> None:
    """Atomically create a JSON file without replacing an existing slot."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = pretty_json_bytes(value)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise
        except OSError:
            # Windows and some volume drivers can reject hard-link publication.
            fd_out = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                with os.fdopen(fd_out, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            except BaseException:
                path.unlink(missing_ok=True)
                raise
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def normalize_logical_path(raw: str) -> str:
    value = raw.replace("\\", "/")
    if not value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise ConfigurationError(
            f"Chemin logique absolu ou vide interdit : {raw!r}",
            error_code="unsafe_path",
        )
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ConfigurationError(
            f"Chemin logique non normalisé interdit : {raw!r}", error_code="unsafe_path"
        )
    return "/".join(parts)


def confined_path(root: Path, logical_path: str) -> Path:
    normalized = normalize_logical_path(logical_path)
    root_resolved = root.resolve()
    candidate = root.joinpath(*normalized.split("/")).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise ConfigurationError(
            f"Chemin hors racine : {logical_path!r}", error_code="unsafe_path"
        ) from exc
    return candidate


def validate_slot(slot: str) -> str:
    if not SAFE_SLOT_RE.fullmatch(slot):
        raise ConfigurationError(
            "MODKIT_HANDOFF_SLOT doit être un identifiant court sans séparateur.",
            error_code="invalid_handoff_slot",
        )
    return slot


def object_path(root: Path, digest: str) -> Path:
    if not SHA256_RE.fullmatch(digest):
        raise ConfigurationError(
            f"SHA-256 invalide : {digest!r}", error_code="invalid_digest"
        )
    return root / "objects" / "sha256" / digest[:2] / digest


def set_read_only(path: Path) -> None:
    try:
        path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        pass


def materialize_object(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        return
    try:
        os.link(source, destination)
    except OSError:
        shutil.copyfile(source, destination)
    set_read_only(destination)


def publish_cas_staging(staging: Path, destination: Path) -> bool:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        staging.unlink(missing_ok=True)
        return False
    try:
        os.link(staging, destination)
        staging.unlink()
    except FileExistsError:
        staging.unlink(missing_ok=True)
        return False
    except OSError:
        try:
            os.replace(staging, destination)
        except BaseException:
            staging.unlink(missing_ok=True)
            raise
    set_read_only(destination)
    fsync_directory(destination.parent)
    return True


def stable_sorted_dicts(
    items: Iterable[dict[str, Any]], key: str = "logical_path"
) -> list[dict[str, Any]]:
    return sorted(items, key=lambda item: str(item.get(key, "")).casefold())
