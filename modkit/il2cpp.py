from __future__ import annotations

import math
import struct
from collections import Counter
from pathlib import Path
from typing import Any

from .util import confined_path

IL2CPP_MAGIC = 0xFAB11BAF
KNOWN_METADATA_VERSIONS = {24, 27, 29, 30, 31}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _payload(manifest: dict[str, Any], logical_path: str) -> dict[str, Any] | None:
    for item in manifest.get("payloads", []):
        if str(item.get("logical_path", "")).casefold() == logical_path.casefold():
            return item
    return None


def inspect_metadata_pair(
    *, manifest: dict[str, Any], snapshot_files: Path
) -> dict[str, Any]:
    """Classify the exact IL2CPP pair without executing or guessing a decoder."""
    binary_logical = "GameAssembly.dll"
    metadata_logical = "Aniimo_Data/il2cpp_data/Metadata/global-metadata.dat"
    binary = _payload(manifest, binary_logical)
    metadata = _payload(manifest, metadata_logical)
    base: dict[str, Any] = {
        "adapter": {"name": "modkit.il2cpp.bounded-header", "version": "1"},
        "binary": None,
        "catalog_published": False,
        "fallback_used": False,
        "metadata": None,
        "schema_version": 1,
        "snapshot_id": manifest.get("snapshot_id"),
    }
    if binary is None or metadata is None:
        return {
            **base,
            "status": "inconsistent_metadata",
            "diagnostic": "exact_binary_metadata_pair_missing_from_snapshot",
        }

    binary_path = confined_path(snapshot_files, binary_logical)
    metadata_path = confined_path(snapshot_files, metadata_logical)
    if not binary_path.is_file() or not metadata_path.is_file():
        return {
            **base,
            "status": "inconsistent_metadata",
            "diagnostic": "snapshot_materialization_missing",
        }

    size = metadata_path.stat().st_size
    with metadata_path.open("rb") as stream:
        header = stream.read(4096)
        stream.seek(0)
        sample = stream.read(min(size, 1024 * 1024))
    if len(header) < 8:
        return {
            **base,
            "binary": {
                "logical_path": binary_logical,
                "sha256": binary["sha256"],
            },
            "metadata": {
                "logical_path": metadata_logical,
                "sha256": metadata["sha256"],
                "size_bytes": size,
            },
            "status": "parse_error",
            "diagnostic": "metadata_header_truncated",
        }

    magic, raw_version = struct.unpack_from("<II", header)
    entropy = round(_entropy(sample), 6)
    details = {
        **base,
        "binary": {
            "logical_path": binary_logical,
            "object_id": binary.get("object_id"),
            "sha256": binary["sha256"],
            "size_bytes": binary["size_bytes"],
        },
        "evidence": {
            "first_16_bytes_hex": header[:16].hex(),
            "magic": f"0x{magic:08x}",
            "raw_version_field": raw_version,
            "sample_entropy_bits_per_byte": entropy,
            "sample_size_bytes": len(sample),
            "second_dword_equals_file_size": raw_version == size,
        },
        "metadata": {
            "logical_path": metadata_logical,
            "object_id": metadata.get("object_id"),
            "sha256": metadata["sha256"],
            "size_bytes": size,
        },
    }
    if magic != IL2CPP_MAGIC:
        return {
            **details,
            "status": "parse_error",
            "diagnostic": "il2cpp_magic_absent",
        }
    if raw_version in KNOWN_METADATA_VERSIONS:
        return {
            **details,
            "status": "parse_error",
            "diagnostic": "known_version_requires_exact_parser_not_available",
        }
    if 1 <= raw_version <= 255:
        return {
            **details,
            "status": "unsupported_metadata_version",
            "diagnostic": "metadata_version_not_supported_by_pinned_adapter",
        }
    if raw_version == size and entropy >= 7.5:
        return {
            **details,
            "status": "suspected_protection",
            "diagnostic": "standard_magic_followed_by_nonconforming_size_field_and_high_entropy_payload",
        }
    return {
        **details,
        "status": "parse_error",
        "diagnostic": "nonconforming_metadata_header",
    }
