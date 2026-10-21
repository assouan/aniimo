from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from .errors import ValidationError


@dataclass(frozen=True)
class PeSection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


class PeImage:
    """Read only the bounded PE headers needed for native locations."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.file_size = path.stat().st_size
        with path.open("rb") as stream:
            dos = stream.read(64)
            if len(dos) != 64 or dos[:2] != b"MZ":
                raise ValidationError("Image PE invalide.", error_code="invalid_pe")
            pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
            if pe_offset < 64 or pe_offset > min(self.file_size - 24, 1024 * 1024):
                raise ValidationError(
                    "Offset PE hors limites.", error_code="invalid_pe"
                )
            stream.seek(pe_offset)
            header = stream.read(24)
            if len(header) != 24 or header[:4] != b"PE\0\0":
                raise ValidationError("Signature PE invalide.", error_code="invalid_pe")
            self.machine, section_count, _, _, _, optional_size, _ = struct.unpack_from(
                "<HHIIIHH", header, 4
            )
            if not 0 < section_count <= 96 or not 96 <= optional_size <= 4096:
                raise ValidationError(
                    "En-tête PE non plausible.", error_code="invalid_pe"
                )
            optional = stream.read(optional_size)
            if len(optional) != optional_size:
                raise ValidationError(
                    "En-tête optionnel PE tronqué.", error_code="invalid_pe"
                )
            magic = struct.unpack_from("<H", optional)[0]
            if magic == 0x10B:
                self.architecture = "x86"
                self.image_base = struct.unpack_from("<I", optional, 28)[0]
                directory_offset = 96
                directory_count_offset = 92
            elif magic == 0x20B:
                self.architecture = "x86_64"
                self.image_base = struct.unpack_from("<Q", optional, 24)[0]
                directory_offset = 112
                directory_count_offset = 108
            else:
                raise ValidationError(
                    "Format d'en-tête PE non pris en charge.",
                    error_code="unsupported_pe_format",
                )
            self.optional_magic = magic
            self.entrypoint_rva = struct.unpack_from("<I", optional, 16)[0]
            directory_count = min(
                struct.unpack_from("<I", optional, directory_count_offset)[0], 32
            )
            available_directories = max(0, (len(optional) - directory_offset) // 8)
            self.data_directories = tuple(
                struct.unpack_from("<II", optional, directory_offset + index * 8)
                for index in range(min(directory_count, available_directories))
            )
            sections: list[PeSection] = []
            for _ in range(section_count):
                raw = stream.read(40)
                if len(raw) != 40:
                    raise ValidationError(
                        "Table de sections PE tronquée.", error_code="invalid_pe"
                    )
                name = raw[:8].split(b"\0", 1)[0].decode("ascii", errors="replace")
                virtual_size, virtual_address, raw_size, raw_offset = (
                    struct.unpack_from("<IIII", raw, 8)
                )
                characteristics = struct.unpack_from("<I", raw, 36)[0]
                if raw_size and (
                    raw_offset > self.file_size
                    or raw_size > self.file_size - raw_offset
                ):
                    raise ValidationError(
                        "Section PE hors fichier.", error_code="invalid_pe"
                    )
                sections.append(
                    PeSection(
                        name=name,
                        virtual_address=virtual_address,
                        virtual_size=virtual_size,
                        raw_offset=raw_offset,
                        raw_size=raw_size,
                        characteristics=characteristics,
                    )
                )
            self.sections = tuple(sections)

    def rva_to_offset(self, rva: int) -> int | None:
        if rva < 0:
            return None
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                delta = rva - section.virtual_address
                if delta >= section.raw_size:
                    return None
                offset = section.raw_offset + delta
                return offset if offset < self.file_size else None
        if rva < min(self.file_size, 1024 * 1024):
            return rva
        return None

    def preferred_va(self, rva: int) -> str:
        return f"0x{self.image_base + rva:x}"

    def _read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset > self.file_size - size:
            raise ValidationError("Lecture PE hors limites.", error_code="invalid_pe")
        with self.path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(size)
        if len(data) != size:
            raise ValidationError("Image PE tronquée.", error_code="invalid_pe")
        return data

    def export_names(self, maximum_names: int = 20_000) -> list[str]:
        """Read the bounded PE export-name table without loading the image."""
        if not self.data_directories:
            return []
        export_rva, export_size = self.data_directories[0]
        if not export_rva or export_size < 40:
            return []
        export_offset = self.rva_to_offset(export_rva)
        if export_offset is None:
            raise ValidationError(
                "Table d'exports PE hors image.", error_code="invalid_pe"
            )
        directory = self._read_at(export_offset, 40)
        number_of_names = struct.unpack_from("<I", directory, 24)[0]
        names_rva = struct.unpack_from("<I", directory, 32)[0]
        if number_of_names > maximum_names:
            raise ValidationError("Trop d'exports PE.", error_code="invalid_pe")
        if not names_rva or not number_of_names:
            return []
        names_offset = self.rva_to_offset(names_rva)
        if names_offset is None:
            raise ValidationError(
                "Table de noms PE hors image.", error_code="invalid_pe"
            )
        offsets = self._read_at(names_offset, number_of_names * 4)
        result: set[str] = set()
        for index in range(number_of_names):
            name_rva = struct.unpack_from("<I", offsets, index * 4)[0]
            name_offset = self.rva_to_offset(name_rva)
            if name_offset is None:
                raise ValidationError(
                    "Nom d'export PE hors image.", error_code="invalid_pe"
                )
            maximum = min(1024, self.file_size - name_offset)
            raw = self._read_at(name_offset, maximum).split(b"\0", 1)[0]
            result.add(raw.decode("ascii", errors="replace"))
        return sorted(result, key=lambda value: (value.casefold(), value))

    def load_context(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "entrypoint_rva": f"0x{self.entrypoint_rva:x}",
            "file_format": "PE32+" if self.optional_magic == 0x20B else "PE32",
            "image_base": f"0x{self.image_base:x}",
            "machine": f"0x{self.machine:04x}",
            "sections": [
                {
                    "characteristics": f"0x{item.characteristics:08x}",
                    "name": item.name,
                    "raw_offset": item.raw_offset,
                    "raw_size": item.raw_size,
                    "virtual_address": item.virtual_address,
                    "virtual_size": item.virtual_size,
                }
                for item in self.sections
            ],
        }
