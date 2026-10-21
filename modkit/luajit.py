from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Any


class LuaJITParseError(ValueError):
    """Raised when an untrusted bytecode chunk is unsupported or malformed."""

    def __init__(self, message: str, *, code: str = "parse_error") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class LuaConstant:
    kind: str
    value: Any = None


@dataclass
class LuaPrototype:
    parse_index: int
    flags: int
    num_params: int
    frame_size: int
    upvalue_count: int
    instructions: tuple[int, ...]
    constants: tuple[LuaConstant, ...]
    first_line: int | None
    line_count: int | None
    parameter_names: tuple[str, ...]
    aliases: set[str] = field(default_factory=set)

    @property
    def is_vararg(self) -> bool:
        return bool(self.flags & 0x02)


@dataclass(frozen=True)
class LuaJITChunk:
    version: int
    flags: int
    chunk_name_sha256: str | None
    chunk_name_is_absolute: bool
    prototypes: tuple[LuaPrototype, ...]
    root: LuaPrototype


@dataclass(frozen=True)
class OpcodeDialect:
    gget: int
    kstr: int
    call: int
    fnew: int
    tsets: int
    tgets: int | None
    evidence: dict[str, Any]


class _Reader:
    def __init__(self, data: bytes | memoryview, *, big_endian: bool = False) -> None:
        self.data = memoryview(data)
        self.position = 0
        self.big_endian = big_endian

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    def read_u8(self) -> int:
        if self.remaining < 1:
            raise LuaJITParseError("Truncated LuaJIT bytecode.")
        value = self.data[self.position]
        self.position += 1
        return int(value)

    def read_bytes(self, size: int) -> bytes:
        if size < 0 or size > self.remaining:
            raise LuaJITParseError("Out-of-bounds LuaJIT bytecode field.")
        start = self.position
        self.position += size
        return bytes(self.data[start : start + size])

    def read_u16(self) -> int:
        raw = self.read_bytes(2)
        return int.from_bytes(raw, "big" if self.big_endian else "little")

    def read_u32(self) -> int:
        raw = self.read_bytes(4)
        return int.from_bytes(raw, "big" if self.big_endian else "little")

    def read_uleb128(self) -> int:
        value = 0
        shift = 0
        for _ in range(5):
            byte = self.read_u8()
            value |= (byte & 0x7F) << shift
            if byte < 0x80:
                if value > 0xFFFFFFFF:
                    raise LuaJITParseError("Oversized LuaJIT ULEB128 value.")
                return value
            shift += 7
        raise LuaJITParseError("Overlong LuaJIT ULEB128 value.")

    def read_uleb128_33(self) -> tuple[int, bool]:
        first = self.read_u8()
        is_number = bool(first & 1)
        value = first >> 1
        if value >= 0x40:
            value &= 0x3F
            shift = 6
            for _ in range(4):
                byte = self.read_u8()
                value |= (byte & 0x7F) << shift
                if byte < 0x80:
                    if value > 0xFFFFFFFF:
                        raise LuaJITParseError("Oversized LuaJIT ULEB128_33 value.")
                    return value, is_number
                shift += 7
            raise LuaJITParseError("Overlong LuaJIT ULEB128_33 value.")
        return value, is_number


MAX_PROTOTYPES = 200_000
MAX_CONSTANTS_PER_PROTO = 1_000_000
MAX_INSTRUCTIONS_PER_PROTO = 4_000_000
MAX_STRING_CONSTANT = 16 * 1024 * 1024
KNOWN_DUMP_FLAGS = 0x1F


def _text(value: bytes, *, maximum: int = 1024) -> str | None:
    if not value or len(value) > maximum or b"\0" in value:
        return None
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(character) < 32 for character in decoded):
        return None
    return decoded


def _read_table_constant(reader: _Reader, *, depth: int = 0) -> Any:
    if depth > 32:
        raise LuaJITParseError("LuaJIT table constant nesting is too deep.")
    kind = reader.read_uleb128()
    if kind >= 5:
        size = kind - 5
        if size > MAX_STRING_CONSTANT:
            raise LuaJITParseError("LuaJIT table string constant is too large.")
        raw = reader.read_bytes(size)
        return {
            "kind": "string",
            "value": _text(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    if kind == 3:
        return {"kind": "integer", "value": reader.read_uleb128()}
    if kind == 4:
        return {
            "kind": "number_bits",
            "low": reader.read_uleb128(),
            "high": reader.read_uleb128(),
        }
    if kind == 0:
        return {"kind": "nil"}
    if kind == 1:
        return {"kind": "boolean", "value": False}
    if kind == 2:
        return {"kind": "boolean", "value": True}
    raise LuaJITParseError("Unknown LuaJIT table constant kind.")


def _read_template_table(reader: _Reader) -> LuaConstant:
    array_count = reader.read_uleb128()
    hash_count = reader.read_uleb128()
    if array_count + hash_count > MAX_CONSTANTS_PER_PROTO:
        raise LuaJITParseError("LuaJIT template table is too large.")
    values = [_read_table_constant(reader) for _ in range(array_count)]
    pairs = [
        (_read_table_constant(reader), _read_table_constant(reader))
        for _ in range(hash_count)
    ]
    digest = hashlib.sha256(repr((values, pairs)).encode("utf-8")).hexdigest()
    return LuaConstant(
        "table",
        {"array_count": array_count, "hash_count": hash_count, "digest": digest},
    )


def _read_debug(
    raw: bytes,
    *,
    instruction_count: int,
    line_count: int,
    upvalue_count: int,
    num_params: int,
    big_endian: bool,
) -> tuple[str, ...]:
    reader = _Reader(raw, big_endian=big_endian)
    line_width = 1 if line_count < 256 else 2 if line_count < 65536 else 4
    line_bytes = instruction_count * line_width
    reader.read_bytes(line_bytes)

    for _ in range(upvalue_count):
        while reader.read_u8() != 0:
            pass

    records: list[tuple[str | None, int, int]] = []
    last_pc = 0
    while reader.remaining:
        first = reader.read_u8()
        if first == 0:
            break
        name: str | None = None
        if first >= 7:
            name_bytes = bytearray([first])
            while True:
                byte = reader.read_u8()
                if byte == 0:
                    break
                if len(name_bytes) >= 1024:
                    raise LuaJITParseError("LuaJIT debug variable name is too long.")
                name_bytes.append(byte)
            name = _text(bytes(name_bytes))
        start_pc = last_pc + reader.read_uleb128()
        end_pc = start_pc + reader.read_uleb128()
        if end_pc < start_pc:
            raise LuaJITParseError("Invalid LuaJIT debug variable range.")
        records.append((name, start_pc, end_pc))
        last_pc = start_pc

    if reader.remaining:
        # LuaJIT may add no bytes after the varinfo terminator. Treat any tail as
        # malformed rather than guessing at a vendor extension.
        raise LuaJITParseError("Unexpected LuaJIT debug-info trailer.")

    active = [name for name, start, end in records if start <= 0 < end]
    names: list[str] = []
    for index in range(num_params):
        candidate = active[index] if index < len(active) else None
        if candidate and candidate.isidentifier():
            names.append(candidate)
        else:
            names.append(f"arg{index + 1}")
    return tuple(names)


def _read_proto(
    raw: bytes,
    *,
    dump_flags: int,
    stack: list[LuaPrototype],
    parse_index: int,
) -> LuaPrototype:
    big_endian = bool(dump_flags & 0x01)
    stripped = bool(dump_flags & 0x02)
    reader = _Reader(raw, big_endian=big_endian)
    flags = reader.read_u8()
    num_params = reader.read_u8()
    frame_size = reader.read_u8()
    upvalue_count = reader.read_u8()
    constant_count = reader.read_uleb128()
    number_count = reader.read_uleb128()
    instruction_count = reader.read_uleb128()
    if constant_count > MAX_CONSTANTS_PER_PROTO:
        raise LuaJITParseError("Too many LuaJIT constants.")
    if instruction_count > MAX_INSTRUCTIONS_PER_PROTO:
        raise LuaJITParseError("Too many LuaJIT instructions.")

    debug_size = 0
    first_line: int | None = None
    line_count: int | None = None
    if not stripped:
        debug_size = reader.read_uleb128()
        if debug_size:
            first_line = reader.read_uleb128()
            line_count = reader.read_uleb128()

    instructions = tuple(reader.read_u32() for _ in range(instruction_count))
    for _ in range(upvalue_count):
        reader.read_u16()

    constants: list[LuaConstant] = []
    for _ in range(constant_count):
        kind = reader.read_uleb128()
        if kind >= 5:
            size = kind - 5
            if size > MAX_STRING_CONSTANT:
                raise LuaJITParseError("LuaJIT string constant is too large.")
            value = reader.read_bytes(size)
            constants.append(LuaConstant("string", value))
        elif kind == 0:
            if not stack:
                raise LuaJITParseError("LuaJIT child prototype stack underflow.")
            constants.append(LuaConstant("child", stack.pop()))
        elif kind == 1:
            constants.append(_read_template_table(reader))
        elif kind in (2, 3):
            constants.append(
                LuaConstant(
                    "integer64_bits",
                    (reader.read_uleb128(), reader.read_uleb128()),
                )
            )
        elif kind == 4:
            constants.append(
                LuaConstant(
                    "complex_bits",
                    tuple(reader.read_uleb128() for _ in range(4)),
                )
            )
        else:
            raise LuaJITParseError("Unknown LuaJIT GC constant kind.")

    for _ in range(number_count):
        _, is_number = reader.read_uleb128_33()
        if is_number:
            reader.read_uleb128()

    parameter_names = tuple(f"arg{index + 1}" for index in range(num_params))
    if debug_size:
        debug_raw = reader.read_bytes(debug_size)
        parameter_names = _read_debug(
            debug_raw,
            instruction_count=instruction_count,
            line_count=int(line_count or 0),
            upvalue_count=upvalue_count,
            num_params=num_params,
            big_endian=big_endian,
        )
    if reader.remaining:
        raise LuaJITParseError("LuaJIT prototype length mismatch.")

    return LuaPrototype(
        parse_index=parse_index,
        flags=flags,
        num_params=num_params,
        frame_size=frame_size,
        upvalue_count=upvalue_count,
        instructions=instructions,
        constants=tuple(constants),
        first_line=first_line,
        line_count=line_count,
        parameter_names=parameter_names,
    )


def parse_luajit_chunk(data: bytes) -> LuaJITChunk:
    """Parse LuaJIT v2 dump metadata without loading or executing the chunk."""
    if not data.startswith(b"\x1bLJ"):
        raise LuaJITParseError(
            "Not a LuaJIT bytecode dump.", code="unsupported_bytecode_format"
        )
    reader = _Reader(data)
    reader.read_bytes(3)
    version = reader.read_u8()
    if version != 2:
        raise LuaJITParseError(
            f"Unsupported LuaJIT bytecode version: {version}",
            code="unsupported_bytecode_version",
        )
    flags = reader.read_uleb128()
    if flags & ~KNOWN_DUMP_FLAGS:
        raise LuaJITParseError(
            "Unsupported LuaJIT bytecode flags.", code="unsupported_bytecode_flags"
        )

    chunk_name_sha256: str | None = None
    chunk_name_is_absolute = False
    if not flags & 0x02:
        name_length = reader.read_uleb128()
        name = reader.read_bytes(name_length)
        chunk_name_sha256 = hashlib.sha256(name).hexdigest()
        decoded = _text(name, maximum=16 * 1024)
        if decoded:
            value = decoded.removeprefix("@")
            chunk_name_is_absolute = value.startswith(("/", "\\")) or (
                len(value) > 2 and value[1] == ":" and value[2] in ("/", "\\")
            )

    stack: list[LuaPrototype] = []
    prototypes: list[LuaPrototype] = []
    while True:
        length = reader.read_uleb128()
        if length == 0:
            break
        if len(prototypes) >= MAX_PROTOTYPES:
            raise LuaJITParseError("Too many LuaJIT prototypes.")
        if length > reader.remaining:
            raise LuaJITParseError("Truncated LuaJIT prototype.")
        proto = _read_proto(
            reader.read_bytes(length),
            dump_flags=flags,
            stack=stack,
            parse_index=len(prototypes),
        )
        prototypes.append(proto)
        stack.append(proto)

    if reader.remaining:
        raise LuaJITParseError("Unexpected LuaJIT chunk trailer.")
    if len(stack) != 1 or not prototypes:
        raise LuaJITParseError("Invalid LuaJIT prototype tree.")
    return LuaJITChunk(
        version=version,
        flags=flags,
        chunk_name_sha256=chunk_name_sha256,
        chunk_name_is_absolute=chunk_name_is_absolute,
        prototypes=tuple(prototypes),
        root=stack[0],
    )


def _constant(proto: LuaPrototype, encoded_index: int) -> LuaConstant | None:
    index = len(proto.constants) - encoded_index - 1
    if 0 <= index < len(proto.constants):
        return proto.constants[index]
    return None


def _constant_text(proto: LuaPrototype, encoded_index: int) -> str | None:
    value = _constant(proto, encoded_index)
    if value is None or value.kind != "string":
        return None
    return _text(value.value)


def infer_opcode_dialect(chunks: list[LuaJITChunk]) -> OpcodeDialect | None:
    """Infer only a small opcode subset from strong typed-constant patterns.

    Aniimo uses structurally valid LuaJIT v2 dumps with a non-stock opcode
    permutation. The inference deliberately requires repeated compiler-shaped
    sequences and never attempts to recover general instruction semantics.
    """
    require_patterns: Counter[tuple[int, int, int]] = Counter()
    closure_patterns: Counter[tuple[int, int]] = Counter()
    for chunk in chunks:
        argument_delta = 2 if chunk.flags & 0x08 else 1
        for proto in chunk.prototypes:
            instructions = proto.instructions
            for index in range(max(0, len(instructions) - 2)):
                first, second, third = instructions[index : index + 3]
                first_a = (first >> 8) & 0xFF
                second_a = (second >> 8) & 0xFF
                third_a = (third >> 8) & 0xFF
                if (
                    _constant_text(proto, (first >> 16) & 0xFFFF) == "require"
                    and _constant_text(proto, (second >> 16) & 0xFFFF)
                    and second_a == first_a + argument_delta
                    and third_a == first_a
                    and ((third >> 16) & 0xFF) >= 2
                ):
                    require_patterns[(first & 0xFF, second & 0xFF, third & 0xFF)] += 1
            for index in range(max(0, len(instructions) - 1)):
                first, second = instructions[index : index + 2]
                child = _constant(proto, (first >> 16) & 0xFFFF)
                key = _constant_text(proto, (second >> 16) & 0xFF)
                if (
                    child is not None
                    and child.kind == "child"
                    and key
                    and ((first >> 8) & 0xFF) == ((second >> 8) & 0xFF)
                ):
                    closure_patterns[(first & 0xFF, second & 0xFF)] += 1

    if not require_patterns or not closure_patterns:
        return None
    require_ops, require_count = require_patterns.most_common(1)[0]
    closure_ops, closure_count = closure_patterns.most_common(1)[0]
    if require_count < 8 or closure_count < 8:
        return None
    if len(require_patterns) > 1:
        second_count = require_patterns.most_common(2)[1][1]
        if second_count * 10 >= require_count:
            return None
    if len(closure_patterns) > 1:
        second_count = closure_patterns.most_common(2)[1][1]
        if second_count * 10 >= closure_count:
            return None

    gget, kstr, call = require_ops
    fnew, tsets = closure_ops
    if len({gget, kstr, call, fnew, tsets}) != 5:
        return None

    tgets_patterns: Counter[int] = Counter()
    for chunk in chunks:
        for proto in chunk.prototypes:
            instructions = proto.instructions
            for index, instruction in enumerate(instructions):
                if instruction & 0xFF != gget:
                    continue
                if _constant_text(proto, (instruction >> 16) & 0xFFFF) != "CS":
                    continue
                register = (instruction >> 8) & 0xFF
                for following in instructions[index + 1 : index + 9]:
                    key = _constant_text(proto, (following >> 16) & 0xFF)
                    if ((following >> 24) & 0xFF) != register or not key:
                        break
                    tgets_patterns[following & 0xFF] += 1
                    register = (following >> 8) & 0xFF
    tgets: int | None = None
    if tgets_patterns:
        candidate, candidate_count = tgets_patterns.most_common(1)[0]
        if candidate_count >= 4:
            tgets = candidate

    return OpcodeDialect(
        gget=gget,
        kstr=kstr,
        call=call,
        fnew=fnew,
        tsets=tsets,
        tgets=tgets,
        evidence={
            "closure_pattern_count": closure_count,
            "require_pattern_count": require_count,
            "sampled_chunk_count": len(chunks),
            "tgets_pattern_count": tgets_patterns.get(tgets, 0)
            if tgets is not None
            else 0,
        },
    )


def analyze_luajit_chunk(
    chunk: LuaJITChunk, dialect: OpcodeDialect | None = None
) -> dict[str, Any]:
    """Recover conservative symbols, require edges and xLua CS references."""
    dependencies: set[str] = set()
    binding_kinds: dict[str, str] = {}

    if dialect is not None:
        argument_delta = 2 if chunk.flags & 0x08 else 1
        for proto in chunk.prototypes:
            instructions = proto.instructions
            for index in range(max(0, len(instructions) - 2)):
                first, second, third = instructions[index : index + 3]
                if (
                    first & 0xFF == dialect.gget
                    and second & 0xFF == dialect.kstr
                    and third & 0xFF == dialect.call
                    and _constant_text(proto, (first >> 16) & 0xFFFF) == "require"
                    and ((second >> 8) & 0xFF) == ((first >> 8) & 0xFF) + argument_delta
                    and ((third >> 8) & 0xFF) == ((first >> 8) & 0xFF)
                ):
                    dependency = _constant_text(proto, (second >> 16) & 0xFFFF)
                    if dependency:
                        dependencies.add(dependency)
            for index in range(max(0, len(instructions) - 1)):
                first, second = instructions[index : index + 2]
                if first & 0xFF != dialect.fnew or second & 0xFF != dialect.tsets:
                    continue
                child = _constant(proto, (first >> 16) & 0xFFFF)
                name = _constant_text(proto, (second >> 16) & 0xFF)
                if (
                    child is not None
                    and child.kind == "child"
                    and name
                    and ((first >> 8) & 0xFF) == ((second >> 8) & 0xFF)
                ):
                    child.value.aliases.add(name)
            if dialect.tgets is not None:
                for index, instruction in enumerate(instructions):
                    if instruction & 0xFF != dialect.gget:
                        continue
                    if _constant_text(proto, (instruction >> 16) & 0xFFFF) != "CS":
                        continue
                    register = (instruction >> 8) & 0xFF
                    path = "CS"
                    for following in instructions[index + 1 : index + 17]:
                        opcode = following & 0xFF
                        if (
                            opcode == dialect.call
                            and ((following >> 8) & 0xFF) == register
                        ):
                            if path != "CS":
                                binding_kinds[path] = "callable_reference"
                            break
                        if (
                            opcode != dialect.tgets
                            or ((following >> 24) & 0xFF) != register
                        ):
                            break
                        key = _constant_text(proto, (following >> 16) & 0xFF)
                        if not key:
                            break
                        path = f"{path}.{key}"
                        binding_kinds.setdefault(path, "type_or_member_reference")
                        register = (following >> 8) & 0xFF

    prototype_rows: list[dict[str, Any]] = []
    for proto in chunk.prototypes:
        names = sorted(proto.aliases)
        prototype_rows.append(
            {
                "aliases": names,
                "first_line": proto.first_line,
                "frame_size": proto.frame_size,
                "is_vararg": proto.is_vararg,
                "line_count": proto.line_count,
                "num_params": proto.num_params,
                "parameter_names": list(proto.parameter_names),
                "parse_index": proto.parse_index,
                "prototype_name": names[0] if names else None,
                "upvalue_count": proto.upvalue_count,
            }
        )
    return {
        "bindings": [
            {"lua_path": path, "binding_role": binding_kinds[path]}
            for path in sorted(binding_kinds)
        ],
        "dependencies": sorted(dependencies),
        "instruction_semantics": (
            {
                "evidence": dialect.evidence,
                "mapping": {
                    "CALL": dialect.call,
                    "FNEW": dialect.fnew,
                    "GGET": dialect.gget,
                    "KSTR": dialect.kstr,
                    "TGETS": dialect.tgets,
                    "TSETS": dialect.tsets,
                },
                "status": "inferred_bounded_subset",
            }
            if dialect is not None
            else {"status": "unsupported_opcode_dialect"}
        ),
        "prototypes": prototype_rows,
    }
