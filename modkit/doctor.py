from __future__ import annotations

import importlib
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .config import LoadedYaml
from .errors import ConfigurationError, ValidationError
from .util import atomic_write_json, digest_json, read_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def quick_preflight(
    role: str,
    roots: dict[str, tuple[Path, bool]],
    *,
    require_inputs_read_only: bool = False,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for name, (path, writable) in roots.items():
        if writable:
            try:
                path.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise ValidationError(
                    f"Point de montage non créable {name}: {exc}",
                    error_code="mount_unavailable",
                ) from exc
            if not os.access(path, os.W_OK):
                raise ValidationError(
                    f"Point de montage non inscriptible : {name}",
                    error_code="mount_not_writable",
                )
        elif not path.exists():
            raise ValidationError(
                f"Point de montage absent : {name}", error_code="mount_missing"
            )
        usage = shutil.disk_usage(path)
        checks.append(
            {
                "free_bytes": usage.free,
                "name": name,
                "required_writable": writable,
                "status": "passed",
            }
        )
    if role == "analyzer" and require_inputs_read_only:
        from .analyzer import assert_inputs_read_only

        assert_inputs_read_only(roots["inputs"][0])
        checks.append(
            {"name": "input_snapshot_boundary", "status": "passed", "read_only": True}
        )
    return {"checks": checks, "role": role, "schema_version": 1, "status": "passed"}


def stable_doctor(
    *,
    role: str,
    profile: LoadedYaml,
    tools_lock: dict[str, Any],
    cache_root: Path | None,
    refresh: bool,
) -> tuple[dict[str, Any], str]:
    key_basis = {
        "image_digests": tools_lock.get("image_digests"),
        "runtime_image_digest": os.environ.get("MODKIT_IMAGE_DIGEST", "unresolved"),
        "profile_sha256": profile.sha256,
        "role": role,
        "tools_lock_sha256": digest_json(tools_lock),
    }
    cache_key = digest_json(key_basis)
    cache_path = (
        cache_root / "doctor" / f"{cache_key}.json" if cache_root is not None else None
    )
    if not refresh and cache_path is not None and cache_path.is_file():
        result = read_json(cache_path)
        result["served_from_cache"] = True
        return result, "hit"

    checks: list[dict[str, Any]] = [
        {"name": "python", "status": "passed", "version": sys.version.split()[0]},
        {"name": "pyyaml", "status": "passed", "version": yaml.__version__},
    ]
    for module in ("modkit.capture", "modkit.analyzer", "modkit.registry"):
        importlib.import_module(module)
        checks.append({"name": f"adapter:{module}", "status": "passed"})
    require_tools = os.environ.get("MODKIT_REQUIRE_TOOL_PRESENCE") == "1"
    for tool in tools_lock.get("tools", []):
        executable = tool.get("executable")
        if not executable:
            checks.append(
                {
                    "name": str(tool.get("name", "unknown")),
                    "status": "not_checked",
                    "reason": "no_executable_contract",
                }
            )
            continue
        required_for = tool.get("required_for")
        if required_for and required_for != role:
            checks.append(
                {
                    "name": str(tool.get("name", executable)),
                    "status": "not_applicable",
                    "reason": f"required_for_{required_for}",
                }
            )
            continue
        resolved = shutil.which(str(executable))
        check: dict[str, Any] = {
            "name": str(tool.get("name", executable)),
            "path_kind": "command",
            "status": "failed",
        }
        if resolved:
            probe_args = [str(value) for value in tool.get("probe_args", [])]
            try:
                probe = subprocess.run(
                    [resolved, *probe_args],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                output = (probe.stdout + "\n" + probe.stderr).strip()
                expected = str(tool.get("version_pattern", ""))
                accepted = [int(value) for value in tool.get("probe_exit_codes", [0])]
                check.update(
                    {
                        "exit_code": probe.returncode,
                        "status": "passed"
                        if probe.returncode in accepted
                        and (not expected or expected in output)
                        else "failed",
                        "version_pattern": expected or None,
                    }
                )
            except (OSError, subprocess.SubprocessError) as exc:
                check["reason"] = type(exc).__name__
        else:
            check["reason"] = "command_not_found"
        checks.append(check)
        if (
            check["status"] != "passed"
            and required_for == role
            and (require_tools or tools_lock.get("lock_status") == "resolved")
        ):
            raise ConfigurationError(
                f"Outil verrouillé absent ou incompatible : {executable}",
                error_code="missing_locked_tool",
            )
    result = {
        "analysis_ready": tools_lock.get("lock_status") == "resolved",
        "cache_key": cache_key,
        "checks": checks,
        "infrastructure_ready": True,
        "lock_status": tools_lock.get("lock_status"),
        "performed_at": _utc_now(),
        "role": role,
        "schema_version": 1,
        "served_from_cache": False,
        "status": "passed"
        if all(item["status"] != "failed" for item in checks)
        else "degraded",
    }
    if cache_path is not None:
        atomic_write_json(cache_path, result)
    return result, "miss"
