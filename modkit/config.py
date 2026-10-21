from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigurationError
from .util import sha256_file


@dataclass(frozen=True)
class LoadedYaml:
    path: Path
    data: dict[str, Any]
    sha256: str


def load_yaml(path: Path) -> LoadedYaml:
    if not path.is_file():
        raise ConfigurationError(
            f"Configuration absente : {path}", error_code="missing_configuration"
        )
    try:
        parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ConfigurationError(
            f"Configuration YAML invalide ({path.name}) : {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise ConfigurationError(f"La racine YAML doit être un objet : {path}")
    digest, _ = sha256_file(path)
    return LoadedYaml(path=path, data=parsed, sha256=digest)


def validate_input_profile(profile: LoadedYaml) -> None:
    data = profile.data
    if not isinstance(data.get("selection_id"), str):
        raise ConfigurationError("selection_id absent du profil d'entrées.")
    feature_sets = data.get("feature_sets", {})
    defaults = (
        feature_sets.get("default_enabled") if isinstance(feature_sets, dict) else None
    )
    if not isinstance(defaults, list) or not all(
        isinstance(item, str) for item in defaults
    ):
        raise ConfigurationError("feature_sets.default_enabled doit être une liste.")
    rule_ids: set[str] = set()
    for section in ("payload_rules", "external_payload_rules", "inventory_rules"):
        rules = data.get(section, [])
        if not isinstance(rules, list):
            raise ConfigurationError(f"{section} doit être une liste.")
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
                raise ConfigurationError(f"Règle invalide dans {section}.")
            rule_id = rule["id"]
            if rule_id in rule_ids:
                raise ConfigurationError(f"Identifiant de règle dupliqué : {rule_id}")
            rule_ids.add(rule_id)


def enabled_features(
    profile: LoadedYaml, disabled: set[str] | None = None
) -> list[str]:
    validate_input_profile(profile)
    disabled = disabled or set()
    defaults = list(profile.data["feature_sets"]["default_enabled"])
    unknown = disabled.difference(
        profile.data["feature_sets"].get("available", {}).keys()
    )
    if unknown:
        raise ConfigurationError(f"Feature inconnue : {', '.join(sorted(unknown))}")
    return [feature for feature in defaults if feature not in disabled]


def public_profile_copy(profile: LoadedYaml) -> dict[str, Any]:
    """Return a path-neutral profile representation suitable for identities."""
    value = copy.deepcopy(profile.data)
    source = value.get("source")
    if isinstance(source, dict):
        source.pop("game_root", None)
        source.pop("steam_manifest", None)
    destination = value.get("destination")
    if isinstance(destination, dict):
        for key in ("root", "object_root", "snapshot_root", "current_pointer"):
            destination.pop(key, None)
    return value
