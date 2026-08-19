from __future__ import annotations

import json
import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

import json5
import toml
import yaml

from subio_v2.workflow.errors import ConfigError


@dataclass(frozen=True)
class RunConfig(Mapping[str, Any]):
    data: Mapping[str, Any]
    providers: tuple[Mapping[str, Any], ...]
    artifacts: tuple[Mapping[str, Any], ...]
    uploaders: tuple[Mapping[str, Any], ...]
    rulesets: tuple[Mapping[str, Any], ...]
    options: Mapping[str, Any]
    filters: Mapping[str, Any]
    allow_conversion_errors: bool
    age_secret_key: str
    age_public_key: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> RunConfig:
        copied = dict(data)
        return cls(
            data=MappingProxyType(copied),
            providers=tuple(copied.get("provider", ())),
            artifacts=tuple(copied.get("artifact", ())),
            uploaders=tuple(copied.get("uploader", ())),
            rulesets=tuple(copied.get("ruleset", ())),
            options=MappingProxyType(dict(copied.get("options", {}))),
            filters=MappingProxyType(dict(copied.get("filters", {}))),
            allow_conversion_errors=bool(
                copied.get("allow_conversion_errors", False)
            ),
            age_secret_key=str(copied.get("age_secret_key", "")),
            age_public_key=str(copied.get("age_public_key", "")),
        )

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.data)

    def __len__(self) -> int:
        return len(self.data)


class ConfigLoader:
    @staticmethod
    def load(path: str) -> RunConfig:
        try:
            with open(path, "r", encoding="utf-8") as file:
                content = file.read()
        except FileNotFoundError as exc:
            raise ConfigError(f"Config file not found: {path}") from exc
        except Exception as exc:
            raise ConfigError(f"Error reading config file: {exc}") from exc

        extension = os.path.splitext(path)[1].lower()
        try:
            if extension == ".toml":
                data = toml.loads(content)
            elif extension in (".yaml", ".yml"):
                data = yaml.safe_load(content)
            elif extension == ".json":
                data = json.loads(content)
            elif extension == ".json5":
                data = json5.loads(content)
            else:
                data = ConfigLoader._parse_auto(content)
        except ConfigError:
            raise
        except Exception as exc:
            raise ConfigError(f"Error parsing config ({extension}): {exc}") from exc

        if not isinstance(data, dict):
            raise ConfigError("Config root must be an object")
        return RunConfig.from_mapping(data)

    @staticmethod
    def _parse_auto(content: str) -> dict[str, Any]:
        parsers = (
            (toml.loads, (toml.TomlDecodeError,)),
            (json.loads, (json.JSONDecodeError,)),
            (json5.loads, (ValueError,)),
            (yaml.safe_load, (yaml.YAMLError,)),
        )
        for parser, errors in parsers:
            try:
                data = parser(content)
            except errors:
                continue
            if isinstance(data, dict):
                return data
        raise ConfigError("Unknown config format (tried toml, json, json5, yaml)")
