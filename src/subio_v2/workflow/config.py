from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

import json5
import toml
import yaml

from subio_v2.core.errors import ConfigError
from subio_v2.rules.config import RuleSetConfig
from subio_v2.workflow.selectors import SelectorSpec


def _freeze_mapping(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    return MappingProxyType(dict(value or {}))


@dataclass(frozen=True)
class FilterConfig:
    include: str | None = None
    exclude: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> FilterConfig | None:
        if value is None:
            return None
        return cls(include=value.get("include"), exclude=value.get("exclude"))


@dataclass(frozen=True)
class RenameRule:
    old: str
    new: str


@dataclass(frozen=True)
class RenameConfig:
    add_prefix: str = ""
    suffix: str = ""
    replace: tuple[RenameRule, ...] = ()

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> RenameConfig | None:
        if value is None:
            return None
        return cls(
            add_prefix=value.get("add_prefix", ""),
            suffix=value.get("suffix", ""),
            replace=tuple(
                RenameRule(item["old"], item["new"])
                for item in value.get("replace", ())
            ),
        )


@dataclass(frozen=True)
class UploadConfig:
    target: str
    file_name: str | None = None


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    provider_type: str
    url: str | None = None
    file: str | None = None
    user_agent: str | None = None
    age_secret_key: str | None = None
    allow_unsafe_external: bool = False
    filters: FilterConfig | None = None
    rename: RenameConfig | None = None
    dialer_proxy: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ProviderConfig:
        return cls(
            name=value["name"],
            provider_type=value["type"],
            url=value.get("url"),
            file=value.get("file"),
            user_agent=value.get("user_agent"),
            age_secret_key=value.get("age_secret_key"),
            allow_unsafe_external=value.get("allow_unsafe_external", False),
            filters=FilterConfig.from_mapping(value.get("filters")),
            rename=RenameConfig.from_mapping(value.get("rename")),
            dialer_proxy=value.get("dialer_proxy"),
        )


@dataclass(frozen=True)
class ArtifactConfig:
    name: str
    artifact_type: str
    template: str | None = None
    providers: tuple[str, ...] = ()
    users: tuple[str, ...] = ()
    user: str | None = None
    options: Mapping[str, Any] = MappingProxyType({})
    allow_conversion_errors: bool = False
    allow_empty: bool = False
    age_public_key: str | None = None
    upload: tuple[UploadConfig, ...] = ()
    selector: str | None = None
    on_duplicate_name: str = "error"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ArtifactConfig:
        return cls(
            name=value["name"],
            artifact_type=value["type"],
            template=value.get("template"),
            providers=tuple(value.get("providers", ())),
            users=tuple(value.get("users", ())),
            user=value.get("user"),
            options=_freeze_mapping(value.get("options")),
            allow_conversion_errors=value.get("allow_conversion_errors", False),
            allow_empty=value.get("allow_empty", False),
            age_public_key=value.get("age_public_key"),
            upload=tuple(
                UploadConfig(
                    target=item["to"],
                    file_name=item.get("file_name"),
                )
                for item in value.get("upload", ())
            ),
            selector=value.get("selector"),
            on_duplicate_name=value.get("on_duplicate_name", "error"),
        )


@dataclass(frozen=True)
class UploaderConfig:
    name: str
    uploader_type: str
    id: str | None = None
    token: str = ""
    clean: bool = False

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> UploaderConfig:
        return cls(
            name=value["name"],
            uploader_type=value["type"],
            id=value.get("id"),
            token=value.get("token", ""),
            clean=value.get("clean", False),
        )


@dataclass(frozen=True)
class RemoteCacheConfig:
    enabled: bool = False
    ttl_seconds: int = 21600
    stale_if_error: bool = False


@dataclass(frozen=True)
class RemoteConfig:
    timeout_seconds: int = 10
    max_bytes: int = 16 * 1024 * 1024
    cache: RemoteCacheConfig = RemoteCacheConfig()


@dataclass(frozen=True)
class RunConfig:
    providers: tuple[ProviderConfig, ...]
    artifacts: tuple[ArtifactConfig, ...]
    uploaders: tuple[UploaderConfig, ...]
    rulesets: tuple[RuleSetConfig, ...]
    selectors: Mapping[str, SelectorSpec]
    remote: RemoteConfig
    options: Mapping[str, Any]
    filters: FilterConfig | None
    allow_conversion_errors: bool
    age_secret_key: str
    age_public_key: str
    log_level: str | None
    extra: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> RunConfig:
        copied = dict(data)
        remote_value = copied.get("remote") or {}
        cache_value = remote_value.get("cache") or {}
        known = {
            "provider",
            "artifact",
            "uploader",
            "ruleset",
            "selectors",
            "remote",
            "options",
            "filters",
            "allow_conversion_errors",
            "age_secret_key",
            "age_public_key",
            "log_level",
        }
        return cls(
            providers=tuple(
                ProviderConfig.from_mapping(item)
                for item in copied.get("provider", ())
            ),
            artifacts=tuple(
                ArtifactConfig.from_mapping(item)
                for item in copied.get("artifact", ())
            ),
            uploaders=tuple(
                UploaderConfig.from_mapping(item)
                for item in copied.get("uploader", ())
            ),
            rulesets=tuple(
                RuleSetConfig(
                    name=item["name"],
                    url=item["url"],
                    dialect=item.get("type", "mihomo"),
                    behavior=item.get("behavior", "classical"),
                    format=item.get("format", "text"),
                    user_agent=item.get("user_agent"),
                )
                for item in copied.get("ruleset", ())
            ),
            selectors=MappingProxyType(
                {
                    name: SelectorSpec.from_mapping(value)
                    for name, value in copied.get("selectors", {}).items()
                }
            ),
            remote=RemoteConfig(
                timeout_seconds=remote_value.get("timeout_seconds", 10),
                max_bytes=remote_value.get("max_bytes", 16 * 1024 * 1024),
                cache=RemoteCacheConfig(
                    enabled=cache_value.get("enabled", False),
                    ttl_seconds=cache_value.get("ttl_seconds", 21600),
                    stale_if_error=cache_value.get("stale_if_error", False),
                ),
            ),
            options=_freeze_mapping(copied.get("options")),
            filters=FilterConfig.from_mapping(copied.get("filters")),
            allow_conversion_errors=bool(
                copied.get("allow_conversion_errors", False)
            ),
            age_secret_key=str(copied.get("age_secret_key", "")),
            age_public_key=str(copied.get("age_public_key", "")),
            log_level=copied.get("log_level"),
            extra=_freeze_mapping(
                {key: value for key, value in copied.items() if key not in known}
            ),
        )


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
        from subio_v2.workflow.config_validation import ConfigValidator

        ConfigValidator.validate(data)
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
