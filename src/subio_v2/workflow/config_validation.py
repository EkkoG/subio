import re
from collections.abc import Mapping
from typing import Any

from subio_v2.core.errors import ConfigError
from subio_v2.adapters.catalog import resolve_format
from subio_v2.infrastructure.logging import logger


class ConfigValidator:
    @classmethod
    def validate(cls, config: Mapping[str, Any]) -> None:
        if not isinstance(config, Mapping):
            raise ConfigError("Config root must be an object")
        if not isinstance(config.get("allow_conversion_errors", False), bool):
            raise ConfigError("'allow_conversion_errors' must be a boolean")
        cls._validate_options(config.get("options"), "Config options")
        cls._validate_filters(config.get("filters"), "Config filters")

        rulesets = config.get("ruleset", [])
        if not isinstance(rulesets, list):
            raise ConfigError("Config section 'ruleset' must be a list")
        for entry in rulesets:
            if not isinstance(entry, dict):
                raise ConfigError("Entries in 'ruleset' must be objects")
            name = entry.get("name")
            if not isinstance(name, str) or not name:
                raise ConfigError("Every 'ruleset' entry must have a name")
            url = entry.get("url")
            if not isinstance(url, str) or not url:
                raise ConfigError(f"Ruleset '{name}' must define a URL")
            for key in ("type", "behavior", "format", "user_agent"):
                value = entry.get(key)
                if value is not None and not isinstance(value, str):
                    raise ConfigError(f"Ruleset '{name}' {key} must be a string")

        for section in ("provider", "artifact", "uploader"):
            entries = config.get(section, [])
            if not isinstance(entries, list):
                raise ConfigError(f"Config section '{section}' must be a list")
            name_positions: dict[str, int] = {}
            artifact_outputs: dict[str, tuple[int, str | None]] = {}
            for position, entry in enumerate(entries, start=1):
                if not isinstance(entry, dict):
                    raise ConfigError(f"Entries in '{section}' must be objects")
                name = entry.get("name")
                if not isinstance(name, str) or not name:
                    raise ConfigError(f"Every '{section}' entry must have a name")
                if section != "artifact":
                    cls._record_unique_name(section, name, position, name_positions)
                if section == "provider":
                    cls._validate_provider(entry, name)
                elif section == "artifact":
                    cls._validate_artifact(
                        entry, name, position, artifact_outputs
                    )
                else:
                    cls._validate_uploader(entry, name)

        cls._validate_references(config)

    @staticmethod
    def warn_platform_replacements(config: Mapping[str, Any]) -> None:
        if hasattr(config, "providers") and hasattr(config, "artifacts"):
            entries = [
                ("Provider", item.name, item.provider_type)
                for item in config.providers
            ] + [
                ("Artifact", item.name, item.artifact_type)
                for item in config.artifacts
            ]
        else:
            entries = [
                (section.title(), entry["name"], entry.get("type"))
                for section in ("provider", "artifact")
                for entry in config.get(section, [])
            ]

        for section, name, platform in entries:
            resolution = (
                resolve_format(platform) if isinstance(platform, str) else None
            )
            if resolution is None:
                continue
            if resolution.deprecated:
                logger.warning(
                    f"{section} {name!r} uses deprecated platform type {platform!r}; "
                    f"use {resolution.replacement!r} for modern Mihomo configurations"
                )
            elif resolution.alias:
                logger.warning(
                    f"{section} {name!r} uses platform type alias {platform!r}; "
                    f"use {resolution.replacement!r} instead"
                )

    @staticmethod
    def _record_unique_name(
        section: str, name: str, position: int, positions: dict[str, int]
    ) -> None:
        first_position = positions.get(name)
        if first_position is not None:
            raise ConfigError(
                f"Duplicate {section} name {name!r}: {section} entry "
                f"#{position} duplicates {section} entry #{first_position}"
            )
        positions[name] = position

    @classmethod
    def _validate_provider(cls, entry: dict[str, Any], name: str) -> None:
        provider_type = entry.get("type")
        if not isinstance(provider_type, str) or not provider_type:
            raise ConfigError(f"Provider '{name}' type must be a non-empty string")
        has_url = "url" in entry
        has_file = "file" in entry
        if has_url == has_file:
            raise ConfigError(
                f"Provider '{name}' must define exactly one of 'url' or 'file'"
            )
        allow_unsafe_external = entry.get("allow_unsafe_external", False)
        if not isinstance(allow_unsafe_external, bool):
            raise ConfigError(
                f"Provider '{name}' allow_unsafe_external must be a boolean"
            )
        if allow_unsafe_external and entry.get("type") != "surge":
            raise ConfigError(
                f"Provider '{name}' can only enable allow_unsafe_external "
                "when type is 'surge'"
            )
        if allow_unsafe_external and not has_url:
            raise ConfigError(
                f"Provider '{name}' can only enable allow_unsafe_external "
                "for a remote URL source"
            )
        cls._validate_filters(entry.get("filters"), f"Provider '{name}' filters")
        cls._validate_rename(entry.get("rename"), f"Provider '{name}' rename")

    @classmethod
    def _validate_artifact(
        cls,
        entry: dict[str, Any],
        name: str,
        position: int,
        outputs: dict[str, tuple[int, str | None]],
    ) -> None:
        artifact_type = entry.get("type")
        if not isinstance(artifact_type, str) or not artifact_type:
            raise ConfigError(f"Artifact '{name}' type must be a non-empty string")
        template = entry.get("template")
        if template is not None and not isinstance(template, str):
            raise ConfigError(f"Artifact '{name}' template must be a string")
        for key in ("allow_conversion_errors", "allow_empty"):
            if not isinstance(entry.get(key, False), bool):
                raise ConfigError(f"Artifact '{name}' {key} must be a boolean")
        providers = entry.get("providers", [])
        if not isinstance(providers, list) or any(
            not isinstance(provider, str) or not provider for provider in providers
        ):
            raise ConfigError(f"Artifact '{name}' providers must be a list of names")
        cls._validate_options(entry.get("options"), f"Artifact '{name}' options")
        cls._validate_artifact_users(entry, name)
        users = entry.get("users", [])
        if users and "{user}" not in name:
            raise ConfigError(
                f"Artifact entry #{position} {name!r} defines users, "
                "so its name must contain '{user}'"
            )
        usernames = users or (
            [entry["user"]] if entry.get("user") is not None else [None]
        )
        for username in usernames:
            output_name = (
                name.replace("{user}", username) if username is not None else name
            )
            previous = outputs.get(output_name)
            if previous is not None:
                first_position, first_user = previous
                current = f"artifact entry #{position}"
                first = f"artifact entry #{first_position}"
                if username is not None:
                    current += f" (user {username!r})"
                if first_user is not None:
                    first += f" (user {first_user!r})"
                if username is None and first_user is None:
                    raise ConfigError(
                        f"Duplicate artifact name {output_name!r}: artifact entry "
                        f"#{position} duplicates artifact entry #{first_position}"
                    )
                raise ConfigError(
                    f"Duplicate artifact output name {output_name!r}: "
                    f"{current} duplicates {first}"
                )
            outputs[output_name] = (position, username)
        cls._validate_artifact_uploads(entry.get("upload"), name)

    @staticmethod
    def _validate_uploader(entry: dict[str, Any], name: str) -> None:
        uploader_type = entry.get("type")
        if not isinstance(uploader_type, str) or not uploader_type:
            raise ConfigError(f"Uploader '{name}' type must be a non-empty string")
        if uploader_type == "gist" and (
            not isinstance(entry.get("id"), str) or not entry["id"]
        ):
            raise ConfigError(f"Uploader '{name}' id must be a non-empty string")
        if not isinstance(entry.get("token", ""), str):
            raise ConfigError(f"Uploader '{name}' token must be a string")
        if not isinstance(entry.get("clean", False), bool):
            raise ConfigError(f"Uploader '{name}' clean must be a boolean")

    @staticmethod
    def _validate_rename(value: Any, label: str) -> None:
        if value is None:
            return
        if not isinstance(value, dict):
            raise ConfigError(f"{label} must be an object")
        for key in ("add_prefix", "suffix"):
            item = value.get(key, "")
            if not isinstance(item, str):
                raise ConfigError(f"{label} {key} must be a string")
        replacements = value.get("replace", [])
        if not isinstance(replacements, list):
            raise ConfigError(f"{label} replace must be a list")
        for item in replacements:
            if not isinstance(item, dict):
                raise ConfigError(f"{label} replace entries must be objects")
            if not isinstance(item.get("old"), str) or not isinstance(
                item.get("new"), str
            ):
                raise ConfigError(f"{label} replace entries need string old/new")

    @staticmethod
    def _validate_references(config: Mapping[str, Any]) -> None:
        provider_names = {item["name"] for item in config.get("provider", [])}
        uploader_names = {item["name"] for item in config.get("uploader", [])}
        for artifact in config.get("artifact", []):
            missing = [
                name
                for name in artifact.get("providers", [])
                if name not in provider_names
            ]
            if missing:
                raise ConfigError(
                    f"Artifact '{artifact['name']}' references missing provider(s): "
                    f"{', '.join(missing)}"
                )
            missing_uploaders = [
                item["to"]
                for item in artifact.get("upload", [])
                if item["to"] not in uploader_names
            ]
            if missing_uploaders:
                raise ConfigError(
                    f"Artifact '{artifact['name']}' references missing uploader(s): "
                    f"{', '.join(missing_uploaders)}"
                )

    @staticmethod
    def _validate_options(value: Any, label: str) -> None:
        if value is not None and not isinstance(value, dict):
            raise ConfigError(f"{label} must be an object")

    @staticmethod
    def _validate_filters(value: Any, label: str) -> None:
        if value is None:
            return
        if not isinstance(value, dict):
            raise ConfigError(f"{label} must be an object")
        for key in ("include", "exclude"):
            pattern = value.get(key)
            if pattern is not None and not isinstance(pattern, str):
                raise ConfigError(f"{label} {key} must be a string")
            if pattern:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ConfigError(f"{label} {key} is not a valid regex") from exc

    @staticmethod
    def _validate_artifact_users(entry: dict[str, Any], name: str) -> None:
        user = entry.get("user")
        users = entry.get("users", [])
        if user is not None and (not isinstance(user, str) or not user):
            raise ConfigError(f"Artifact '{name}' user must be a non-empty string")
        if not isinstance(users, list) or any(
            not isinstance(item, str) or not item for item in users
        ):
            raise ConfigError(f"Artifact '{name}' users must be a list of names")
        if user is not None and users:
            raise ConfigError(f"Artifact '{name}' cannot define both user and users")

    @staticmethod
    def _validate_artifact_uploads(value: Any, name: str) -> None:
        if value is None:
            return
        if not isinstance(value, list):
            raise ConfigError(f"Artifact '{name}' upload must be a list")
        for item in value:
            if not isinstance(item, dict):
                raise ConfigError(f"Artifact '{name}' upload entries must be objects")
            target = item.get("to")
            if not isinstance(target, str) or not target:
                raise ConfigError(
                    f"Artifact '{name}' upload target must be a non-empty string"
                )
            file_name = item.get("file_name")
            if file_name is not None and (
                not isinstance(file_name, str) or not file_name
            ):
                raise ConfigError(
                    f"Artifact '{name}' upload file_name must be a non-empty string"
                )
