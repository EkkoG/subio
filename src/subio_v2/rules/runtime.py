"""Load shareable rulesets and expose data-only template callables."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from subio_v2.adapters.catalog import normalize_format
from subio_v2.core.dialect import DialectContext
from subio_v2.core.errors import ConfigError
from subio_v2.core.results import ConversionIssue
from subio_v2.core.rule_model import (
    BoundRule,
    DefaultParameter,
    HeadlessRuleSet,
    LiteralPolicy,
    ParameterizedRuleSet,
    ParameterReference,
    RuleComment,
    RuleRenderResult,
)
from subio_v2.infrastructure.logging import logger
from subio_v2.infrastructure.remote import (
    RemoteLoadError,
    RemoteMetadata,
    RunRemoteLoader,
)
from subio_v2.rules.codecs import (
    DEFAULT_RULESET_CODEC_REGISTRY,
    RuleSetInputCodecCatalog,
    RuleSetInputSelection,
)
from subio_v2.rules.config import RuleSetConfig
from subio_v2.rules.output import get_rule_output_dialect
from subio_v2.rules.parser import (
    MIHOMO_CLASSICAL_PARSER,
    parse_argument_names,
    validate_identifier,
)


@dataclass
class RuleIssueCollector:
    issues: list[ConversionIssue] = field(default_factory=list)
    _seen: set[ConversionIssue] = field(default_factory=set, init=False, repr=False)

    def add(self, issue: ConversionIssue) -> None:
        if issue not in self._seen:
            self._seen.add(issue)
            self.issues.append(issue)

    def extend(self, issues: tuple[ConversionIssue, ...] | list[ConversionIssue]) -> None:
        for issue in issues:
            self.add(issue)


class RuleSetRenderer:
    def render(
        self,
        ruleset: ParameterizedRuleSet,
        platform: str,
        arguments: Mapping[str, Any],
    ) -> RuleRenderResult:
        platform = normalize_format(platform)
        output_dialect = get_rule_output_dialect(platform)
        if output_dialect is None:
            raise ValueError(f"Unknown ruleset target platform: {platform}")
        issues = [replace(issue, target=output_dialect.name) for issue in ruleset.issues]
        lines: list[str] = []

        for entry in ruleset.entries:
            if isinstance(entry, RuleComment):
                lines.append(entry.content)
                continue

            policy = self._resolve_policy(entry, ruleset, arguments)
            rendered, expression_issues = output_dialect.render(
                source=ruleset.name,
                expression=entry.expression,
                source_context=ruleset.source_context,
                policy=policy,
            )
            issues.extend(expression_issues)
            if rendered is not None:
                lines.append(rendered)

        return RuleRenderResult(content="\n".join(lines), issues=tuple(issues))

    def _resolve_policy(
        self,
        entry: BoundRule,
        ruleset: ParameterizedRuleSet,
        arguments: Mapping[str, Any],
    ) -> str:
        binding = entry.policy_binding
        if isinstance(binding, DefaultParameter):
            return str(arguments[ruleset.parameters[0]])
        if isinstance(binding, ParameterReference):
            return str(arguments[binding.name])
        if isinstance(binding, LiteralPolicy):
            return binding.value
        raise TypeError(f"Unsupported policy binding: {type(binding).__name__}")


RULESET_RENDERER = RuleSetRenderer()


class RuleSet:
    """Runtime facade for a parameterized, data-only ruleset."""

    def __init__(self, model: ParameterizedRuleSet):
        validate_identifier(model.name, "name")
        if not model.parameters:
            raise ValueError("Ruleset must declare at least one argument")
        for name in model.parameters:
            validate_identifier(name, "argument")
        self.model = model

    @property
    def name(self) -> str:
        return self.model.name

    @property
    def argument_names(self) -> tuple[str, ...]:
        return self.model.parameters

    def _bind_arguments(
        self, values: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> dict[str, Any]:
        names = self.argument_names
        if len(values) > len(names):
            raise TypeError(
                f"Ruleset {self.name!r} expected at most {len(names)} argument(s), "
                f"got {len(values)}"
            )

        bound = dict(zip(names, values))
        for name, value in kwargs.items():
            if name not in names:
                raise TypeError(
                    f"Ruleset {self.name!r} got an unexpected argument {name!r}"
                )
            if name in bound:
                raise TypeError(
                    f"Ruleset {self.name!r} got multiple values for argument {name!r}"
                )
            bound[name] = value

        missing = [name for name in names if name not in bound]
        if missing:
            raise TypeError(
                f"Ruleset {self.name!r} missing required argument(s): "
                f"{', '.join(missing)}"
            )
        return bound

    def render_result(
        self, platform: str, *values: Any, **kwargs: Any
    ) -> RuleRenderResult:
        arguments = self._bind_arguments(values, kwargs)
        return RULESET_RENDERER.render(self.model, platform, arguments)

    def render(self, platform: str, *values: Any, **kwargs: Any) -> str:
        return self.render_result(platform, *values, **kwargs).content

    def as_callable(
        self, platform: str, collector: RuleIssueCollector | None = None
    ) -> Callable[..., str]:
        def render_ruleset(*values: Any, **kwargs: Any) -> str:
            result = self.render_result(platform, *values, **kwargs)
            if collector is not None:
                collector.extend(result.issues)
            return result.content

        render_ruleset.__name__ = self.name
        return render_ruleset


class RuleSetStore:
    def __init__(self) -> None:
        self._items: dict[str, RuleSet] = {}

    def register(self, name: str, item: RuleSet) -> None:
        validate_identifier(name, "name")
        if name != item.name:
            raise ValueError(
                f"Ruleset registration name {name!r} does not match item name "
                f"{item.name!r}"
            )
        if name in self._items:
            raise ValueError(f"Duplicate ruleset name: {name}")
        self._items[name] = item

    def get(self, name: str) -> RuleSet | None:
        return self._items.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._items

    @property
    def names(self) -> list[str]:
        return list(self._items)

    def get_callables(
        self, platform: str, collector: RuleIssueCollector | None = None
    ) -> dict[str, Callable[..., str]]:
        return {
            name: item.as_callable(platform, collector)
            for name, item in self._items.items()
        }


def load_remote_resource(
    url: str,
    user_agent: str | None = None,
    debug: bool = False,
    *,
    loader: RunRemoteLoader | None = None,
    metadata_sink: dict[str, RemoteMetadata] | None = None,
    resource_name: str | None = None,
) -> bytes:
    """Load remote ruleset bytes without text decoding or content sniffing."""
    del debug
    headers = {"User-Agent": user_agent} if user_agent else {}
    owned_loader = loader is None
    active_loader = loader or RunRemoteLoader()
    try:
        content = active_loader.fetch(url, headers=headers)
        if metadata_sink is not None and active_loader.last_result is not None:
            metadata_sink[resource_name or "remote"] = active_loader.last_result.metadata
        return content
    except RemoteLoadError as exc:
        raise ConfigError(str(exc).replace("remote resource", "remote ruleset")) from exc
    finally:
        if owned_loader:
            active_loader.close()


def load_rulesets(
    ruleset_configs: list[RuleSetConfig] | tuple[RuleSetConfig, ...] | list[dict[str, Any]],
    registry: RuleSetInputCodecCatalog = DEFAULT_RULESET_CODEC_REGISTRY,
    *,
    loader: RunRemoteLoader | None = None,
    metadata_sink: dict[str, RemoteMetadata] | None = None,
) -> RuleSetStore:
    store = RuleSetStore()
    if not isinstance(ruleset_configs, (list, tuple)):
        raise ConfigError("Config section 'ruleset' must be a list")

    for config in ruleset_configs:
        if isinstance(config, RuleSetConfig):
            name = config.name
            url = config.url
            user_agent = config.user_agent
            selection = RuleSetInputSelection(
                dialect=config.dialect,
                behavior=config.behavior,
                format=config.format,
            )
        else:
            if not isinstance(config, dict):
                raise ConfigError("Entries in 'ruleset' must be objects")
            name = config.get("name")
            url = config.get("url")
            user_agent = config.get("user_agent")
            selection = RuleSetInputSelection.from_config(config)
        if not isinstance(name, str) or not name:
            raise ConfigError("Every remote ruleset must define a name")
        if not isinstance(url, str) or not url:
            raise ConfigError(f"Ruleset {name!r} must define a URL")
        if user_agent is not None and not isinstance(user_agent, str):
            raise ConfigError(f"Ruleset {name!r} user_agent must be a string")

        callable_name = f"remote_{name}"
        try:
            validate_identifier(callable_name, "name")
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc

        codec = registry.get(selection)
        logger.info(f"Loading ruleset: [cyan]{name}[/cyan]")
        content = load_remote_resource(
            url,
            user_agent,
            loader=loader,
            metadata_sink=metadata_sink,
            resource_name=name,
        )
        if not content:
            raise ConfigError(f"Ruleset {name!r} is empty")

        context = DialectContext(
            dialect=selection.dialect,
            format=selection.format,
        )
        parsed = codec.parse(name=callable_name, content=content, context=context)
        model = _parameterize_headless(parsed.ruleset, parsed.issues)
        store.register(callable_name, RuleSet(model))

    return store


def load_snippets(snippet_dir: str) -> RuleSetStore:
    store = RuleSetStore()
    if not os.path.exists(snippet_dir):
        return store

    for snippet_file in sorted(os.listdir(snippet_dir)):
        if snippet_file.startswith("."):
            continue
        snippet_path = os.path.join(snippet_dir, snippet_file)
        if not os.path.isfile(snippet_path):
            continue

        try:
            validate_identifier(snippet_file, "name")
            with open(snippet_path, "r", encoding="utf-8") as file:
                text = file.read()
            lines = text.splitlines()
            if not lines:
                raise ValueError("file is empty")
            parameters = parse_argument_names(lines[0].strip())
            parsed = MIHOMO_CLASSICAL_PARSER.parse_snippet(
                name=snippet_file,
                parameter_names=parameters,
                content="\n".join(lines[1:]),
                source_context=DialectContext("mihomo", "text"),
            )
            model = ParameterizedRuleSet(
                name=snippet_file,
                parameters=parameters,
                entries=parsed.entries,
                source_context=DialectContext("mihomo", "text"),
                issues=parsed.issues,
            )
            store.register(snippet_file, RuleSet(model))
        except ConfigError:
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            raise ConfigError(f"Invalid snippet {snippet_file!r}: {exc}") from exc

    return store


def _parameterize_headless(
    ruleset: HeadlessRuleSet,
    issues: tuple[ConversionIssue, ...],
) -> ParameterizedRuleSet:
    entries = tuple(
        entry
        if isinstance(entry, RuleComment)
        else BoundRule(entry, DefaultParameter())
        for entry in ruleset.entries
    )
    return ParameterizedRuleSet(
        name=ruleset.name,
        parameters=("rule",),
        entries=entries,
        source_context=ruleset.source_context,
        issues=issues,
    )


def merge_stores(*stores: RuleSetStore) -> RuleSetStore:
    merged = RuleSetStore()
    for store in stores:
        for name in store.names:
            item = store.get(name)
            if item is not None:
                merged.register(name, item)
    return merged
