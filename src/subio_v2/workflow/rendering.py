"""Prepare serving resources, then render with request-owned conversion state."""

import copy
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType

from subio_v2.core.errors import ConfigError
from subio_v2.core.parameters import ParameterValue
from subio_v2.infrastructure.logging import Logger
from subio_v2.infrastructure.remote import RunRemoteLoader
from subio_v2.rules.runtime import (
    RuleSetStore,
    load_rulesets,
    load_snippets,
    merge_stores,
)
from subio_v2.workflow.artifacts import (
    ArtifactGenerationResult,
    ArtifactGenerationService,
)
from subio_v2.workflow.config import RunConfig
from subio_v2.workflow.providers import (
    PreparedProvider,
    ProviderLoaderService,
    ProviderLoadResult,
)
from subio_v2.workflow.template import PreparedTemplates


@dataclass(frozen=True)
class PreparationFailure:
    phase: str
    category: str = "unavailable"


@dataclass(frozen=True)
class PreparedRenderResult:
    provider_result: ProviderLoadResult
    artifact_result: ArtifactGenerationResult


@dataclass(frozen=True)
class PreparedArtifact:
    _config: RunConfig = field(repr=False)
    _providers: tuple[PreparedProvider, ...] = field(repr=False)
    _rulesets: RuleSetStore = field(repr=False)
    _templates: PreparedTemplates = field(repr=False)

    def render(
        self, file_name: str, parameters: Mapping[str, ParameterValue]
    ) -> PreparedRenderResult:
        artifact = self._config.artifacts[0]
        selected = next(
            (
                (name, user)
                for name, user in artifact.output_names()
                if name == file_name
            ),
            None,
        )
        if selected is None:
            raise ConfigError("Unknown subscription filename")
        parameters = MappingProxyType(dict(parameters))
        config = replace(
            self._config,
            artifacts=(
                replace(
                    artifact,
                    users=(),
                    user=selected[1],
                    upload=(),
                    options=MappingProxyType(copy.deepcopy(dict(artifact.options))),
                ),
            ),
            uploaders=(),
            options=MappingProxyType(copy.deepcopy(dict(self._config.options))),
        )
        providers = ProviderLoadResult({}, {})
        for prepared in self._providers:
            bound = prepared.bind(parameters)
            providers.providers.update(bound.providers)
            providers.issues.update(bound.issues)
            providers.metadata.update(bound.metadata)
            providers.summaries.update(bound.summaries)
        result = ArtifactGenerationService(
            config,
            providers.providers,
            providers.issues,
            self._templates.renderer(),
            self._rulesets,
            config.age_public_key,
            parameters=parameters,
        ).generate()
        return PreparedRenderResult(providers, result)


@dataclass(frozen=True)
class PreparedRound:
    """Concrete output filenames share their configured artifact's candidate."""

    candidates: Mapping[str, PreparedArtifact]
    failures: Mapping[str, PreparationFailure]


def _preparation_error(exc: Exception) -> str:
    parts = []
    seen = set()
    while exc is not None and id(exc) not in seen and len(parts) < 8:
        seen.add(id(exc))
        parts.append(type(exc).__name__)
        mark = getattr(exc, "problem_mark", None)
        line, column = getattr(mark, "line", None), getattr(mark, "column", None)
        if type(line) is int and type(column) is int:
            parts.append(f"line {line + 1}, column {column + 1}")
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if type(status) is int and 100 <= status <= 599:
            parts.append(f"HTTP {status}")
        exc = exc.__cause__ or exc.__context__
    return " -> ".join(parts)


def prepare_resources(
    config_path: str, config: RunConfig, service_logger: Logger | None = None
) -> PreparedRound:
    """Build private per-artifact candidates; retain no loader or publication state."""
    loader = RunRemoteLoader(
        timeout=config.remote.timeout_seconds,
        max_bytes=config.remote.max_bytes,
        cache_enabled=False,
        stale_if_error=False,
    )
    candidates: dict[str, PreparedArtifact] = {}
    failures: dict[str, PreparationFailure] = {}
    try:
        config_dir = os.path.dirname(config_path)
        if service_logger:
            service_logger.debug("Preparing shared rulesets and snippets")
        try:
            rulesets = merge_stores(
                load_snippets(os.path.join(config_dir, "snippet")),
                load_rulesets(config.rulesets, loader=loader),
            )
            if service_logger:
                service_logger.debug(f"Shared rules prepared ({len(rulesets.names)} sets)")
        except Exception as exc:
            if service_logger:
                service_logger.error("Shared ruleset preparation failed: " + _preparation_error(exc))
            return PreparedRound(
                MappingProxyType({}),
                MappingProxyType(
                    {
                        name: PreparationFailure("ruleset")
                        for item in config.artifacts
                        for name, _ in item.output_names()
                    }
                ),
            )
        service = ProviderLoaderService(config_path, config.age_secret_key)
        referenced = {name for item in config.artifacts for name in item.providers}
        providers = {}
        for index, item in enumerate(config.providers, 1):
            if item.name in referenced:
                started = time.monotonic()
                if service_logger:
                    source_kind = "remote" if item.url else "local"
                    service_logger.debug(f"Preparing provider #{index} ({source_kind}, {item.provider_type})")
                try:
                    providers[item.name] = service.prepare(item, loader)
                except Exception as exc:
                    # Do not retain exception bodies, source text, paths or credentials.
                    if service_logger:
                        service_logger.warning(f"Provider #{index} preparation failed: " + _preparation_error(exc))
                else:
                    if service_logger:
                        service_logger.debug(f"Provider #{index} prepared ({time.monotonic() - started:.3f}s)")
        template_dir = os.path.join(config_dir, "template")
        if not os.path.exists(template_dir):
            template_dir = config_dir
        roots = {item.template for item in config.artifacts if item.template}
        templates = PreparedTemplates(
            MappingProxyType({}), MappingProxyType({}), frozenset()
        )
        if roots:
            if service_logger:
                service_logger.debug(f"Capturing templates for {len(roots)} configured roots")
            try:
                templates = PreparedTemplates.capture(template_dir, roots)
            except Exception as exc:
                templates = None
                if service_logger:
                    service_logger.error("Template capture failed: " + _preparation_error(exc))
        for index, artifact in enumerate(config.artifacts, 1):
            if any(name not in providers for name in artifact.providers):
                if service_logger:
                    service_logger.warning(f"Artifact #{index} unavailable: provider preparation failed")
                failures.update(
                    {
                        name: PreparationFailure("provider")
                        for name, _ in artifact.output_names()
                    }
                )
            elif artifact.template and (
                templates is None or artifact.template in templates.failed_roots
            ):
                if service_logger:
                    service_logger.warning(f"Artifact #{index} unavailable: root template preparation failed")
                failures.update(
                    {
                        name: PreparationFailure("template")
                        for name, _ in artifact.output_names()
                    }
                )
            else:
                private_artifact = replace(
                    artifact,
                    options=MappingProxyType(copy.deepcopy(dict(artifact.options))),
                )
                private_config = replace(
                    config,
                    artifacts=(private_artifact,),
                    providers=tuple(
                        item
                        for item in config.providers
                        if item.name in artifact.providers
                    ),
                    uploaders=(),
                    options=MappingProxyType(copy.deepcopy(dict(config.options))),
                )
                candidate = PreparedArtifact(
                    private_config,
                    tuple(providers[name] for name in artifact.providers),
                    rulesets,
                    templates
                    or PreparedTemplates(
                        MappingProxyType({}), MappingProxyType({}), frozenset()
                    ),
                )
                candidates.update(
                    {name: candidate for name, _ in artifact.output_names()}
                )
                if service_logger:
                    service_logger.debug(f"Artifact #{index} prepared ({len(artifact.output_names())} outputs)")
        return PreparedRound(MappingProxyType(candidates), MappingProxyType(failures))
    finally:
        loader.close()
