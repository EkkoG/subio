"""Prepare serving resources, then render with request-owned conversion state."""

import copy
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType

from subio_v2.core.errors import ConfigError
from subio_v2.core.parameters import ParameterValue
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
                    allow_conversion_errors=False,
                    options=MappingProxyType(copy.deepcopy(dict(artifact.options))),
                ),
            ),
            uploaders=(),
            allow_conversion_errors=False,
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


def prepare_resources(config_path: str, config: RunConfig) -> PreparedRound:
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
        try:
            rulesets = merge_stores(
                load_snippets(os.path.join(config_dir, "snippet")),
                load_rulesets(config.rulesets, loader=loader),
            )
        except Exception:
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
        for item in config.providers:
            if item.name in referenced:
                try:
                    providers[item.name] = service.prepare(item, loader)
                except Exception:
                    # Do not retain exception bodies, source text, paths or credentials.
                    pass
        template_dir = os.path.join(config_dir, "template")
        if not os.path.exists(template_dir):
            template_dir = config_dir
        roots = {item.template for item in config.artifacts if item.template}
        templates = PreparedTemplates(
            MappingProxyType({}), MappingProxyType({}), frozenset()
        )
        if roots:
            try:
                templates = PreparedTemplates.capture(template_dir, roots)
            except Exception:
                templates = None
        for artifact in config.artifacts:
            if any(name not in providers for name in artifact.providers):
                failures.update(
                    {
                        name: PreparationFailure("provider")
                        for name, _ in artifact.output_names()
                    }
                )
            elif artifact.template and (
                templates is None or artifact.template in templates.failed_roots
            ):
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
                    allow_conversion_errors=False,
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
        return PreparedRound(MappingProxyType(candidates), MappingProxyType(failures))
    finally:
        loader.close()
