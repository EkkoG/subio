import copy
import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType

from subio_v2.core.errors import ConfigError
from subio_v2.core.parameters import ParameterValue
from subio_v2.core.results import (
    WorkflowResult,
)
from subio_v2.infrastructure import age
from subio_v2.infrastructure.logging import logger
from subio_v2.infrastructure.remote import RemoteMetadata, RunRemoteLoader
from subio_v2.rules.runtime import (
    RuleSetStore,
    load_rulesets,
    load_snippets,
    merge_stores,
)
from subio_v2.workflow.artifacts import (
    ArtifactDraft,
    ArtifactGenerationResult,
    ArtifactGenerationService,
)
from subio_v2.workflow.config import ConfigLoader, RunConfig
from subio_v2.workflow.config_validation import ConfigValidator
from subio_v2.workflow.manifest import apply_manifest
from subio_v2.workflow.providers import ProviderLoaderService, ProviderLoadResult
from subio_v2.workflow.publication import ArtifactPublisher
from subio_v2.workflow.template import TemplateRenderer
from subio_v2.workflow.uploader import GistBatchUploader, queue_upload_requests


@dataclass(frozen=True)
class WorkflowPreparation:
    provider_result: ProviderLoadResult
    artifact_result: ArtifactGenerationResult
    ruleset_metadata: dict[str, RemoteMetadata]


class WorkflowEngine:
    def __init__(
        self,
        config_path: str,
        dry_run: bool = False,
        clean_gist: bool = False,
        write_manifest: bool = False,
        clean_dist: bool = False,
        *,
        _config: RunConfig | None = None,
        _parameters: Mapping[str, ParameterValue] | None = None,
    ):
        self.config_path = config_path
        self.config = _config if _config is not None else ConfigLoader.load(config_path)
        self._parameters = (
            MappingProxyType(dict(_parameters)) if _parameters is not None else None
        )
        if self._parameters is None and any(
            item.parameterized for item in self.config.providers
        ):
            raise ConfigError(
                "Parameterized providers are only available in scoped rendering requests"
            )
        self.dry_run = dry_run
        self.clean_gist = clean_gist
        self.write_manifest = write_manifest or clean_dist
        self.clean_dist = clean_dist
        self.batch_uploader = GistBatchUploader(dry_run=dry_run, clean_gist=clean_gist)
        self.publisher = ArtifactPublisher()

        # Age encryption keys
        self.global_age_secret_key = self.config.age_secret_key
        self.global_age_public_key = self.config.age_public_key

        if self.global_age_secret_key:
            err = age.verify_secret_key(self.global_age_secret_key)
            if err:
                raise ConfigError(f"Invalid global age_secret_key: {err}")

        if self.global_age_public_key:
            err = age.verify_public_key(self.global_age_public_key)
            if err:
                raise ConfigError(f"Invalid global age_public_key: {err}")

        ConfigValidator.warn_platform_replacements(self.config)

        # Parsers and emitters are constructed by their registries.

        # Template Renderer
        config_dir = os.path.dirname(self.config_path)
        template_dir = os.path.join(config_dir, "template")
        snippet_dir = os.path.join(config_dir, "snippet")

        if not os.path.exists(template_dir):
            # Fallback or just use config dir
            template_dir = config_dir
        self.renderer = TemplateRenderer(template_dir)

        # Local snippets are static; remote rulesets are rebuilt for every run.
        if os.path.exists(snippet_dir):
            self._local_rulesets = load_snippets(snippet_dir)
        else:
            self._local_rulesets = RuleSetStore()

    @classmethod
    def for_render(
        cls,
        config_path: str,
        config: RunConfig,
        file_name: str,
        parameters: Mapping[str, ParameterValue],
    ) -> "WorkflowEngine":
        """Create a prepare-only engine from a snapshot and normalized parameters."""
        selected = next(
            (
                (item, user) for item in config.artifacts
                for output_name, user in item.output_names() if output_name == file_name
            ),
            None,
        )
        if selected is None:
            raise ConfigError("Unknown subscription filename")
        artifact, user = selected
        selected_artifact = replace(
            artifact,
            users=(),
            user=user,
            allow_conversion_errors=False,
            upload=(),
            options=MappingProxyType(copy.deepcopy(dict(artifact.options))),
        )
        selected_config = replace(
            config,
            providers=tuple(
                item for item in config.providers if item.name in artifact.providers
            ),
            artifacts=(selected_artifact,),
            uploaders=(),
            allow_conversion_errors=False,
            options=MappingProxyType(copy.deepcopy(dict(config.options))),
        )
        return cls(config_path, _config=selected_config, _parameters=parameters)

    def run(self) -> WorkflowResult:
        if self._parameters is not None:
            raise ConfigError("Scoped rendering requests only support preparation")
        if self.dry_run:
            logger.info("--- Starting SubIO v2 Workflow (DRY-RUN) ---")
        else:
            logger.info("--- Starting SubIO v2 Workflow ---")
        self.batch_uploader.begin()
        try:
            preparation = self.prepare()
            artifact_result = preparation.artifact_result
            queue_upload_requests(
                artifact_result.upload_requests,
                self.config.uploaders,
                self.batch_uploader,
            )
            generated = [draft.filename for draft in artifact_result.drafts]
            queued_uploads = self.batch_uploader.pending_uploads()
            self._commit_artifacts(artifact_result.drafts)
            self.batch_uploader.flush()
            if self.write_manifest:
                apply_manifest(
                    self.config_path,
                    artifact_result.summaries,
                    preparation.provider_result.summaries,
                    dist_dir=Path("dist"),
                    clean=self.clean_dist,
                )
        except BaseException:
            self.batch_uploader.abort()
            raise
        logger.success("--- Finished ---")
        return WorkflowResult(
            generated=generated,
            uploaded=[] if self.dry_run else queued_uploads,
            issues=list(artifact_result.issues),
        )

    def prepare(self) -> WorkflowPreparation:
        """Run all pure/load/generate stages without writing or uploading."""

        remote_loader = self._remote_loader()
        try:
            ruleset_metadata: dict[str, RemoteMetadata] = {}
            remote_rulesets = (
                load_rulesets(
                    self.config.rulesets,
                    loader=remote_loader,
                    metadata_sink=ruleset_metadata,
                )
                if self.config.rulesets
                else RuleSetStore()
            )
            rulesets = merge_stores(self._local_rulesets, remote_rulesets)
            provider_service = ProviderLoaderService(
                self.config_path, self.global_age_secret_key
            )
            provider_result = (
                provider_service.load(self.config, remote_loader)
                if self._parameters is None
                else provider_service.load(
                    self.config, remote_loader, parameters=self._parameters
                )
            )
            artifact_result = ArtifactGenerationService(
                self.config,
                provider_result.providers,
                provider_result.issues,
                self.renderer,
                rulesets,
                self.global_age_public_key,
                parameters=self._parameters,
            ).generate()
            return WorkflowPreparation(
                provider_result,
                artifact_result,
                ruleset_metadata,
            )
        finally:
            remote_loader.close()

    def load_providers(self) -> ProviderLoadResult:
        """Load providers for inspect without generating or publishing artifacts."""

        if self._parameters is not None:
            raise ConfigError("Scoped rendering requests only support preparation")
        remote_loader = self._remote_loader()
        try:
            return ProviderLoaderService(
                self.config_path, self.global_age_secret_key
            ).load(self.config, remote_loader)
        finally:
            remote_loader.close()

    def _remote_loader(self) -> RunRemoteLoader:
        return RunRemoteLoader(
            timeout=self.config.remote.timeout_seconds,
            max_bytes=self.config.remote.max_bytes,
            cache_enabled=self.config.remote.cache.enabled,
            cache_ttl=self.config.remote.cache.ttl_seconds,
            stale_if_error=self.config.remote.cache.stale_if_error,
        )

    def _commit_artifacts(self, drafts: tuple[ArtifactDraft, ...]) -> None:
        self.publisher.commit(drafts)
