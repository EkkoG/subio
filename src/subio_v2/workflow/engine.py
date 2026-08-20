import os
from dataclasses import dataclass

from subio_v2.core.errors import ConfigError
from subio_v2.core.results import (
    WorkflowResult,
)
from subio_v2.infrastructure import age
from subio_v2.infrastructure.logging import logger
from subio_v2.infrastructure.remote import RunRemoteLoader
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
from subio_v2.workflow.providers import ProviderLoaderService, ProviderLoadResult
from subio_v2.workflow.publication import ArtifactPublisher
from subio_v2.workflow.template import TemplateRenderer
from subio_v2.workflow.uploader import GistBatchUploader, queue_upload_requests


@dataclass(frozen=True)
class WorkflowPreparation:
    provider_result: ProviderLoadResult
    artifact_result: ArtifactGenerationResult


class WorkflowEngine:
    def __init__(
        self, config_path: str, dry_run: bool = False, clean_gist: bool = False
    ):
        self.config_path = config_path
        self.config: RunConfig = ConfigLoader.load(self.config_path)
        self.dry_run = dry_run
        self.clean_gist = clean_gist
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

    def run(self) -> WorkflowResult:
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

        remote_loader = RunRemoteLoader()
        remote_rulesets = (
            load_rulesets(self.config.rulesets, loader=remote_loader)
            if self.config.rulesets
            else RuleSetStore()
        )
        rulesets = merge_stores(self._local_rulesets, remote_rulesets)
        provider_result = ProviderLoaderService(
            self.config_path, self.global_age_secret_key
        ).load(self.config, remote_loader)
        artifact_result = ArtifactGenerationService(
            self.config,
            provider_result.providers,
            provider_result.issues,
            self.renderer,
            rulesets,
            self.global_age_public_key,
        ).generate()
        return WorkflowPreparation(provider_result, artifact_result)

    def load_providers(self) -> ProviderLoadResult:
        """Load providers for inspect without generating or publishing artifacts."""

        return ProviderLoaderService(
            self.config_path, self.global_age_secret_key
        ).load(self.config, RunRemoteLoader())

    def _commit_artifacts(self, drafts: tuple[ArtifactDraft, ...]) -> None:
        self.publisher.commit(drafts)
