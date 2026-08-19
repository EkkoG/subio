import os
from typing import Dict, List

from subio_v2.conversion import (
    ConversionIssue,
    WorkflowResult,
)
from subio_v2.crypto import age
from subio_v2.errors import ConfigError
from subio_v2.model.nodes import Node
from subio_v2.remote import RunRemoteLoader
from subio_v2.rules.runtime import (
    RuleSetStore,
    load_rulesets,
    load_snippets,
    merge_stores,
)
from subio_v2.utils.logger import logger
from subio_v2.workflow.artifacts import ArtifactGenerationService
from subio_v2.workflow.config import ConfigLoader, RunConfig
from subio_v2.workflow.config_validation import ConfigValidator
from subio_v2.workflow.providers import ProviderLoaderService
from subio_v2.workflow.publication import ArtifactPublisher
from subio_v2.workflow.template import TemplateRenderer
from subio_v2.workflow.uploader import GistBatchUploader


class WorkflowEngine:
    def __init__(
        self, config_path: str, dry_run: bool = False, clean_gist: bool = False
    ):
        self.config_path = config_path
        self.config: RunConfig = ConfigLoader.load(self.config_path)
        self.providers: Dict[str, List[Node]] = {}
        self.provider_issues: Dict[str, List[ConversionIssue]] = {}
        self.dry_run = dry_run
        self.clean_gist = clean_gist
        self._staged_artifacts: Dict[str, str] = {}
        self.issues: List[ConversionIssue] = []
        self.batch_uploader = GistBatchUploader(dry_run=dry_run, clean_gist=clean_gist)
        self.publisher = ArtifactPublisher()

        # Age encryption keys
        self.global_age_secret_key = self.config.get("age_secret_key", "")
        self.global_age_public_key = self.config.get("age_public_key", "")

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
        self.rulesets = merge_stores(self._local_rulesets)

    def run(self) -> WorkflowResult:
        if self.dry_run:
            logger.info("--- Starting SubIO v2 Workflow (DRY-RUN) ---")
        else:
            logger.info("--- Starting SubIO v2 Workflow ---")
        self.batch_uploader.begin()
        self._staged_artifacts.clear()
        self.providers.clear()
        self.issues.clear()
        self.provider_issues.clear()
        remote_loader = RunRemoteLoader()
        try:
            remote_rulesets = (
                load_rulesets(self.config["ruleset"], loader=remote_loader)
                if "ruleset" in self.config
                else RuleSetStore()
            )
            self.rulesets = merge_stores(self._local_rulesets, remote_rulesets)
            provider_result = ProviderLoaderService(
                self.config_path, self.global_age_secret_key
            ).load(self.config, remote_loader)
            self.providers = provider_result.providers
            self.provider_issues = provider_result.issues
            artifact_result = ArtifactGenerationService(
                self.config,
                self.providers,
                self.provider_issues,
                self.renderer,
                self.rulesets,
                self.batch_uploader,
                self.global_age_public_key,
            ).generate()
            self._staged_artifacts = artifact_result.staged_artifacts
            self.issues.extend(artifact_result.issues)
            generated = list(self._staged_artifacts)
            queued_uploads = self.batch_uploader.pending_uploads()
            self._commit_artifacts()
            self.batch_uploader.flush()
        except BaseException:
            self._staged_artifacts.clear()
            self.batch_uploader.abort()
            raise
        logger.success("--- Finished ---")
        return WorkflowResult(
            generated=generated,
            uploaded=[] if self.dry_run else queued_uploads,
            issues=list(self.issues),
        )

    def _commit_artifacts(self) -> None:
        self.publisher.commit(self._staged_artifacts)
