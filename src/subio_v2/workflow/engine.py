import os
from dataclasses import replace
from typing import Any, Dict, List

import yaml

from subio_v2.conversion import (
    ConversionIssue,
    IssueSeverity,
    WorkflowResult,
)
from subio_v2.crypto import age
from subio_v2.emitter.base import BaseEmitter
from subio_v2.emitter.registry import EmitterRegistry
from subio_v2.errors import ArtifactGenerationError, ConfigError
from subio_v2.model.nodes import Node
from subio_v2.processor.common import FilterProcessor
from subio_v2.protocols.user_overrides import get_nodes_for_user
from subio_v2.remote import RunRemoteLoader
from subio_v2.rules.runtime import (
    RuleSetStore,
    load_rulesets,
    load_snippets,
    merge_stores,
)
from subio_v2.utils.logger import logger
from subio_v2.workflow.config import ConfigLoader, RunConfig
from subio_v2.workflow.config_validation import ConfigValidator
from subio_v2.workflow.providers import ProviderLoaderService
from subio_v2.workflow.publication import ArtifactPublisher
from subio_v2.workflow.template import TemplateRenderer
from subio_v2.workflow.uploader import GistBatchUploader, upload


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

        ConfigValidator.validate(self.config)
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
            self._generate_artifacts()
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

    def _generate_artifacts(self):
        global_filter = None
        if self.config.get("filters"):
            global_filter = FilterProcessor(
                include=self.config["filters"].get("include"),
                exclude=self.config["filters"].get("exclude"),
            )

        for art_conf in self.config.get("artifact", []):
            # Check for multi-user batch generation
            users = art_conf.get("users", [])
            single_user = art_conf.get("user")

            if users:
                # Batch generate for multiple users
                for username in users:
                    self._generate_single_artifact(art_conf, global_filter, username)
            elif single_user:
                # Single user specified
                self._generate_single_artifact(art_conf, global_filter, single_user)
            else:
                # No user specified, generate normally
                self._generate_single_artifact(art_conf, global_filter, None)

    def _generate_single_artifact(
        self,
        art_conf: Dict[str, Any],
        global_filter: FilterProcessor | None,
        username: str | None,
    ):
        name = art_conf.get("name")
        a_type = art_conf.get("type")

        # Gather nodes from providers
        nodes = []
        for prov_name in art_conf.get("providers", []):
            if prov_name not in self.providers:
                raise ArtifactGenerationError(
                    f"Artifact '{name}' references unloaded provider '{prov_name}'"
                )
            nodes.extend(self.providers[prov_name])

        # If username specified, process nodes for that user
        if username:
            try:
                nodes = get_nodes_for_user(nodes, username)
            except ValueError as exc:
                raise ArtifactGenerationError(
                    f"Invalid user overrides for artifact '{name}': {exc}"
                ) from exc

        # Apply Global Filter
        if global_filter:
            nodes = global_filter.process(nodes)

        # Emit
        emitter = EmitterRegistry.get_emitter(a_type)

        if emitter:
            # Determine display name and actual filename
            display_name = name
            if username:
                display_name = f"{name} (user: {username})"

            logger.info(
                f"Generating artifact: [bold cyan]{display_name}[/bold cyan] ({a_type}) - {len(nodes)} nodes"
            )
            try:
                emission = emitter.emit_result(nodes)
            except Exception as exc:
                raise ArtifactGenerationError(
                    f"Failed to emit artifact '{display_name}': {exc}"
                ) from exc

            artifact_issues = [
                replace(issue, artifact=name, user=username)
                for prov_name in art_conf.get("providers", [])
                for issue in self.provider_issues.get(prov_name, [])
            ]
            artifact_issues.extend(
                replace(issue, artifact=name, user=username)
                for issue in emission.issues
            )
            self.issues.extend(artifact_issues)
            emitter.log_issues(artifact_issues)
            errors = [
                issue
                for issue in artifact_issues
                if issue.severity == IssueSeverity.ERROR
            ]
            allow_conversion_errors = bool(
                self.config.get("allow_conversion_errors", False)
                or art_conf.get("allow_conversion_errors", False)
            )
            if errors and not allow_conversion_errors:
                raise ArtifactGenerationError(
                    f"Artifact '{display_name}' has {len(errors)} conversion error(s)",
                    issues=errors,
                )
            if errors:
                logger.warning(
                    f"Artifact '{display_name}' is continuing with {len(errors)} "
                    "conversion error(s) because allow_conversion_errors=true"
                )

            supported_nodes = emission.supported_nodes
            if not supported_nodes and not art_conf.get("allow_empty", False):
                raise ArtifactGenerationError(
                    f"Artifact '{display_name}' has no emit-capable nodes; "
                    "set allow_empty=true to permit this",
                    issues=artifact_issues,
                )

            output = emission.content
            extra_context = emission.extras.get("template_context", {})
            if not isinstance(extra_context, dict):
                raise ArtifactGenerationError(
                    f"Emitter for artifact '{display_name}' returned an invalid "
                    "template context"
                )

            # Use unified writer
            self._write_artifact(
                name,
                output,
                art_conf.get("template"),
                a_type,
                art_conf.get("options", {}),
                art_conf,
                username,
                extra_context,
            )
        else:
            raise ArtifactGenerationError(
                f"Unsupported artifact type '{a_type}' for artifact '{name}'"
            )

    def _write_artifact(
        self,
        filename: str,
        content: str | Dict[str, Any],
        template_path: str,
        artifact_type: str = None,
        artifact_options: Dict[str, Any] = None,
        artifact_conf: Dict[str, Any] = None,
        username: str = None,
        extra_context: Dict[str, Any] = None,
    ):
        final_content = ""

        # If content is dict (Clash/Stash), dump to YAML string first
        is_yaml_data = isinstance(content, dict)
        raw_content_str = ""

        if is_yaml_data:
            proxies_list = content.get("proxies", [])
            raw_content_str = yaml.dump(
                proxies_list, allow_unicode=True, sort_keys=False
            )
        else:
            raw_content_str = content

        if template_path:
            # Merge global_options into options (artifact options override global)
            merged_options = {
                **self.config.get("options", {}),
                **(artifact_options or {}),
            }
            context = {
                "proxies": raw_content_str,  # For Clash, this is the proxies list YAML. For Surge, this is the text block.
                "options": merged_options,
                "user": username,  # Add username to template context
            }

            if extra_context:
                context.update(extra_context)

            render_result = self.renderer.render_result(
                template_path, context, artifact_type, self.rulesets
            )
            final_content = render_result.content
            ruleset_issues = [
                replace(issue, artifact=filename, user=username)
                for issue in render_result.issues
            ]
            self.issues.extend(ruleset_issues)
            BaseEmitter.log_issues(ruleset_issues)
            ruleset_errors = [
                issue
                for issue in ruleset_issues
                if issue.severity == IssueSeverity.ERROR
            ]
            allow_conversion_errors = bool(
                self.config.get("allow_conversion_errors", False)
                or (artifact_conf or {}).get("allow_conversion_errors", False)
            )
            if ruleset_errors and not allow_conversion_errors:
                raise ArtifactGenerationError(
                    f"Artifact '{filename}' has {len(ruleset_errors)} ruleset conversion error(s)",
                    issues=ruleset_errors,
                )
            if ruleset_errors:
                logger.warning(
                    f"Artifact '{filename}' is continuing with "
                    f"{len(ruleset_errors)} ruleset conversion error(s) because "
                    "allow_conversion_errors=true"
                )
        else:
            if is_yaml_data:
                final_content = yaml.dump(content, allow_unicode=True, sort_keys=False)
            else:
                final_content = raw_content_str

        # Replace {user} placeholder in filename
        actual_filename = filename
        if username:
            actual_filename = filename.replace("{user}", username)

        if (
            not isinstance(actual_filename, str)
            or not actual_filename
            or actual_filename != os.path.basename(actual_filename)
            or "/" in actual_filename
            or "\\" in actual_filename
            or actual_filename in {".", ".."}
        ):
            raise ArtifactGenerationError(
                f"Invalid artifact filename: {actual_filename!r}"
            )

        # Encrypt output with age if public key is configured.
        # Artifact-level key takes precedence over global key.
        artifact_public_key = (artifact_conf or {}).get("age_public_key", "")
        public_key = artifact_public_key or self.global_age_public_key
        if public_key:
            try:
                final_content_bytes = age.encrypt_bytes(final_content, public_key)
                final_content = final_content_bytes.decode("ascii")
                logger.dim("Encrypted artifact output with age public key")
            except Exception as e:
                raise ArtifactGenerationError(
                    f"Failed to encrypt artifact '{actual_filename}': {e}"
                ) from e

        if actual_filename in self._staged_artifacts:
            raise ArtifactGenerationError(
                f"Multiple artifacts would overwrite 'dist/{actual_filename}'"
            )
        self._staged_artifacts[actual_filename] = final_content

        # Upload
        if artifact_conf and artifact_conf.get("upload"):
            upload(
                final_content,
                artifact_conf,
                self.config.get("uploader", []),
                self.batch_uploader,
                username,
            )

    def _commit_artifacts(self) -> None:
        self.publisher.commit(self._staged_artifacts)
