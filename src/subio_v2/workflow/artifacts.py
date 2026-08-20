import os
from dataclasses import dataclass, replace
from typing import Any

import yaml

from subio_v2.conversion import ConversionIssue, IssueSeverity
from subio_v2.crypto import age
from subio_v2.emitter.base import BaseEmitter
from subio_v2.emitter.registry import get_emitter
from subio_v2.errors import ArtifactGenerationError
from subio_v2.model.nodes import Node
from subio_v2.processor.common import FilterProcessor
from subio_v2.protocols.user_overrides import get_nodes_for_user
from subio_v2.rules.runtime import RuleSetStore
from subio_v2.utils.logger import logger
from subio_v2.workflow.config import ArtifactConfig, RunConfig
from subio_v2.workflow.template import TemplateRenderer
from subio_v2.workflow.uploader import GistBatchUploader, upload


@dataclass(frozen=True)
class ArtifactGenerationResult:
    staged_artifacts: dict[str, str]
    issues: list[ConversionIssue]


class ArtifactGenerationService:
    def __init__(
        self,
        config: RunConfig,
        providers: dict[str, list[Node]],
        provider_issues: dict[str, list[ConversionIssue]],
        renderer: TemplateRenderer,
        rulesets: RuleSetStore,
        batch_uploader: GistBatchUploader,
        global_age_public_key: str = "",
    ):
        self.config = config
        self.providers = providers
        self.provider_issues = provider_issues
        self.renderer = renderer
        self.rulesets = rulesets
        self.batch_uploader = batch_uploader
        self.global_age_public_key = global_age_public_key
        self.staged_artifacts: dict[str, str] = {}
        self.issues: list[ConversionIssue] = []

    def generate(self) -> ArtifactGenerationResult:
        global_filter = None
        if self.config.get("filters"):
            global_filter = FilterProcessor(
                include=self.config["filters"].get("include"),
                exclude=self.config["filters"].get("exclude"),
            )
        for artifact_config in self.config.artifacts:
            users = artifact_config.get("users", [])
            single_user = artifact_config.get("user")
            if users:
                for username in users:
                    self._generate_one(artifact_config, global_filter, username)
            else:
                self._generate_one(
                    artifact_config, global_filter, single_user or None
                )
        return ArtifactGenerationResult(
            dict(self.staged_artifacts), list(self.issues)
        )

    def _generate_one(
        self,
        artifact_config: ArtifactConfig,
        global_filter: FilterProcessor | None,
        username: str | None,
    ) -> None:
        name = artifact_config.name
        artifact_type = artifact_config.artifact_type
        nodes: list[Node] = []
        for provider_name in artifact_config.providers:
            if provider_name not in self.providers:
                raise ArtifactGenerationError(
                    f"Artifact '{name}' references unloaded provider '{provider_name}'"
                )
            nodes.extend(self.providers[provider_name])
        if username:
            try:
                nodes = get_nodes_for_user(nodes, username)
            except ValueError as exc:
                raise ArtifactGenerationError(
                    f"Invalid user overrides for artifact '{name}': {exc}"
                ) from exc
        if global_filter:
            nodes = global_filter.process(nodes)

        emitter = get_emitter(artifact_type)
        if emitter is None:
            raise ArtifactGenerationError(
                f"Unsupported artifact type '{artifact_type}' for artifact '{name}'"
            )
        display_name = f"{name} (user: {username})" if username else name
        logger.info(
            f"Generating artifact: [bold cyan]{display_name}[/bold cyan] "
            f"({artifact_type}) - {len(nodes)} nodes"
        )
        try:
            emission = emitter.emit_result(nodes)
        except Exception as exc:
            raise ArtifactGenerationError(
                f"Failed to emit artifact '{display_name}': {exc}"
            ) from exc

        artifact_issues = [
            replace(issue, artifact=name, user=username)
            for provider_name in artifact_config.providers
            for issue in self.provider_issues.get(provider_name, [])
        ]
        artifact_issues.extend(
            replace(issue, artifact=name, user=username) for issue in emission.issues
        )
        self.issues.extend(artifact_issues)
        emitter.log_issues(artifact_issues)
        errors = [
            issue for issue in artifact_issues if issue.severity == IssueSeverity.ERROR
        ]
        allow_errors = bool(
            self.config.get("allow_conversion_errors", False)
            or artifact_config.get("allow_conversion_errors", False)
        )
        if errors and not allow_errors:
            raise ArtifactGenerationError(
                f"Artifact '{display_name}' has {len(errors)} conversion error(s)",
                issues=errors,
            )
        if errors:
            logger.warning(
                f"Artifact '{display_name}' is continuing with {len(errors)} "
                "conversion error(s) because allow_conversion_errors=true"
            )
        if not emission.supported_nodes and not artifact_config.get(
            "allow_empty", False
        ):
            raise ArtifactGenerationError(
                f"Artifact '{display_name}' has no emit-capable nodes; "
                "set allow_empty=true to permit this",
                issues=artifact_issues,
            )
        extra_context = emission.extras.get("template_context", {})
        if not isinstance(extra_context, dict):
            raise ArtifactGenerationError(
                f"Emitter for artifact '{display_name}' returned an invalid "
                "template context"
            )
        self._stage(
            name,
            emission.content,
            artifact_config.get("template"),
            artifact_type,
            artifact_config.get("options", {}),
            artifact_config,
            username,
            extra_context,
        )

    def _stage(
        self,
        filename: str,
        content: str | dict[str, Any],
        template_path: str | None,
        artifact_type: str,
        artifact_options: dict[str, Any],
        artifact_config: ArtifactConfig,
        username: str | None,
        extra_context: dict[str, Any],
    ) -> None:
        is_yaml_data = isinstance(content, dict)
        raw_content = (
            yaml.dump(content.get("proxies", []), allow_unicode=True, sort_keys=False)
            if is_yaml_data
            else content
        )
        if template_path:
            context = {
                "proxies": raw_content,
                "options": {
                    **self.config.get("options", {}),
                    **artifact_options,
                },
                "user": username,
                **extra_context,
            }
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
            errors = [
                issue
                for issue in ruleset_issues
                if issue.severity == IssueSeverity.ERROR
            ]
            allow_errors = bool(
                self.config.get("allow_conversion_errors", False)
                or artifact_config.get("allow_conversion_errors", False)
            )
            if errors and not allow_errors:
                raise ArtifactGenerationError(
                    f"Artifact '{filename}' has {len(errors)} ruleset conversion error(s)",
                    issues=errors,
                )
            if errors:
                logger.warning(
                    f"Artifact '{filename}' is continuing with {len(errors)} "
                    "ruleset conversion error(s) because "
                    "allow_conversion_errors=true"
                )
        elif is_yaml_data:
            final_content = yaml.dump(content, allow_unicode=True, sort_keys=False)
        else:
            final_content = raw_content

        actual_filename = (
            filename.replace("{user}", username) if username else filename
        )
        if (
            not actual_filename
            or actual_filename != os.path.basename(actual_filename)
            or "/" in actual_filename
            or "\\" in actual_filename
            or actual_filename in {".", ".."}
        ):
            raise ArtifactGenerationError(
                f"Invalid artifact filename: {actual_filename!r}"
            )
        public_key = artifact_config.get(
            "age_public_key", ""
        ) or self.global_age_public_key
        if public_key:
            try:
                final_content = age.encrypt_bytes(final_content, public_key).decode(
                    "ascii"
                )
                logger.dim("Encrypted artifact output with age public key")
            except Exception as exc:
                raise ArtifactGenerationError(
                    f"Failed to encrypt artifact '{actual_filename}': {exc}"
                ) from exc
        if actual_filename in self.staged_artifacts:
            raise ArtifactGenerationError(
                f"Multiple artifacts would overwrite 'dist/{actual_filename}'"
            )
        self.staged_artifacts[actual_filename] = final_content
        if artifact_config.get("upload"):
            upload(
                final_content,
                artifact_config,
                self.config.uploaders,
                self.batch_uploader,
                username,
            )
