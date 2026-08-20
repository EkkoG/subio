import os
from dataclasses import dataclass, replace
from typing import Any

import yaml

from subio_v2.core.results import ConversionIssue, IssueSeverity
from subio_v2.infrastructure import age
from subio_v2.adapters.base import BaseEmitter
from subio_v2.core.errors import ArtifactGenerationError
from subio_v2.adapters.catalog import get_emitter
from subio_v2.core.nodes import Node
from subio_v2.protocols.user_overrides import get_nodes_for_user
from subio_v2.rules.runtime import RuleSetStore
from subio_v2.infrastructure.logging import logger
from subio_v2.workflow.config import ArtifactConfig, RunConfig
from subio_v2.workflow.template import TemplateRenderer
from subio_v2.workflow.transforms import filter_nodes


@dataclass(frozen=True)
class ArtifactDraft:
    filename: str
    content: str


@dataclass(frozen=True)
class ArtifactUploadRequest:
    content: str
    artifact_config: ArtifactConfig
    username: str | None = None


@dataclass(frozen=True)
class ArtifactGenerationResult:
    drafts: tuple[ArtifactDraft, ...]
    issues: tuple[ConversionIssue, ...] = ()
    upload_requests: tuple[ArtifactUploadRequest, ...] = ()


class ArtifactGenerationService:
    def __init__(
        self,
        config: RunConfig,
        providers: dict[str, list[Node]],
        provider_issues: dict[str, list[ConversionIssue]],
        renderer: TemplateRenderer,
        rulesets: RuleSetStore,
        global_age_public_key: str = "",
    ):
        self.config = config
        self.providers = providers
        self.provider_issues = provider_issues
        self.renderer = renderer
        self.rulesets = rulesets
        self.global_age_public_key = global_age_public_key

    def generate(self) -> ArtifactGenerationResult:
        drafts: list[ArtifactDraft] = []
        issues: list[ConversionIssue] = []
        upload_requests: list[ArtifactUploadRequest] = []
        filenames: set[str] = set()
        global_filter = self.config.filters
        for artifact_config in self.config.artifacts:
            users = artifact_config.users
            single_user = artifact_config.user
            if users:
                for username in users:
                    result = self._generate_one(
                        artifact_config, global_filter, username
                    )
                    self._collect_result(
                        result, drafts, issues, upload_requests, filenames
                    )
            else:
                result = self._generate_one(
                    artifact_config, global_filter, single_user or None
                )
                self._collect_result(
                    result, drafts, issues, upload_requests, filenames
                )
        return ArtifactGenerationResult(
            drafts=tuple(drafts),
            issues=tuple(issues),
            upload_requests=tuple(upload_requests),
        )

    @staticmethod
    def _collect_result(
        result: tuple[
            ArtifactDraft, tuple[ConversionIssue, ...], ArtifactUploadRequest | None
        ],
        drafts: list[ArtifactDraft],
        issues: list[ConversionIssue],
        upload_requests: list[ArtifactUploadRequest],
        filenames: set[str],
    ) -> None:
        draft, artifact_issues, upload_request = result
        if draft.filename in filenames:
            raise ArtifactGenerationError(
                f"Multiple artifacts would overwrite 'dist/{draft.filename}'"
            )
        filenames.add(draft.filename)
        drafts.append(draft)
        issues.extend(artifact_issues)
        if upload_request is not None:
            upload_requests.append(upload_request)

    def _generate_one(
        self,
        artifact_config: ArtifactConfig,
        global_filter,
        username: str | None,
    ) -> tuple[
        ArtifactDraft, tuple[ConversionIssue, ...], ArtifactUploadRequest | None
    ]:
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
            nodes = filter_nodes(nodes, global_filter)

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
        extra_context = emission.extras.get("template_context", {})
        if not isinstance(extra_context, dict):
            raise ArtifactGenerationError(
                f"Emitter for artifact '{display_name}' returned an invalid "
                "template context"
            )
        rendered_content, ruleset_issues = self._render_content(
            emission.content,
            artifact_config.template,
            artifact_type,
            artifact_config.options,
            username,
            extra_context,
            name,
        )
        artifact_issues.extend(ruleset_issues)
        errors = [
            issue for issue in artifact_issues if issue.severity == IssueSeverity.ERROR
        ]
        BaseEmitter.log_issues(artifact_issues)
        allow_errors = bool(
            self.config.allow_conversion_errors
            or artifact_config.allow_conversion_errors
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
        if not emission.supported_nodes and not artifact_config.allow_empty:
            raise ArtifactGenerationError(
                f"Artifact '{display_name}' has no emit-capable nodes; "
                "set allow_empty=true to permit this",
                issues=artifact_issues,
            )
        draft = self._stage(name, rendered_content, artifact_config, username)
        upload_request = (
            ArtifactUploadRequest(draft.content, artifact_config, username)
            if artifact_config.upload
            else None
        )
        return draft, tuple(artifact_issues), upload_request

    def _render_content(
        self,
        content: str | dict[str, Any],
        template_path: str | None,
        artifact_type: str,
        artifact_options: dict[str, Any],
        username: str | None,
        extra_context: dict[str, Any],
        artifact_name: str,
    ) -> tuple[str, list[ConversionIssue]]:
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
                    **self.config.options,
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
                replace(issue, artifact=artifact_name, user=username)
                for issue in render_result.issues
            ]
            return final_content, ruleset_issues
        elif is_yaml_data:
            final_content = yaml.dump(content, allow_unicode=True, sort_keys=False)
        else:
            final_content = raw_content
        return final_content, []

    def _stage(
        self,
        filename: str,
        content: str,
        artifact_config: ArtifactConfig,
        username: str | None,
    ) -> ArtifactDraft:
        final_content = content
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
        public_key = artifact_config.age_public_key or self.global_age_public_key
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
        return ArtifactDraft(actual_filename, final_content)
