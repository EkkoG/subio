"""Privacy-safe workflow reports for check and inspect commands."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from subio_v2.core.results import ConversionIssue, IssueSeverity
from subio_v2.infrastructure.remote import RemoteMetadata
from subio_v2.workflow.artifacts import ArtifactGenerationResult
from subio_v2.workflow.manifest import MANIFEST_NAME, read_manifest
from subio_v2.workflow.providers import ProviderLoadResult


def _issue_dict(issue: ConversionIssue) -> dict[str, Any]:
    return {
        "severity": issue.severity.value,
        "code": issue.code,
        "stage": issue.stage,
        "node": issue.node,
        "protocol": issue.protocol,
        "source": issue.source,
        "target": issue.target,
        "field": issue.field,
        "artifact": issue.artifact,
        "user": issue.user,
        "message": issue.message,
        "suggestion": issue.suggestion,
    }


def _issue_counts(issues: list[ConversionIssue]) -> dict[str, int]:
    return {
        "errors": sum(issue.severity == IssueSeverity.ERROR for issue in issues),
        "warnings": sum(issue.severity == IssueSeverity.WARNING for issue in issues),
        "infos": sum(issue.severity == IssueSeverity.INFO for issue in issues),
    }


def _dist_status(dist_dir: Path | None, filename: str, digest: str) -> str:
    if dist_dir is None:
        return "not-compared"
    target = dist_dir / filename
    if not target.is_file():
        return "new"
    hasher = hashlib.sha256()
    with target.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return "unchanged" if hasher.hexdigest() == digest else "changed"


def build_report(
    provider_result: ProviderLoadResult | None = None,
    artifact_result: ArtifactGenerationResult | None = None,
    *,
    dist_dir: Path | None = None,
    fatal_error: str | None = None,
    extra_issues: tuple[ConversionIssue, ...] = (),
    ruleset_metadata: Mapping[str, RemoteMetadata] | None = None,
) -> dict[str, Any]:
    provider_result = provider_result or ProviderLoadResult({}, {})
    artifact_result = artifact_result or ArtifactGenerationResult(())
    issues = list(dict.fromkeys([*extra_issues, *artifact_result.issues]))
    providers: list[dict[str, Any]] = []
    for name, nodes in provider_result.providers.items():
        provider_issues = list(provider_result.issues.get(name, ()))
        provider_summary = provider_result.summaries.get(name)
        providers.append(
            {
                "name": name,
                "node_count": len(nodes),
                "parsed_nodes": (
                    provider_summary.parsed_nodes
                    if provider_summary is not None
                    else len(nodes)
                ),
                "content_sha256": (
                    provider_summary.content_sha256
                    if provider_summary is not None
                    else None
                ),
                "issue_counts": _issue_counts(provider_issues),
                "issue_codes": sorted({issue.code for issue in provider_issues}),
            }
        )
        for issue in provider_issues:
            if issue not in issues:
                issues.append(issue)

        metadata = provider_result.metadata.get(name)
        if metadata is not None:
            providers[-1]["remote"] = {
                "state": metadata.state,
                "etag": bool(metadata.etag),
                "last_modified": bool(metadata.last_modified),
                "content_length": metadata.content_length,
                "subscription_user_info": dict(
                    metadata.subscription_user_info or {}
                ),
            }
            if metadata.state == "stale":
                issues.append(_stale_issue("provider", name))

    rulesets = []
    for name, metadata in (ruleset_metadata or {}).items():
        rulesets.append(
            {
                "name": name,
                "state": metadata.state,
                "etag": bool(metadata.etag),
                "last_modified": bool(metadata.last_modified),
                "content_length": metadata.content_length,
            }
        )
        if metadata.state == "stale":
            issues.append(_stale_issue("ruleset", name))

    artifacts = [
        {
            "name": summary.name,
            "type": summary.artifact_type,
            "filename": summary.filename,
            "user": summary.user,
            "input_nodes": summary.input_nodes,
            "supported_nodes": summary.supported_nodes,
            "bytes": summary.content_bytes,
            "sha256": summary.content_sha256,
            "dist_status": _dist_status(
                dist_dir, summary.filename, summary.content_sha256
            ),
            "issue_codes": list(summary.issue_codes),
        }
        for summary in artifact_result.summaries
    ]
    all_errors = [
        issue for issue in issues if issue.severity == IssueSeverity.ERROR
    ]
    report: dict[str, Any] = {
        "version": 1,
        "status": "error" if fatal_error or all_errors else "ok",
        "summary": {
            "provider_count": len(providers),
            "artifact_count": len(artifacts),
            "issue_counts": _issue_counts(issues),
        },
        "providers": providers,
        "rulesets": rulesets,
        "artifacts": artifacts,
        "issues": [_issue_dict(issue) for issue in issues],
    }
    if dist_dir is not None:
        previous = read_manifest(dist_dir)
        if previous is not None:
            managed = set(previous.get("artifacts", {}))
            current = {artifact["filename"] for artifact in artifacts}
            report["orphan_files"] = sorted(managed - current - {MANIFEST_NAME})
        else:
            report["orphan_files"] = []
    if fatal_error:
        report["error"] = fatal_error
    return report


def _stale_issue(kind: str, name: str) -> ConversionIssue:
    return ConversionIssue(
        severity=IssueSeverity.WARNING,
        node=None,
        protocol=None,
        source=name,
        target=None,
        field=None,
        message=f"Using stale cached {kind} resource after the request failed",
        stage="remote",
        code="remote.stale-cache",
    )


def render_report(report: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    lines = [
        f"status: {report['status']}",
        "summary: "
        + json.dumps(report["summary"], ensure_ascii=False, sort_keys=True),
    ]
    if report.get("error"):
        lines.append(f"error: {report['error']}")
    for provider in report["providers"]:
        lines.append(
            f"provider {provider['name']}: {provider['node_count']} nodes"
        )
    for artifact in report["artifacts"]:
        lines.append(
            f"artifact {artifact['filename']}: "
            f"{artifact['supported_nodes']}/{artifact['input_nodes']} nodes, "
            f"{artifact['dist_status']}, sha256:{artifact['sha256'][:12]}"
        )
    if report.get("orphan_files"):
        lines.append("orphan files: " + ", ".join(report["orphan_files"]))
    for issue in report["issues"]:
        location = issue.get("artifact") or issue.get("source") or issue.get("node")
        prefix = f"{location}: " if location else ""
        lines.append(
            f"{issue['severity']} {issue['code']}: {prefix}{issue['message']}"
        )
    return "\n".join(lines) + "\n"
