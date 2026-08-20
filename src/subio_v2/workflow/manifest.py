"""Optional, privacy-safe manifest management for generated local artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from subio_v2.core.errors import ArtifactGenerationError
from subio_v2.workflow.artifacts import ArtifactSummary
from subio_v2.workflow.providers import ProviderSummary

MANIFEST_NAME = ".subio-manifest.json"
MANIFEST_VERSION = 1


def _safe_filename(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if value in {".", ".."} or value != os.path.basename(value):
        return None
    return value


def read_manifest(dist_dir: Path) -> dict[str, Any] | None:
    path = dist_dir / MANIFEST_NAME
    if not path.is_file() or path.is_symlink():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("version") != MANIFEST_VERSION:
        return None
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, dict):
        return None
    if any(_safe_filename(name) is None for name in artifacts):
        return None
    return data


def _config_digest(config_path: str) -> str:
    hasher = hashlib.sha256()
    with open(config_path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_manifest(
    config_path: str,
    summaries: tuple[ArtifactSummary, ...],
    provider_summaries: Mapping[str, ProviderSummary] | None = None,
) -> dict[str, Any]:
    return {
        "version": MANIFEST_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "config_sha256": _config_digest(config_path),
        "providers": {
            name: {
                "content_sha256": summary.content_sha256,
                "parsed_nodes": summary.parsed_nodes,
                "selected_nodes": summary.selected_nodes,
            }
            for name, summary in (provider_summaries or {}).items()
        },
        "artifacts": {
            summary.filename: {
                "name": summary.name,
                "type": summary.artifact_type,
                "user": summary.user,
                "bytes": summary.content_bytes,
                "sha256": summary.content_sha256,
                "input_nodes": summary.input_nodes,
                "supported_nodes": summary.supported_nodes,
                "issue_codes": list(summary.issue_codes),
            }
            for summary in summaries
        },
    }


def managed_orphans(
    dist_dir: Path,
    previous: dict[str, Any] | None,
    current_filenames: set[str],
) -> tuple[str, ...]:
    if previous is None:
        return ()
    artifacts = previous.get("artifacts", {})
    orphaned = sorted(set(artifacts) - current_filenames - {MANIFEST_NAME})
    for filename in orphaned:
        target = dist_dir / filename
        if (
            target.is_symlink()
            or target.is_dir()
            or target.resolve().parent != dist_dir.resolve()
        ):
            raise ArtifactGenerationError(
                f"Refusing to clean unsafe managed artifact path: {filename!r}"
            )
    return tuple(orphaned)


def write_manifest(dist_dir: Path, manifest: dict[str, Any]) -> None:
    dist_dir.mkdir(parents=True, exist_ok=True)
    target = dist_dir / MANIFEST_NAME
    fd, temporary = tempfile.mkstemp(
        prefix=f".{MANIFEST_NAME}.", suffix=".tmp", dir=dist_dir
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(manifest, output, ensure_ascii=False, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def apply_manifest(
    config_path: str,
    summaries: tuple[ArtifactSummary, ...],
    provider_summaries: Mapping[str, ProviderSummary] | None = None,
    *,
    dist_dir: Path,
    clean: bool,
) -> tuple[str, ...]:
    previous = read_manifest(dist_dir)
    current = {summary.filename for summary in summaries}
    orphaned = managed_orphans(dist_dir, previous, current) if clean else ()
    moved: list[tuple[Path, Path]] = []
    try:
        for filename in orphaned:
            target = dist_dir / filename
            if not target.exists():
                continue
            fd, temporary_name = tempfile.mkstemp(
                prefix=".subio-clean-", suffix=".tmp", dir=dist_dir
            )
            os.close(fd)
            temporary = Path(temporary_name)
            temporary.unlink()
            os.replace(target, temporary)
            moved.append((temporary, target))
        write_manifest(
            dist_dir,
            build_manifest(config_path, summaries, provider_summaries),
        )
    except Exception:
        for temporary, target in reversed(moved):
            if temporary.exists() and not target.exists():
                os.replace(temporary, target)
        raise
    finally:
        for temporary, _ in moved:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return orphaned
