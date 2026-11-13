import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from subio_v2.core.errors import ArtifactGenerationError
from subio_v2.infrastructure.files import set_private_permissions
from subio_v2.workflow.artifacts import ArtifactDraft


class ArtifactPublisher:
    def commit(self, drafts: Iterable[ArtifactDraft]) -> None:
        dist_dir = Path("dist").resolve()
        dist_dir.mkdir(parents=True, exist_ok=True)
        prepared: list[tuple[str, Path]] = []

        try:
            for draft in drafts:
                filename, content = draft.filename, draft.content
                target = dist_dir / filename
                if target.parent != dist_dir:
                    raise ArtifactGenerationError(
                        f"Artifact path escapes dist directory: {filename!r}"
                    )
                fd, temp_name = tempfile.mkstemp(
                    prefix=".subio-artifact-", suffix=".tmp", dir=dist_dir
                )
                prepared.append((temp_name, target))
                with os.fdopen(fd, "w", encoding="utf-8") as output:
                    set_private_permissions(output.fileno(), temp_name)
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())

            for temp_name, target in prepared:
                os.replace(temp_name, target)
            prepared.clear()
        except ArtifactGenerationError:
            raise
        except Exception as exc:
            raise ArtifactGenerationError(
                f"Failed to write generated artifacts: {exc}"
            ) from exc
        finally:
            for temp_name, _ in prepared:
                try:
                    os.unlink(temp_name)
                except FileNotFoundError:
                    pass
