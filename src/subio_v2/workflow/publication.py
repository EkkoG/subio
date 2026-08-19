import os
import tempfile
from pathlib import Path

from subio_v2.errors import ArtifactGenerationError


class ArtifactPublisher:
    def commit(self, staged_artifacts: dict[str, str]) -> None:
        dist_dir = Path("dist").resolve()
        dist_dir.mkdir(parents=True, exist_ok=True)
        prepared: list[tuple[str, Path]] = []

        try:
            for filename, content in staged_artifacts.items():
                target = dist_dir / filename
                if target.parent != dist_dir:
                    raise ArtifactGenerationError(
                        f"Artifact path escapes dist directory: {filename!r}"
                    )
                fd, temp_name = tempfile.mkstemp(
                    prefix=f".{filename}.", suffix=".tmp", dir=dist_dir
                )
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as output:
                        output.write(content)
                        output.flush()
                        os.fsync(output.fileno())
                except Exception:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    raise
                prepared.append((temp_name, target))

            for temp_name, target in prepared:
                os.replace(temp_name, target)
            prepared.clear()
            staged_artifacts.clear()
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
