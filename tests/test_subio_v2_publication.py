from pathlib import Path

import pytest

from subio_v2.core.errors import ArtifactGenerationError
from subio_v2.workflow.artifacts import ArtifactDraft
from subio_v2.workflow.publication import ArtifactPublisher


@pytest.mark.parametrize("failure", ["write", "flush", "fsync"])
def test_failed_preparation_cleans_current_and_previous_temporary_files(
    tmp_path, monkeypatch, failure
):
    monkeypatch.chdir(tmp_path)
    dist = Path("dist")
    dist.mkdir()
    (dist / "first.yaml").write_text("old-first")
    (dist / "second.yaml").write_text("old-second")
    import subio_v2.workflow.publication as publication

    original_fdopen = publication.os.fdopen
    original_fsync = publication.os.fsync
    opened = 0
    synced = 0

    class FailingOutput:
        def __init__(self, output):
            self.output = output

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.output.close()

        def write(self, content):
            self.output.write(content)
            if failure == "write":
                raise OSError("injected write failure")

        def flush(self):
            self.output.flush()
            if failure == "flush":
                raise OSError("injected flush failure")

        def fileno(self):
            return self.output.fileno()

    def fdopen(*args, **kwargs):
        nonlocal opened
        opened += 1
        output = original_fdopen(*args, **kwargs)
        return FailingOutput(output) if opened == 2 else output

    def fsync(fd):
        nonlocal synced
        synced += 1
        if failure == "fsync" and synced == 2:
            raise OSError("injected fsync failure")
        return original_fsync(fd)

    monkeypatch.setattr(publication.os, "fdopen", fdopen)
    monkeypatch.setattr(publication.os, "fsync", fsync)
    with pytest.raises(ArtifactGenerationError, match="injected"):
        ArtifactPublisher().commit((
            ArtifactDraft("first.yaml", "new-first"),
            ArtifactDraft("second.yaml", "synthetic-credential"),
        ))

    assert {path.name for path in dist.iterdir()} == {"first.yaml", "second.yaml"}
    assert (dist / "first.yaml").read_text() == "old-first"
    assert (dist / "second.yaml").read_text() == "old-second"
