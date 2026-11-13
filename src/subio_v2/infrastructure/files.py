import os
import tempfile
from collections.abc import Iterable
from pathlib import Path


def set_private_permissions(fd: int, temporary_path: str) -> None:
    """Set permissions on a newly created temporary file."""
    if hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)
    else:
        os.chmod(temporary_path, 0o600)


def filename_aliases(directory: Path, names: Iterable[str]) -> dict[str, str]:
    """Resolve filename equivalence with exclusive creates on the target filesystem."""
    aliases = {}
    representatives = {}
    with tempfile.TemporaryDirectory(prefix=".subio-names-", dir=directory) as probe:
        for name in names:
            path = Path(probe) / name
            if not name or name in {".", ".."} or path.parent != Path(probe):
                raise ValueError("Expected a single filename")
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
            info = path.stat()
            identity = (info.st_dev, info.st_ino)
            aliases[name] = representatives.setdefault(identity, name)
    return aliases
