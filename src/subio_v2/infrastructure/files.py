import os


def set_private_permissions(fd: int, temporary_path: str) -> None:
    """Set permissions on a newly created temporary file."""
    if hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)
    else:
        os.chmod(temporary_path, 0o600)
