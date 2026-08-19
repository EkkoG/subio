import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List

from subio_v2.errors import UploadError
from subio_v2.utils.logger import logger

_GIST_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _redact(value: str, secret: str | None) -> str:
    if secret:
        return value.replace(secret, "***")
    return value


class GistBatchUploader:
    """Collect all files for a workflow run and upload each Gist once."""

    def __init__(self, dry_run: bool = False, clean_gist: bool = False):
        self._pending: Dict[str, Dict[str, Any]] = {}
        self.dry_run = dry_run
        self.clean_gist = clean_gist

    def begin(self) -> None:
        """Start a run with an empty queue."""
        self.reset()

    def reset(self) -> None:
        self._pending.clear()

    def abort(self) -> None:
        """Discard files queued by a failed run."""
        self.reset()

    def pending_uploads(self) -> list[str]:
        return [
            f"{gist_id}:{filename}"
            for gist_id, data in self._pending.items()
            for filename in data["files"]
        ]

    def add(
        self,
        content: str,
        artifact_config: Dict[str, Any],
        upload_item: Dict[str, Any],
        uploader: Dict[str, Any],
        username: str | None = None,
    ) -> None:
        token = uploader.get("token", "")
        if token.startswith("ENV_"):
            env_var = token[4:]
            token = os.getenv(env_var, "")
            if not token and not self.dry_run:
                raise UploadError(
                    f"Environment variable {env_var} required by uploader "
                    f"'{uploader.get('name', 'unknown')}' is not set"
                )
        elif not token and not self.dry_run:
            raise UploadError(
                f"Token required by uploader '{uploader.get('name', 'unknown')}' is missing"
            )

        gist_id = uploader.get("id")
        if not isinstance(gist_id, str) or not _GIST_ID_RE.fullmatch(gist_id):
            raise UploadError(f"Invalid Gist ID: {gist_id!r}")

        file_name = upload_item.get("file_name") or artifact_config.get("name")
        if username and isinstance(file_name, str):
            file_name = file_name.replace("{user}", username)
        if not isinstance(file_name, str) or not file_name:
            raise UploadError("Upload filename is missing")

        safe_filename = os.path.basename(file_name)
        if safe_filename != file_name or safe_filename in {".", ".."}:
            raise UploadError(f"Invalid upload filename: {file_name}")

        if gist_id not in self._pending:
            clean = self.clean_gist or bool(uploader.get("clean", False))
            self._pending[gist_id] = {"token": token, "files": {}, "clean": clean}

        pending = self._pending[gist_id]
        if pending["token"] != token:
            raise UploadError(f"Conflicting credentials configured for Gist {gist_id}")
        existing = pending["files"].get(safe_filename)
        if existing is not None and existing != content:
            raise UploadError(
                f"Multiple artifacts would overwrite '{safe_filename}' in Gist {gist_id}"
            )

        pending["files"][safe_filename] = content
        logger.dim(f"[Upload] Queued {safe_filename} for Gist {gist_id}")

    def flush(self) -> None:
        if not self._pending:
            return

        if self.dry_run:
            for gist_id, data in self._pending.items():
                names = ", ".join(data["files"])
                logger.info(
                    f"[Dry-run] Would upload {len(data['files'])} file(s) "
                    f"to Gist {gist_id}: {names}"
                )
            self.reset()
            return

        for gist_id, data in self._pending.items():
            self._upload_batch(
                gist_id, data["token"], data["files"], data.get("clean", False)
            )
        self.reset()

    @staticmethod
    def _git_env(askpass_path: str, token: str) -> Dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "GIT_ASKPASS": askpass_path,
                "GIT_TERMINAL_PROMPT": "0",
                "SUBIO_GIST_TOKEN": token,
            }
        )
        return env

    @staticmethod
    def _run_git(
        args: List[str], env: Dict[str, str], token: str, *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                args,
                check=check,
                capture_output=True,
                text=True,
                env=env,
            )
        except subprocess.CalledProcessError as exc:
            detail = _redact((exc.stderr or exc.stdout or str(exc)).strip(), token)
            raise UploadError(f"Git command failed: {detail}") from exc

    def _upload_batch(
        self, gist_id: str, token: str, files: Dict[str, str], clean: bool = False
    ) -> None:
        if not files:
            raise UploadError(f"Refusing to upload an empty file set to Gist {gist_id}")

        file_names = list(files)
        logger.step(
            f"Uploading [bold]{len(files)}[/bold] file(s) to Gist {gist_id}: "
            f"{', '.join(file_names)}"
        )

        temp_base = tempfile.mkdtemp(prefix="subio-v2-gist-")
        repo_dir = os.path.join(temp_base, gist_id)
        askpass_path = os.path.join(temp_base, "askpass.sh")

        try:
            with open(askpass_path, "w", encoding="ascii") as askpass:
                askpass.write(
                    "#!/bin/sh\n"
                    'case "$1" in\n'
                    "  *Username*) printf '%s\\n' oauth2 ;;\n"
                    "  *) printf '%s\\n' \"$SUBIO_GIST_TOKEN\" ;;\n"
                    "esac\n"
                )
            os.chmod(askpass_path, 0o700)
            git_env = self._git_env(askpass_path, token)
            clone_url = f"https://gist.github.com/{gist_id}.git"

            self._run_git(["git", "clone", clone_url, repo_dir], git_env, token)

            if clean:
                logger.dim(f"[Upload] Cleaning existing files in Gist {gist_id}")
                for item in os.listdir(repo_dir):
                    if item == ".git":
                        continue
                    item_path = os.path.join(repo_dir, item)
                    if os.path.isfile(item_path) or os.path.islink(item_path):
                        os.remove(item_path)
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)

            for filename, content in files.items():
                file_path = os.path.join(repo_dir, filename)
                with open(file_path, "w", encoding="utf-8") as output:
                    output.write(content)
                os.chmod(file_path, 0o600)

            self._run_git(["git", "-C", repo_dir, "add", "."], git_env, token)
            diff = self._run_git(
                ["git", "-C", repo_dir, "diff", "--cached", "--quiet"],
                git_env,
                token,
                check=False,
            )
            if diff.returncode == 0:
                logger.dim(f"[Upload] No changes for Gist {gist_id}")
                return
            if diff.returncode != 1:
                detail = _redact((diff.stderr or diff.stdout).strip(), token)
                raise UploadError(f"Unable to inspect Gist changes: {detail}")

            stat = self._run_git(
                ["git", "-C", repo_dir, "diff", "--cached", "--stat"],
                git_env,
                token,
            )
            if stat.stdout.strip():
                logger.dim(f"[Upload] Change summary: {stat.stdout.strip()}")

            commit_msg = f"update {', '.join(file_names)}"
            self._run_git(
                ["git", "-C", repo_dir, "commit", "-m", commit_msg],
                git_env,
                token,
            )
            self._run_git(["git", "-C", repo_dir, "push"], git_env, token)
            logger.success(f"[Upload] {len(files)} file(s) updated in Gist {gist_id}")
        finally:
            shutil.rmtree(temp_base, ignore_errors=True)


def upload(
    content: str,
    artifact_config: Dict[str, Any],
    uploader_configs: List[Dict[str, Any]],
    batch_uploader: GistBatchUploader,
    username: str | None = None,
) -> None:
    """Validate upload references and queue an artifact in the run-local uploader."""
    for upload_item in artifact_config.get("upload", []):
        uploader_name = upload_item.get("to")
        if not uploader_name:
            raise UploadError(
                f"Upload target is missing in artifact {artifact_config.get('name')!r}"
            )

        uploader = next(
            (item for item in uploader_configs if item.get("name") == uploader_name),
            None,
        )
        if not uploader:
            raise UploadError(f"Uploader {uploader_name!r} is not configured")
        if uploader.get("type") != "gist":
            raise UploadError(f"Unsupported uploader type: {uploader.get('type')!r}")

        batch_uploader.add(content, artifact_config, upload_item, uploader, username)
