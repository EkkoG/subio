import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List
from subio_v2.utils.logger import logger


class GistBatchUploader:
    """Batch uploader for Gist - collects files and uploads them in one git operation."""

    def __init__(self):
        # Structure: {gist_id: {"token": token, "files": {filename: content}}}
        self._pending: Dict[str, Dict[str, Any]] = {}

    def add(
        self,
        content: str,
        artifact_config: Dict[str, Any],
        upload_item: Dict[str, Any],
        uploader: Dict[str, Any],
        username: str = None,
    ):
        """Add a file to the pending upload queue."""
        # Resolve Token
        token = uploader.get("token", "")
        if token.startswith("ENV_"):
            env_var = token[4:]
            token = os.getenv(env_var)
            if not token:
                logger.error(f"[Upload] Environment variable {env_var} not found")
                return

        gist_id = uploader.get("id")
        if not gist_id:
            logger.error("[Upload] Gist ID missing")
            return

        # Validate gist_id
        if not gist_id.replace("-", "").replace("_", "").isalnum():
            logger.error(f"[Upload] Invalid gist ID: {gist_id}")
            return

        file_name = upload_item.get("file_name") or artifact_config.get("name")
        
        # Replace {user} placeholder if username is provided
        if username:
            file_name = file_name.replace("{user}", username)
        
        # Validate filename
        safe_filename = os.path.basename(file_name)
        if safe_filename != file_name or ".." in safe_filename:
            logger.error(f"[Upload] Invalid filename: {file_name}")
            return

        # Add to pending
        if gist_id not in self._pending:
            self._pending[gist_id] = {"token": token, "files": {}}

        self._pending[gist_id]["files"][safe_filename] = content
        logger.dim(f"[Upload] Queued {safe_filename} for Gist {gist_id}")

    def flush(self):
        """Upload all pending files to their respective gists."""
        if not self._pending:
            return

        for gist_id, data in self._pending.items():
            self._upload_batch(gist_id, data["token"], data["files"])

        self._pending.clear()

    def _upload_batch(self, gist_id: str, token: str, files: Dict[str, str]):
        """Upload multiple files to a single gist in one git operation."""
        if not files:
            return

        file_names = list(files.keys())
        logger.step(
            f"Uploading [bold]{len(files)}[/bold] file(s) to Gist {gist_id}: {', '.join(file_names)}"
        )

        temp_base = tempfile.mkdtemp(prefix="subio-v2-gist-")
        repo_dir = os.path.join(temp_base, gist_id)

        try:
            clone_url = f"https://{token}@gist.github.com/{gist_id}.git"

            # Clone
            subprocess.run(
                ["git", "clone", clone_url, repo_dir], check=True, capture_output=True
            )

            # Write all files
            for filename, content in files.items():
                file_path = os.path.join(repo_dir, filename)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(content)

            # Git add all
            subprocess.run(
                ["git", "-C", repo_dir, "add", "."], check=True, capture_output=True
            )

            # Check diff
            result = subprocess.run(
                ["git", "-C", repo_dir, "diff", "--cached", "--quiet"],
                capture_output=True,
            )

            if result.returncode != 0:
                # Commit with all filenames
                commit_msg = f"update {', '.join(file_names)}"
                subprocess.run(
                    ["git", "-C", repo_dir, "commit", "-m", commit_msg],
                    check=True,
                    capture_output=True,
                )
                # Push
                subprocess.run(
                    ["git", "-C", repo_dir, "push"], check=True, capture_output=True
                )
                logger.success(f"[Upload] {len(files)} file(s) updated in Gist {gist_id}")
            else:
                logger.dim(f"[Upload] No changes for Gist {gist_id}")

        except subprocess.CalledProcessError as e:
            logger.error(f"[Upload] Git Error: {e}")
            if e.stderr:
                logger.error(f"[Upload] Stderr: {e.stderr.decode()}")
        except Exception as e:
            logger.error(f"[Upload] Error: {e}")
        finally:
            if os.path.exists(temp_base):
                shutil.rmtree(temp_base, ignore_errors=True)


# Global batch uploader instance
_gist_batch_uploader: GistBatchUploader | None = None


def get_gist_batch_uploader() -> GistBatchUploader:
    """Get or create the global GistBatchUploader instance."""
    global _gist_batch_uploader
    if _gist_batch_uploader is None:
        _gist_batch_uploader = GistBatchUploader()
    return _gist_batch_uploader


def flush_uploads():
    """Flush all pending uploads."""
    global _gist_batch_uploader
    if _gist_batch_uploader:
        _gist_batch_uploader.flush()
        _gist_batch_uploader = None


def upload(
    content: str,
    artifact_config: Dict[str, Any],
    uploader_configs: List[Dict[str, Any]],
    username: str = None,
):
    """Queue files for upload (will be uploaded when flush_uploads is called)."""
    upload_list = artifact_config.get("upload", [])
    if not upload_list:
        return

    for upload_item in upload_list:
        uploader_name = upload_item.get("to")
        if not uploader_name:
            logger.error(
                f"[Upload] 'to' not specified in artifact {artifact_config.get('name')}"
            )
            continue

        # Find uploader config
        uploader = next(
            (u for u in uploader_configs if u.get("name") == uploader_name), None
        )
        if not uploader:
            logger.error(f"[Upload] Uploader '{uploader_name}' not found")
            continue

        if uploader.get("type") == "gist":
            # Add to batch uploader instead of uploading immediately
            batch_uploader = get_gist_batch_uploader()
            batch_uploader.add(content, artifact_config, upload_item, uploader, username)
        else:
            logger.error(f"[Upload] Unsupported uploader type: {uploader.get('type')}")
