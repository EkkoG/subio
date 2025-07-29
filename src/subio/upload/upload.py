import requests
from subio.log.log import logger
from subio.config.model import Artifact, Uploader
import os
import subprocess
import tempfile


def upload(content: str, artifact: Artifact, uploaders: Uploader):
    if artifact.upload and len(artifact.upload) > 0:
        for upload_info in artifact.upload:
            uploader = list(
                filter(lambda uploader: uploader.name == upload_info.to, uploaders)
            )
            if len(uploader) == 0:
                logger.error(
                    f"artifact {artifact.name} 没有找到上传器 {upload_info.to}"
                )
                continue
            if len(uploader) > 1:
                logger.error(f"artifact {artifact.name} 有多个上传器 {upload_info.to}")
                continue
            if uploader[0].type == "gist":
                if upload_info.file_name is None or len(upload_info.file_name) == 0:
                    upload_info.file_name = artifact.name

                # git clone https://gist.github.com/${id}.git gist_dist
                # cp -r dist/* gist_dist
                # cd gist_dist
                # git add .
                # git commit -m "update"
                # git push

                # Create secure temporary directory
                temp_base = tempfile.mkdtemp(prefix="subio-gist-")
                gist_id = uploader[0].id
                # Validate gist_id to prevent injection
                if not gist_id.replace("-", "").replace("_", "").isalnum():
                    logger.error(f"Invalid gist ID: {gist_id}")
                    continue

                dir = os.path.join(temp_base, gist_id)
                try:
                    if os.path.exists(dir):
                        subprocess.run(
                            ["git", "-C", dir, "pull"], check=True, capture_output=True
                        )
                    else:
                        clone_url = (
                            f"https://{uploader[0].token}@gist.github.com/{gist_id}.git"
                        )
                        subprocess.run(
                            ["git", "clone", clone_url, dir],
                            check=True,
                            capture_output=True,
                        )
                except subprocess.CalledProcessError as e:
                    logger.error(f"Git operation failed: {e}")
                    continue

                logger.info(f"开始上传 {upload_info.file_name} 到 {upload_info.to}")

                # Validate filename to prevent path traversal
                safe_filename = os.path.basename(upload_info.file_name)
                if safe_filename != upload_info.file_name or ".." in safe_filename:
                    logger.error(f"Invalid filename: {upload_info.file_name}")
                    continue

                file_path = os.path.join(dir, safe_filename)
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(content)

                    # Add files to git
                    subprocess.run(
                        ["git", "-C", dir, "add", "."], check=True, capture_output=True
                    )

                    # Check if there are changes
                    result = subprocess.run(
                        ["git", "-C", dir, "diff", "--cached", "--quiet"],
                        capture_output=True,
                    )
                    if result.returncode != 0:
                        # Commit changes
                        commit_msg = f"update {safe_filename}"
                        subprocess.run(
                            ["git", "-C", dir, "commit", "-m", commit_msg],
                            check=True,
                            capture_output=True,
                        )

                        # Push changes
                        subprocess.run(
                            ["git", "-C", dir, "push"], check=True, capture_output=True
                        )
                        logger.info(f"上传 {artifact.name} 到 {upload_info.to} 成功")
                    else:
                        logger.info(f"artifact {safe_filename} 没有变化，无需上传")

                except (subprocess.CalledProcessError, OSError) as e:
                    logger.error(f"上传 {artifact.name} 到 {upload_info.to} 失败: {e}")

                # logger.info(f"开始上传 {upload_info.file_name} 到 {upload_info.to}")
                # upload_info.description = "subio"
                # upload_info.content = content
                # upload_info.id = uploader[0].id
                # upload_info.token = uploader[0].token
                # success = upload_to_gist(upload_info)
                # if success:
                #     logger.info(f"上传 {artifact.name} 到 {upload_info.to} 成功")
                # else:
                #     logger.error(f"上传 {artifact.name} 到 {upload_info.to} 失败")
            else:
                logger.error(f"artifact {artifact.name} 不支持上传到 {upload_info.to}")
    else:
        logger.info(f"artifact {artifact.name} 没有配置上传或者配置错误")


def upload_to_gist(args):
    token = args.token
    if token.startswith("ENV_"):
        env_var = token[4:]  # Remove "ENV_" prefix
        token = os.getenv(env_var)
        if not token:
            logger.error(f"Environment variable {env_var} not found")
            return False
    resp = requests.patch(
        f"https://api.github.com/gists/{args.id}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        json={
            "description": args.description,
            "files": {
                args.file_name: {
                    "content": args.content,
                }
            },
        },
    )
    if resp.status_code == 200:
        return True
    logger.info(resp.text)
    return False
