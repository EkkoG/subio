import os
import subprocess
import tempfile
from typing import Any, Dict, List

def upload(content: str, artifact_config: Dict[str, Any], uploader_configs: List[Dict[str, Any]]):
    upload_list = artifact_config.get("upload", [])
    if not upload_list:
        return

    for upload_item in upload_list:
        uploader_name = upload_item.get("to")
        if not uploader_name:
            print(f"  [Upload] Error: 'to' not specified in artifact {artifact_config.get('name')}")
            continue

        # Find uploader config
        uploader = next((u for u in uploader_configs if u.get("name") == uploader_name), None)
        if not uploader:
            print(f"  [Upload] Error: Uploader '{uploader_name}' not found")
            continue
            
        if uploader.get("type") == "gist":
            _upload_to_gist(content, artifact_config, upload_item, uploader)
        else:
            print(f"  [Upload] Unsupported uploader type: {uploader.get('type')}")


def _upload_to_gist(content: str, artifact_config: Dict[str, Any], upload_item: Dict[str, Any], uploader: Dict[str, Any]):
    # Resolve Token
    token = uploader.get("token", "")
    if token.startswith("ENV_"):
        env_var = token[4:]
        token = os.getenv(env_var)
        if not token:
            print(f"  [Upload] Error: Environment variable {env_var} not found")
            return
    
    gist_id = uploader.get("id")
    if not gist_id:
        print("  [Upload] Error: Gist ID missing")
        return
        
    # Validate gist_id
    if not gist_id.replace("-", "").replace("_", "").isalnum():
         print(f"  [Upload] Invalid gist ID: {gist_id}")
         return

    file_name = upload_item.get("file_name") or artifact_config.get("name")
    # Validate filename
    safe_filename = os.path.basename(file_name)
    if safe_filename != file_name or ".." in safe_filename:
        print(f"  [Upload] Invalid filename: {file_name}")
        return

    print(f"  [Upload] Uploading {safe_filename} to Gist {gist_id}...")

    # Use git operations
    temp_base = tempfile.mkdtemp(prefix="subio-v2-gist-")
    repo_dir = os.path.join(temp_base, gist_id)
    
    try:
        clone_url = f"https://{token}@gist.github.com/{gist_id}.git"
        
        # Clone
        subprocess.run(["git", "clone", clone_url, repo_dir], check=True, capture_output=True)
        
        # Write file
        file_path = os.path.join(repo_dir, safe_filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
            
        # Git add
        subprocess.run(["git", "-C", repo_dir, "add", "."], check=True, capture_output=True)
        
        # Check diff
        result = subprocess.run(
            ["git", "-C", repo_dir, "diff", "--cached", "--quiet"],
            capture_output=True
        )
        
        if result.returncode != 0:
            # Commit
            subprocess.run(
                ["git", "-C", repo_dir, "commit", "-m", f"update {safe_filename}"],
                check=True, capture_output=True
            )
            # Push
            subprocess.run(
                ["git", "-C", repo_dir, "push"],
                check=True, capture_output=True
            )
            print(f"  [Upload] Success: {safe_filename} updated.")
        else:
            print(f"  [Upload] No changes for {safe_filename}.")

    except subprocess.CalledProcessError as e:
        print(f"  [Upload] Git Error: {e}")
        if e.stderr:
            print(f"  [Upload] Stderr: {e.stderr.decode()}")
    except Exception as e:
        print(f"  [Upload] Error: {e}")
    finally:
        # Cleanup temp dir? 
        # Ideally yes, using shutil.rmtree
        import shutil
        if os.path.exists(temp_base):
            shutil.rmtree(temp_base, ignore_errors=True)

