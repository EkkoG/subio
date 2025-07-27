"""GitHub Gist uploader."""
import json
from typing import Dict, Any, Optional
import requests
from ..core.interfaces import Uploader
from ..core.registry import uploader_registry


@uploader_registry.decorator('gist')
class GistUploader(Uploader):
    """Upload files to GitHub Gist."""
    
    def supports_type(self, upload_type: str) -> bool:
        """Check if this uploader supports the given type."""
        return upload_type == 'gist'
    
    def upload(self, content: str, filename: str, config: Dict[str, Any]) -> Optional[str]:
        """Upload content to GitHub Gist."""
        token = config.get('token')
        gist_id = config.get('id')
        
        if not token:
            raise ValueError("GitHub token is required for Gist upload")
        
        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        data = {
            'files': {
                filename: {
                    'content': content
                }
            }
        }
        
        if gist_id:
            # Update existing gist
            url = f'https://api.github.com/gists/{gist_id}'
            response = requests.patch(url, headers=headers, json=data)
        else:
            # Create new gist
            url = 'https://api.github.com/gists'
            data['public'] = config.get('public', False)
            data['description'] = config.get('description', 'SubIO2 generated file')
            response = requests.post(url, headers=headers, json=data)
        
        response.raise_for_status()
        
        # Return the raw URL for the file
        gist_data = response.json()
        file_data = gist_data['files'].get(filename)
        if file_data:
            return file_data.get('raw_url')
        
        return None