"""Configuration loader for SubIO2."""
import os
import json
import json5
import toml
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from dacite import from_dict
from ..models.config import Config, Provider, Artifact, Ruleset, UploaderConfig, FilterConfig, Options, RenameRule, UploadTarget


class ConfigLoader:
    """Load and parse configuration files."""
    
    @staticmethod
    def load_file(file_path: Path) -> Dict[str, Any]:
        """Load configuration from file."""
        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        
        content = file_path.read_text(encoding='utf-8')
        suffix = file_path.suffix.lower()
        
        if suffix == '.toml':
            return toml.loads(content)
        elif suffix in ['.yaml', '.yml']:
            return yaml.safe_load(content)
        elif suffix == '.json':
            return json.loads(content)
        elif suffix == '.json5':
            return json5.loads(content)
        else:
            raise ValueError(f"Unsupported configuration format: {suffix}")
    
    @staticmethod
    def replace_env_vars(data: Any) -> Any:
        """Recursively replace environment variables in configuration."""
        if isinstance(data, str):
            if data.startswith("ENV_"):
                env_var = data[4:]  # Remove ENV_ prefix
                return os.environ.get(env_var, data)
            return data
        elif isinstance(data, dict):
            return {k: ConfigLoader.replace_env_vars(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [ConfigLoader.replace_env_vars(item) for item in data]
        return data
    
    @staticmethod
    def load_config(file_path: Optional[str] = None) -> Config:
        """Load configuration from file or auto-detect."""
        if file_path:
            path = Path(file_path)
        else:
            # Auto-detect configuration file
            for name in ['config.toml', 'config.yaml', 'config.yml', 'config.json', 'config.json5']:
                path = Path(name)
                if path.exists():
                    break
            else:
                raise FileNotFoundError("No configuration file found")
        
        # Load raw data
        data = ConfigLoader.load_file(path)
        
        # Replace environment variables
        data = ConfigLoader.replace_env_vars(data)
        
        # Parse into config object
        return ConfigLoader.parse_config(data)
    
    @staticmethod
    def parse_config(data: Dict[str, Any]) -> Config:
        """Parse configuration data into Config object."""
        # Parse providers
        providers = []
        for provider_data in data.get('provider', []):
            if 'rename' in provider_data:
                provider_data['rename'] = from_dict(RenameRule, provider_data['rename'])
            providers.append(from_dict(Provider, provider_data))
        
        # Parse artifacts
        artifacts = []
        for artifact_data in data.get('artifact', []):
            if 'upload' in artifact_data:
                upload_targets = []
                for upload_data in artifact_data['upload']:
                    upload_targets.append(from_dict(UploadTarget, upload_data))
                artifact_data['upload'] = upload_targets
            artifacts.append(from_dict(Artifact, artifact_data))
        
        # Parse uploaders
        uploaders = []
        for uploader_data in data.get('uploader', []):
            # Extract name and type, put rest in config
            name = uploader_data.pop('name')
            type_ = uploader_data.pop('type')
            uploaders.append(UploaderConfig(name=name, type=type_, config=uploader_data))
        
        # Parse rulesets
        rulesets = [from_dict(Ruleset, rs) for rs in data.get('ruleset', [])]
        
        # Parse filter
        filter_config = None
        if 'filter' in data:
            filter_config = from_dict(FilterConfig, data['filter'])
        
        # Parse options
        options = None
        if 'options' in data:
            options_data = data['options']
            work_filter = options_data.pop('work_filter', None)
            options = Options(work_filter=work_filter, extra=options_data)
        
        return Config(
            log_level=data.get('log_level', 'INFO'),
            options=options,
            filter=filter_config,
            uploaders=uploaders,
            providers=providers,
            artifacts=artifacts,
            rulesets=rulesets
        )