"""Main entry point for SubIO2."""
import sys
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests

from .core.config import ConfigLoader
from .core.registry import parser_registry, renderer_registry, filter_registry, uploader_registry
from .models import Node
from .models.config import Config, Provider, Artifact
from .filters import all_filters

# Import all parsers and renderers to register them
from . import parsers
from . import renderers


class SubIO2:
    """Main application class."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize SubIO2 with configuration."""
        self.config = ConfigLoader.load_config(config_path)
        self._setup_logging()
        self.logger = logging.getLogger('SubIO2')
        
        # Set working directory to config file's directory
        if config_path:
            self.work_dir = Path(config_path).parent
        else:
            self.work_dir = Path.cwd()
        
        # Storage for loaded content
        self._rulesets: Dict[str, str] = {}
        self._providers_nodes: Dict[str, List[Node]] = {}
    
    def _setup_logging(self):
        """Setup logging configuration."""
        level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def run(self):
        """Run the main conversion process."""
        try:
            # Load rulesets
            self._load_rulesets()
            
            # Process providers
            self._process_providers()
            
            # Process artifacts
            self._process_artifacts()
            
            self.logger.info("SubIO2 completed successfully")
        except Exception as e:
            self.logger.error(f"Error: {e}")
            sys.exit(1)
    
    def _load_rulesets(self):
        """Load all rulesets."""
        for ruleset in self.config.rulesets:
            self.logger.info(f"Loading ruleset: {ruleset.name}")
            try:
                response = requests.get(ruleset.url, timeout=30)
                response.raise_for_status()
                self._rulesets[ruleset.name] = response.text
            except Exception as e:
                self.logger.warning(f"Failed to load ruleset {ruleset.name}: {e}")
    
    def _process_providers(self):
        """Process all providers to load nodes."""
        for provider in self.config.providers:
            self.logger.info(f"Processing provider: {provider.name}")
            try:
                nodes = self._load_provider_nodes(provider)
                
                # Apply rename rules
                if provider.rename:
                    nodes = self._apply_rename_rules(nodes, provider.rename)
                
                # Apply privacy endpoint
                if provider.privacy_endpoint:
                    nodes = self._apply_privacy_endpoint(nodes, provider.privacy_endpoint)
                
                self._providers_nodes[provider.name] = nodes
                self.logger.info(f"Loaded {len(nodes)} nodes from {provider.name}")
            except Exception as e:
                self.logger.error(f"Failed to process provider {provider.name}: {e}")
                self._providers_nodes[provider.name] = []
    
    def _load_provider_nodes(self, provider: Provider) -> List[Node]:
        """Load nodes from a provider."""
        # Get content
        if provider.file:
            # Try to find file in provider directory first
            provider_dir = self.work_dir / 'provider'
            file_path = provider_dir / provider.file if provider_dir.exists() else self.work_dir / provider.file
            content = file_path.read_text(encoding='utf-8')
        elif provider.url:
            response = requests.get(provider.url, timeout=30)
            response.raise_for_status()
            content = response.text
        else:
            raise ValueError("Provider must have either file or url")
        
        # Get parser
        parser = parser_registry.create(provider.type)
        if not parser:
            raise ValueError(f"No parser found for type: {provider.type}")
        
        # Parse nodes
        return parser.parse(content)
    
    def _apply_rename_rules(self, nodes: List[Node], rename_rule) -> List[Node]:
        """Apply rename rules to nodes."""
        for node in nodes:
            # Add prefix/suffix
            if rename_rule.add_prefix:
                node.name = rename_rule.add_prefix + node.name
            if rename_rule.add_suffix:
                node.name = node.name + rename_rule.add_suffix
            
            # Apply replacements
            for replace in rename_rule.replace:
                node.name = node.name.replace(replace['old'], replace['new'])
        
        return nodes
    
    def _apply_privacy_endpoint(self, nodes: List[Node], endpoint: str) -> List[Node]:
        """Apply privacy endpoint to nodes."""
        # Find the endpoint node
        endpoint_node = None
        for node in nodes:
            if node.name == endpoint:
                endpoint_node = node
                break
        
        if not endpoint_node:
            self.logger.warning(f"Privacy endpoint '{endpoint}' not found")
            return nodes
        
        # Apply endpoint to all nodes
        result_nodes = []
        for node in nodes:
            if node == endpoint_node:
                # Keep the endpoint node as is
                result_nodes.append(node)
            else:
                # Create a new node with privacy endpoint
                from .models.node import CompositeNode
                if isinstance(node, CompositeNode):
                    # Clone the node and add dialer-proxy
                    node_dict = node.to_dict()
                    node_dict['dialer-proxy'] = endpoint
                    # Update the name to show the chain
                    node_dict['name'] = f"{endpoint} -> {node.name}"
                    new_node = CompositeNode.from_dict(node_dict)
                    result_nodes.append(new_node)
                else:
                    # For old-style nodes
                    node.extra_fields['dialer-proxy'] = endpoint
                    node.name = f"{endpoint} -> {node.name}"
                    result_nodes.append(node)
        
        return result_nodes
    
    def _process_artifacts(self):
        """Process all artifacts."""
        for artifact in self.config.artifacts:
            self.logger.info(f"Processing artifact: {artifact.name}")
            try:
                # Collect nodes from specified providers
                all_nodes = []
                for provider_name in artifact.providers:
                    nodes = self._providers_nodes.get(provider_name, [])
                    all_nodes.extend(nodes)
                
                # Apply filters
                filtered_nodes = self._apply_filters(all_nodes, artifact)
                
                # Get renderer
                renderer = renderer_registry.create(
                    artifact.type,
                    template_dir=str(self.work_dir / 'template'),
                    snippet_dir=str(self.work_dir / 'snippet')
                )
                if not renderer:
                    raise ValueError(f"No renderer found for type: {artifact.type}")
                
                # Set rulesets for the renderer
                renderer.set_rulesets(self._rulesets)
                
                # Merge options: artifact options override global options
                merged_options = {}
                if self.config.options:
                    if hasattr(self.config.options, '__dict__'):
                        merged_options.update(self.config.options.__dict__)
                    else:
                        merged_options.update(self.config.options)
                if artifact.options:
                    if hasattr(artifact.options, '__dict__'):
                        merged_options.update(artifact.options.__dict__)
                    else:
                        merged_options.update(artifact.options)
                
                # Prepare context
                context = {
                    'artifact': artifact,
                    'options': merged_options,
                    'global_options': merged_options,  # For v1 compatibility
                    'rulesets': self._rulesets,
                    'config': self.config
                }
                
                # Render content
                content = renderer.render(filtered_nodes, artifact.template, context)
                
                # Save to file
                output_path = self.work_dir / 'dist-subio2' / artifact.name
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(content, encoding='utf-8')
                self.logger.info(f"Saved artifact to: {output_path}")
                
                # Upload if configured
                for upload_target in artifact.upload:
                    self._upload_artifact(content, artifact.name, upload_target)
                
            except Exception as e:
                self.logger.error(f"Failed to process artifact {artifact.name}: {e}")
    
    def _apply_filters(self, nodes: List[Node], artifact: Artifact) -> List[Node]:
        """Apply filters to nodes."""
        import re
        
        filtered = nodes
        
        # Use artifact filters if available, otherwise fall back to global filters
        filters = artifact.filters if artifact.filters else (
            {'include': self.config.filter.include, 'exclude': self.config.filter.exclude} 
            if self.config.filter else None
        )
        
        if filters:
            # Apply include filter
            if filters.get('include'):
                include_pattern = re.compile(filters['include'], re.IGNORECASE)
                filtered = [n for n in filtered if include_pattern.search(n.name)]
            
            # Apply exclude filter
            if filters.get('exclude'):
                exclude_pattern = re.compile(filters['exclude'], re.IGNORECASE)
                filtered = [n for n in filtered if not exclude_pattern.search(n.name)]
        
        # Note: work_filter should be handled by templates through options.work and global_options.work_filter
        # v1 doesn't implement work_filter in code, leaving it to templates
        
        return filtered
    
    def _upload_artifact(self, content: str, filename: str, upload_target):
        """Upload artifact to target."""
        # Find uploader config
        uploader_config = None
        for uploader in self.config.uploaders:
            if uploader.name == upload_target.to:
                uploader_config = uploader
                break
        
        if not uploader_config:
            self.logger.warning(f"Uploader '{upload_target.to}' not found")
            return
        
        # Get uploader
        uploader = uploader_registry.create(uploader_config.type)
        if not uploader:
            self.logger.warning(f"No uploader found for type: {uploader_config.type}")
            return
        
        # Upload
        try:
            upload_filename = upload_target.file_name or filename
            result = uploader.upload(content, upload_filename, uploader_config.config)
            if result:
                self.logger.info(f"Uploaded {filename} to {upload_target.to}: {result}")
        except Exception as e:
            self.logger.error(f"Failed to upload {filename}: {e}")


def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='SubIO2 - Subscription Converter')
    parser.add_argument('-c', '--config', help='Configuration file path')
    args = parser.parse_args()
    
    app = SubIO2(args.config)
    app.run()


if __name__ == '__main__':
    main()