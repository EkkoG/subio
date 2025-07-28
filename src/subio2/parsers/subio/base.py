"""SubIO native format parser."""
import toml
import yaml
import json
import json5
from typing import List, Dict, Any
from ...core.registry import parser_registry
from ...models.node import Proxy
from ..base import BaseParser
from .protocols import parse_node


@parser_registry.decorator('subio')
class SubIOParser(BaseParser):
    """Parser for SubIO native format (TOML/YAML/JSON)."""
    
    def parse(self, content: str) -> List[Proxy]:
        """Parse SubIO native format."""
        try:
            # Try to detect format
            data = self._parse_content(content)
            
            if not isinstance(data, dict):
                return []
            
            # SubIO format has 'nodes' key
            nodes_data = data.get('nodes', [])
            nodes = []
            
            for node_data in nodes_data:
                node = parse_node(node_data)
                if node:
                    nodes.append(node)
            
            return nodes
        except Exception as e:
            print(f"Error parsing SubIO content: {e}")
            return []
    
    def _parse_content(self, content: str) -> Dict[str, Any]:
        """Try to parse content in different formats."""
        # Try TOML first
        try:
            return toml.loads(content)
        except:
            pass
        
        # Try YAML
        try:
            return yaml.safe_load(content)
        except:
            pass
        
        # Try JSON5
        try:
            return json5.loads(content)
        except:
            pass
        
        # Try JSON
        try:
            return json.loads(content)
        except:
            pass
        
        raise ValueError("Unable to parse content as TOML, YAML, JSON5 or JSON")