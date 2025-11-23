import jinja2
import yaml
import json
import sys
from typing import Any, List, Dict
from subio_v2.utils.logger import logger
from subio_v2.workflow.filters import all_filters
import os

class TemplateRenderer:
    def __init__(self, template_dir: str):
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            undefined=jinja2.Undefined
        )
        self._register_base_filters()
        self._register_globals()

    def _register_base_filters(self):
        def render(value):
            if isinstance(value, list):
                return json.dumps(value, ensure_ascii=False)
            return str(value)
        
        def to_yaml_filter(value):
            return yaml.dump(value, allow_unicode=True, sort_keys=False).strip()
        
        self.env.filters['render'] = render
        self.env.filters['to_yaml'] = to_yaml_filter

    def _register_globals(self):
        self.env.globals['filter'] = all_filters

    def _get_render_filter(self, artifact_type: str):
        def default_render(value):
            if isinstance(value, list):
                return json.dumps(value, ensure_ascii=False)
            if not isinstance(value, str):
                return str(value)
            return value

        def clash_render(value):
            if isinstance(value, list):
                return json.dumps(value, ensure_ascii=False)
            if not isinstance(value, str):
                return str(value)
            
            # Process ruleset string for Clash
            lines = value.split("\n")
            filtered_lines = []
            for line in lines:
                line = line.strip()
                if not line: continue
                if line.startswith("#") or line.startswith("//"):
                    filtered_lines.append(line)
                    continue
                if "USER-AGENT" in line: continue
                if "IP-ASN" in line: continue
                
                # V1 logic: check no-resolve
                if ",no-resolve" in line:
                    line = line.replace(",no-resolve", "")
                
                filtered_lines.append(f"- {line}")
            
            return "\n".join(filtered_lines)

        if artifact_type in ["clash", "clash-meta", "stash"]:
            return clash_render
        return default_render

    def render(self, template_name: str, context: Dict[str, Any], macros: str = "", artifact_type: str = None) -> str:
        try:
            # Read template file directly
            template_path = os.path.join(self.env.loader.searchpath[0], template_name)
            if not os.path.exists(template_path):
                 raise FileNotFoundError(f"Template not found: {template_name}")

            with open(template_path, 'r', encoding='utf-8') as f:
                template_source = f.read()
            
            # Prepend macros
            full_source = f"{macros}\n{template_source}"
            
            original_render = self.env.filters['render']
            if artifact_type:
                self.env.filters['render'] = self._get_render_filter(artifact_type)
            
            try:
                template = self.env.from_string(full_source)
                return template.render(**context)
            finally:
                self.env.filters['render'] = original_render

        except FileNotFoundError as e:
            logger.error(f"Template error: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error rendering template {template_name}: {e}")
            sys.exit(1)
