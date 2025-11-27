import jinja2
import yaml
import json
import sys
from typing import Any, Dict
from subio_v2.utils.logger import logger
from subio_v2.workflow.filters import all_filters
from subio_v2.workflow.ruleset import RULESET_MARKER
from subio_v2.workflow.rules import parse_rules, render_rules
import os


class TemplateRenderer:
    def __init__(self, template_dir: str):
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir), undefined=jinja2.Undefined
        )
        self._artifact_type = None
        self._register_base_filters()
        self._register_globals()

    def _register_base_filters(self):
        def to_yaml_filter(value):
            return yaml.dump(value, allow_unicode=True, sort_keys=False).strip()

        self.env.filters["to_yaml"] = to_yaml_filter

    def _register_globals(self):
        self.env.globals["filter"] = all_filters

    def _auto_render(self, value):
        """Auto render value based on type and artifact_type."""
        if value is None:
            return ""
        if isinstance(value, list):
            return json.dumps(value, ensure_ascii=False)
        if not isinstance(value, str):
            return str(value)

        # Check if it's a ruleset (marked by RULESET_MARKER from snippet/remote ruleset)
        if value.startswith(RULESET_MARKER):
            content = value[len(RULESET_MARKER):]
            return self._render_ruleset(content)

        return value

    def _render_ruleset(self, value: str) -> str:
        """Render ruleset content based on artifact type."""
        platform = self._artifact_type or "clash-meta"
        rules = parse_rules(value)
        return render_rules(rules, platform)

    def render(
        self,
        template_name: str,
        context: Dict[str, Any],
        macros: str = "",
        artifact_type: str = None,
    ) -> str:
        try:
            # Read template file directly
            template_path = os.path.join(self.env.loader.searchpath[0], template_name)
            if not os.path.exists(template_path):
                raise FileNotFoundError(f"Template not found: {template_name}")

            with open(template_path, "r", encoding="utf-8") as f:
                template_source = f.read()

            # Prepend macros
            full_source = f"{macros}\n{template_source}"

            # Set artifact type for auto-rendering
            self._artifact_type = artifact_type

            # Create environment with finalize for auto-rendering
            original_finalize = self.env.finalize
            self.env.finalize = self._auto_render

            try:
                template = self.env.from_string(full_source)
                return template.render(**context)
            finally:
                self.env.finalize = original_finalize
                self._artifact_type = None

        except FileNotFoundError as e:
            logger.error(f"Template error: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error rendering template {template_name}: {e}")
            sys.exit(1)
