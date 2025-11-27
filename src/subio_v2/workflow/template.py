import jinja2
import yaml
import json
import sys
from typing import Any, Dict
from subio_v2.utils.logger import logger
from subio_v2.workflow.filters import all_filters
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

        # Check if it looks like a ruleset (multiline with rule patterns)
        if "\n" in value and self._is_ruleset_content(value):
            return self._render_ruleset(value)

        return value

    def _is_ruleset_content(self, value: str) -> bool:
        """Check if value looks like ruleset content."""
        rule_prefixes = (
            "DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-KEYWORD,",
            "IP-CIDR,", "IP-CIDR6,", "GEOIP,",
            "USER-AGENT,", "PROCESS-NAME,", "IP-ASN,",
            "URL-REGEX,", "AND,", "OR,", "NOT,",
        )
        lines = value.split("\n")
        rule_count = 0
        for line in lines:
            line = line.strip()
            if line.startswith(rule_prefixes):
                rule_count += 1
                if rule_count >= 2:
                    return True
        return False

    def _render_ruleset(self, value: str) -> str:
        """Render ruleset content based on artifact type."""
        if self._artifact_type not in ["clash", "clash-meta", "stash"]:
            return value

        # Process ruleset string for Clash
        lines = value.split("\n")
        filtered_lines = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#") or line.startswith("//"):
                filtered_lines.append(line)
                continue
            if "USER-AGENT" in line:
                continue
            if "IP-ASN" in line:
                continue

            # V1 logic: check no-resolve
            if ",no-resolve" in line:
                line = line.replace(",no-resolve", "")

            filtered_lines.append(f"- {line}")

        return "\n".join(filtered_lines)

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
