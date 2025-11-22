import toml
import requests
import os
import re
from typing import Dict, List, Any
from src.subio_v2.model.nodes import Node
from src.subio_v2.parser.factory import ParserFactory
from src.subio_v2.emitter.factory import EmitterFactory
from src.subio_v2.processor.common import FilterProcessor, RenameProcessor
from src.subio_v2.workflow.template import TemplateRenderer
from src.subio_v2.workflow.ruleset import load_rulesets, load_snippets
from src.subio_v2.workflow.uploader import upload
import yaml
import json

class WorkflowEngine:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()
        self.providers: Dict[str, List[Node]] = {}
        
        # Parsers and Emitters are now managed by Factory
        
        # Template Renderer
        config_dir = os.path.dirname(self.config_path)
        template_dir = os.path.join(config_dir, "template")
        snippet_dir = os.path.join(config_dir, "snippet")
        
        if not os.path.exists(template_dir):
             # Fallback or just use config dir
             template_dir = config_dir
        self.renderer = TemplateRenderer(template_dir)
        
        # Load Snippets & Rulesets
        self.macros = ""
        
        # Snippets
        if os.path.exists(snippet_dir):
             self.macros += load_snippets(snippet_dir) + "\n"
        
        # Rulesets
        if "ruleset" in self.config:
            self.macros += load_rulesets(self.config["ruleset"]) + "\n"

    def _load_config(self) -> Dict[str, Any]:
        with open(self.config_path, 'r') as f:
            return toml.load(f)

    def run(self):
        print("--- Starting SubIO v2 Workflow ---")
        self._load_providers()
        self._generate_artifacts()
        print("--- Finished ---")

    def _load_providers(self):
        for prov_conf in self.config.get("provider", []):
            name = prov_conf.get("name")
            p_type = prov_conf.get("type")
            print(f"Loading provider: {name} ({p_type})")
            
            content = self._fetch_content(prov_conf)
            if not content:
                print(f"  Skipping {name}: No content")
                continue

            nodes = []
            parser = ParserFactory.get_parser(p_type)
            
            if parser:
                nodes = parser.parse(content)
            else:
                 print(f"  Unsupported provider type: {p_type}")
            
            # Apply Rename
            rename_conf = prov_conf.get("rename")
            if rename_conf:
                processor = RenameProcessor(
                    prefix=rename_conf.get("add_prefix", ""),
                    replace=rename_conf.get("replace", [])
                )
                nodes = processor.process(nodes)

            print(f"  Loaded {len(nodes)} nodes.")
            self.providers[name] = nodes

    def _fetch_content(self, conf: Dict[str, Any]) -> str | None:
        if "url" in conf:
            try:
                # Simplified fetch
                resp = requests.get(conf["url"], timeout=10)
                resp.raise_for_status()
                return resp.text
            except Exception as e:
                print(f"  Fetch error: {e}")
                return None
        elif "file" in conf:
            # Relative to config file location? Or CWD?
            # Usually relative to config file or CWD.
            # Assuming CWD or config dir.
            path = conf["file"]
            # Check if relative to config
            config_dir = os.path.dirname(self.config_path)
            abs_path = os.path.join(config_dir, path)
            if os.path.exists(abs_path):
                with open(abs_path, 'r') as f:
                    return f.read()
            # Check 'provider' subfolder
            abs_path = os.path.join(config_dir, "provider", path)
            if os.path.exists(abs_path):
                with open(abs_path, 'r') as f:
                    return f.read()
            
            print(f"  File not found: {path}")
            return None
        return None

    def _generate_artifacts(self):
        options = self.config.get("options", {})
        work_filter_regex = options.get("work_filter")
        
        global_filter = None
        if self.config.get("filter"):
             global_filter = FilterProcessor(
                 include=self.config["filter"].get("include"),
                 exclude=self.config["filter"].get("exclude")
             )

        for art_conf in self.config.get("artifact", []):
            name = art_conf.get("name")
            a_type = art_conf.get("type")
            print(f"Generating artifact: {name} ({a_type})")
            
            # Gather nodes
            nodes = []
            for prov_name in art_conf.get("providers", []):
                if prov_name in self.providers:
                    nodes.extend(self.providers[prov_name])
            
            # Apply Global Filter
            if global_filter:
                nodes = global_filter.process(nodes)

            # Removed work_filter application to match V1 behavior
            # if art_opts.get("work") and work_filter_regex: ...

            print(f"  Contains {len(nodes)} nodes.")

            # Emit
            output = None
            emitter = EmitterFactory.get_emitter(a_type)
            
            if emitter:
                output = emitter.emit(nodes)
                # Use unified writer
                self._write_artifact(name, output, art_conf.get("template"), a_type, art_conf.get("options", {}), art_conf)
            else:
                print(f"  Unsupported artifact type: {a_type}")

    def _write_artifact(self, filename: str, content: str | Dict[str, Any], template_path: str, artifact_type: str = None, artifact_options: Dict[str, Any] = None, artifact_conf: Dict[str, Any] = None):
        final_content = ""
        
        # If content is dict (Clash/Stash), dump to YAML string first
        is_yaml_data = isinstance(content, dict)
        raw_content_str = ""
        
        if is_yaml_data:
             proxies_list = content.get("proxies", [])
             raw_content_str = yaml.dump(proxies_list, allow_unicode=True, sort_keys=False)
        else:
             raw_content_str = content

        if template_path:
            context = {
                "proxies": raw_content_str, # For Clash, this is the proxies list YAML. For Surge, this is the text block.
                "global_options": self.config.get("options", {}),
                "options": artifact_options or {}
            }
            
            if is_yaml_data:
                proxies_list = content.get("proxies", [])
                context["proxies_names"] = [p["name"] for p in proxies_list]

            final_content = self.renderer.render(template_path, context, self.macros, artifact_type)
        else:
            if is_yaml_data:
                final_content = yaml.dump(content, allow_unicode=True, sort_keys=False)
            else:
                final_content = raw_content_str

        # Fallback if render returns empty? No, let's trust render.
        
        with open(f"dist/{filename}", "w") as f:
            f.write(final_content)
            
        # Upload
        if artifact_conf and artifact_conf.get("upload"):
            upload(final_content, artifact_conf, self.config.get("uploader", []))

    def _read_template(self, path: str) -> str | None:
        # Check 'template' dir
        config_dir = os.path.dirname(self.config_path)
        abs_path = os.path.join(config_dir, "template", path)
        if os.path.exists(abs_path):
            with open(abs_path, 'r') as f:
                return f.read()
        # Check relative
        abs_path = os.path.join(config_dir, path)
        if os.path.exists(abs_path):
             with open(abs_path, 'r') as f:
                return f.read()
        return None

