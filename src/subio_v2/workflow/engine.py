import toml
import requests
import os
import re
from typing import Dict, List, Any
from src.subio_v2.model.nodes import Node
from src.subio_v2.parser.clash import ClashParser
from src.subio_v2.parser.v2rayn import V2RayNParser
from src.subio_v2.parser.surge import SurgeParser
from src.subio_v2.emitter.clash import ClashEmitter
from src.subio_v2.emitter.surge import SurgeEmitter
from src.subio_v2.emitter.v2rayn import V2RayNEmitter
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
        
        self.clash_parser = ClashParser()
        self.v2rayn_parser = V2RayNParser()
        self.surge_parser = SurgeParser()
        
        self.clash_emitter = ClashEmitter()
        self.surge_emitter = SurgeEmitter()
        self.v2rayn_emitter = V2RayNEmitter()
        
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
            if p_type in ["clash", "clash-meta"]:
                nodes = self.clash_parser.parse(content)
            elif p_type in ["v2rayn", "subio"]: # subio is basically v2rayn/clash mix? Check subio definition.
                # In v1, subio seems to be a custom format or just used generic parser.
                # Looking at model.py, subio nodes were objects.
                # Let's assume for now it might be file-based toml/json or similar to clash. 
                # The example uses 'self.toml'. 
                # If it's TOML, it might be clash-like structure?
                # Let's check 'example/provider/self.toml'.
                if p_type == "subio":
                     # subio format could be toml, json, or python dict in text?
                     # V1 used automatic detection.
                     # Let's try parsing as TOML first (as in example)
                     try:
                         data = toml.loads(content)
                     except:
                         # Try loading as JSON
                         try:
                             data = json.loads(content)
                         except:
                             # If failed, it might be python dict text? 
                             # V1 subio parser used `eval` via `load_with_ext` if ext was `.py`?
                             # Or if it's a custom format.
                             # Given the error "Found invalid character in key name: ':'", it looks like YAML (key: value).
                             try:
                                 data = yaml.safe_load(content)
                             except Exception as e:
                                 print(f"  Error parsing subio provider {name}: {e}")
                                 continue

                     # Convert nodes list to a dict for ClashParser
                     if isinstance(data, dict) and "nodes" in data:
                        nodes = self.clash_parser.parse({"proxies": data["nodes"]})
                     else:
                        print(f"  Error: subio provider {name} does not contain 'nodes' list.")
                         
                elif p_type == "v2rayn":
                    nodes = self.v2rayn_parser.parse(content)
            elif p_type == "surge":
                nodes = self.surge_parser.parse(content)
            
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
            if a_type in ["clash", "clash-meta", "stash"]: # stash is similar to clash
                output = self.clash_emitter.emit(nodes)
                # TODO: Merge with template
                self._write_clash_artifact(name, output, art_conf.get("template"), a_type, art_conf.get("options", {}), art_conf)
            elif a_type == "surge":
                output = self.surge_emitter.emit(nodes)
                 # TODO: Merge with template
                self._write_text_artifact(name, output, art_conf.get("template"), art_conf.get("options", {}), art_conf)
            elif a_type == "v2rayn":
                output = self.v2rayn_emitter.emit(nodes) # Returns Base64 string
                self._write_text_artifact(name, output, art_conf.get("template"), art_conf.get("options", {}), art_conf)
            else:
                print(f"  Unsupported artifact type: {a_type}")

    def _write_clash_artifact(self, filename: str, proxies_data: Dict[str, Any], template_path: str, artifact_type: str = None, artifact_options: Dict[str, Any] = None, artifact_conf: Dict[str, Any] = None):
        if template_path:
            # Prepare context
            proxies_list = proxies_data["proxies"]
            proxies_names = [p["name"] for p in proxies_list]
            
            # Dump proxies list to YAML string
            proxies_yaml = yaml.dump(proxies_list, allow_unicode=True, sort_keys=False)
            
            context = {
                "proxies": proxies_yaml,
                "proxies_names": proxies_names,
                "global_options": self.config.get("options", {}),
                "options": artifact_options or {}
            }
            
            final_content = self.renderer.render(template_path, context, self.macros, artifact_type)
        else:
            final_content = yaml.dump(proxies_data, allow_unicode=True, sort_keys=False)

        with open(f"dist/{filename}", "w") as f:
            f.write(final_content)
            
        # Upload
        if artifact_conf and artifact_conf.get("upload"):
            upload(final_content, artifact_conf, self.config.get("uploader", []))

    def _write_text_artifact(self, filename: str, content: str, template_path: str, artifact_options: Dict[str, Any] = None, artifact_conf: Dict[str, Any] = None):
        final_content = content
        if template_path:
            # For text artifacts, we might not have advanced context, 
            # or maybe pass 'proxies' as the content string?
            context = {
                "proxies": content,
                "global_options": self.config.get("options", {}),
                "options": artifact_options or {}
            }
            rendered = self.renderer.render(template_path, context, self.macros)
            if rendered:
                final_content = rendered
            else:
                 pass
        
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

