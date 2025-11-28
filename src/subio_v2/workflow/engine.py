import toml
import json
import json5
import requests
import os
import sys
from typing import Dict, List, Any
from subio_v2.model.nodes import Node, get_nodes_for_user
from subio_v2.parser.factory import ParserFactory
from subio_v2.emitter.factory import EmitterFactory
from subio_v2.processor.common import FilterProcessor, RenameProcessor
from subio_v2.workflow.template import TemplateRenderer
from subio_v2.workflow.ruleset import load_rulesets, load_snippets, merge_stores, RuleSetStore
from subio_v2.workflow.uploader import upload, flush_uploads
from subio_v2.utils.logger import logger
import yaml


class WorkflowEngine:
    def __init__(self, config_path: str, dry_run: bool = False, clean_gist: bool = False):
        self.config_path = config_path
        self.config = self._load_config()
        self.providers: Dict[str, List[Node]] = {}
        self.dry_run = dry_run
        self.clean_gist = clean_gist

        # Parsers and Emitters are now managed by Factory

        # Template Renderer
        config_dir = os.path.dirname(self.config_path)
        template_dir = os.path.join(config_dir, "template")
        snippet_dir = os.path.join(config_dir, "snippet")

        if not os.path.exists(template_dir):
            # Fallback or just use config dir
            template_dir = config_dir
        self.renderer = TemplateRenderer(template_dir)

        # Load Snippets & Rulesets into RuleSetStore
        stores = []

        # Snippets
        if os.path.exists(snippet_dir):
            stores.append(load_snippets(snippet_dir))

        # Rulesets
        if "ruleset" in self.config:
            stores.append(load_rulesets(self.config["ruleset"]))

        self.rulesets = merge_stores(*stores) if stores else RuleSetStore()

    def _load_config(self) -> Dict[str, Any]:
        try:
            with open(self.config_path, "r") as f:
                content = f.read()
        except FileNotFoundError:
            logger.error(f"Config file not found: {self.config_path}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error reading config file: {e}")
            sys.exit(1)

        # Determine format by file extension
        ext = os.path.splitext(self.config_path)[1].lower()

        try:
            if ext == ".toml":
                return toml.loads(content)
            elif ext in (".yaml", ".yml"):
                return yaml.safe_load(content)
            elif ext == ".json":
                return json.loads(content)
            elif ext == ".json5":
                return json5.loads(content)
            else:
                # Try to auto-detect format
                return self._parse_config_auto(content)
        except Exception as e:
            logger.error(f"Error parsing config ({ext}): {e}")
            sys.exit(1)

    def _parse_config_auto(self, content: str) -> Dict[str, Any]:
        """Try to parse config content by attempting multiple formats."""
        # Try TOML first
        try:
            return toml.loads(content)
        except Exception:
            pass

        # Try JSON
        try:
            return json.loads(content)
        except Exception:
            pass

        # Try JSON5
        try:
            return json5.loads(content)
        except Exception:
            pass

        # Try YAML last (most permissive)
        try:
            return yaml.safe_load(content)
        except Exception:
            pass

        logger.error("Error parsing config: Unknown format (tried toml, json, json5, yaml)")
        sys.exit(1)

    def run(self):
        if self.dry_run:
            logger.info("--- Starting SubIO v2 Workflow (DRY-RUN) ---")
        else:
            logger.info("--- Starting SubIO v2 Workflow ---")
        self._load_providers()
        self._generate_artifacts()
        # Flush all pending uploads (batch upload to gist)
        flush_uploads(dry_run=self.dry_run, clean_gist=self.clean_gist)
        logger.success("--- Finished ---")

    def _load_providers(self):
        with logger.status("[bold green]Loading providers...") as status:
            for prov_conf in self.config.get("provider", []):
                name = prov_conf.get("name")
                p_type = prov_conf.get("type")
                status.update(f"[bold green]Loading provider: {name} ({p_type})")

                content = self._fetch_content(prov_conf)
                if not content:
                    logger.error(f"Failed to load provider {name}: No content")
                    sys.exit(1)

                nodes = []
                parser = ParserFactory.get_parser(p_type)

                if parser:
                    nodes = parser.parse(content)
                else:
                    logger.error(f"Unsupported provider type: {p_type}")

                # Apply Rename
                rename_conf = prov_conf.get("rename")
                if rename_conf:
                    processor = RenameProcessor(
                        prefix=rename_conf.get("add_prefix", ""),
                        replace=rename_conf.get("replace", []),
                    )
                    nodes = processor.process(nodes)

                logger.info(
                    f"Provider [bold cyan]{name}[/bold cyan] loaded: [bold]{len(nodes)}[/bold] nodes"
                )
                self.providers[name] = nodes

    def _fetch_content(self, conf: Dict[str, Any]) -> str | None:
        if "url" in conf:
            try:
                # Simplified fetch
                headers = {}
                if conf.get("user_agent"):
                    headers["User-Agent"] = conf["user_agent"]

                resp = requests.get(conf["url"], headers=headers, timeout=10)
                resp.raise_for_status()
                content = resp.text
                logger.dim(f"Fetched content from {conf['url']} (first 100 chars): {content[:100]}...")
                return content
            except Exception as e:
                logger.error(f"Fetch error: {e}")
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
                with open(abs_path, "r") as f:
                    content = f.read()
                    logger.dim(f"Read file {path} (first 100 chars): {content[:100]}...")
                    return content
            # Check 'provider' subfolder
            abs_path = os.path.join(config_dir, "provider", path)
            if os.path.exists(abs_path):
                with open(abs_path, "r") as f:
                    content = f.read()
                    logger.dim(f"Read file {path} (first 100 chars): {content[:100]}...")
                    return content

            logger.error(f"File not found: {path}")
            return None
        return None

    def _generate_artifacts(self):
        global_filter = None
        if self.config.get("filters"):
            global_filter = FilterProcessor(
                include=self.config["filters"].get("include"),
                exclude=self.config["filters"].get("exclude"),
            )

        for art_conf in self.config.get("artifact", []):
            # Check for multi-user batch generation
            users = art_conf.get("users", [])
            single_user = art_conf.get("user")

            if users:
                # Batch generate for multiple users
                for username in users:
                    self._generate_single_artifact(art_conf, global_filter, username)
            elif single_user:
                # Single user specified
                self._generate_single_artifact(art_conf, global_filter, single_user)
            else:
                # No user specified, generate normally
                self._generate_single_artifact(art_conf, global_filter, None)

    def _generate_single_artifact(
        self,
        art_conf: Dict[str, Any],
        global_filter: FilterProcessor | None,
        username: str | None,
    ):
        name = art_conf.get("name")
        a_type = art_conf.get("type")

        # Gather nodes from providers
        nodes = []
        for prov_name in art_conf.get("providers", []):
            if prov_name in self.providers:
                nodes.extend(self.providers[prov_name])

        # If username specified, process nodes for that user
        if username:
            nodes = get_nodes_for_user(nodes, username)

        # Apply Global Filter
        if global_filter:
            nodes = global_filter.process(nodes)

        # Emit
        emitter = EmitterFactory.get_emitter(a_type)

        if emitter:
            # Determine display name and actual filename
            display_name = name
            if username:
                display_name = f"{name} (user: {username})"

            logger.info(
                f"Generating artifact: [bold cyan]{display_name}[/bold cyan] ({a_type}) - {len(nodes)} nodes"
            )
            output = emitter.emit(nodes)

            # Use unified writer
            self._write_artifact(
                name,
                output,
                art_conf.get("template"),
                a_type,
                art_conf.get("options", {}),
                art_conf,
                username,
            )
        else:
            logger.error(f"Unsupported artifact type: {a_type}")

    def _write_artifact(
        self,
        filename: str,
        content: str | Dict[str, Any],
        template_path: str,
        artifact_type: str = None,
        artifact_options: Dict[str, Any] = None,
        artifact_conf: Dict[str, Any] = None,
        username: str = None,
    ):
        final_content = ""

        # If content is dict (Clash/Stash), dump to YAML string first
        is_yaml_data = isinstance(content, dict)
        raw_content_str = ""

        if is_yaml_data:
            proxies_list = content.get("proxies", [])
            raw_content_str = yaml.dump(
                proxies_list, allow_unicode=True, sort_keys=False
            )
        else:
            raw_content_str = content

        if template_path:
            # Merge global_options into options (artifact options override global)
            merged_options = {**self.config.get("options", {}), **(artifact_options or {})}
            context = {
                "proxies": raw_content_str,  # For Clash, this is the proxies list YAML. For Surge, this is the text block.
                "options": merged_options,
                "user": username,  # Add username to template context
            }

            if is_yaml_data:
                proxies_list = content.get("proxies", [])
                context["proxies_names"] = [p["name"] for p in proxies_list]

            final_content = self.renderer.render(
                template_path, context, artifact_type, self.rulesets
            )
        else:
            if is_yaml_data:
                final_content = yaml.dump(content, allow_unicode=True, sort_keys=False)
            else:
                final_content = raw_content_str

        # Replace {user} placeholder in filename
        actual_filename = filename
        if username:
            actual_filename = filename.replace("{user}", username)

        with open(f"dist/{actual_filename}", "w") as f:
            f.write(final_content)

        # Upload
        if artifact_conf and artifact_conf.get("upload"):
            upload(final_content, artifact_conf, self.config.get("uploader", []), username, self.dry_run, self.clean_gist)

    def _read_template(self, path: str) -> str | None:
        # This method is actually not used by TemplateRenderer directly,
        # but TemplateRenderer uses Jinja2 loader which might fail silently or raise error.
        # TemplateRenderer.render catches FileNotFoundError and logs it.
        # We should probably make TemplateRenderer exit if template not found.
        pass
