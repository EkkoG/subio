import copy
import toml
import json
import json5
import hashlib
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Dict, List, Any
from subio_v2.conversion import (
    ConversionIssue,
    IssueSeverity,
    WorkflowResult,
)
from subio_v2.model.nodes import Node, get_nodes_for_user
from subio_v2.parser.factory import ParserFactory
from subio_v2.emitter.factory import EmitterFactory
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.emitter.dae import DaeEmitter
from subio_v2.processor.common import (
    FilterProcessor,
    RenameProcessor,
    DialerProxyProcessor,
)
from subio_v2.workflow.template import TemplateRenderer
from subio_v2.workflow.ruleset import (
    load_rulesets,
    load_snippets,
    merge_stores,
    RuleSetStore,
)
from subio_v2.workflow.errors import (
    ArtifactGenerationError,
    ConfigError,
    ProviderLoadError,
)
from subio_v2.workflow.uploader import GistBatchUploader, upload
from subio_v2.crypto import age
from subio_v2.utils.logger import logger
import yaml


class WorkflowEngine:
    def __init__(
        self, config_path: str, dry_run: bool = False, clean_gist: bool = False
    ):
        self.config_path = config_path
        self.config = self._load_config()
        self.providers: Dict[str, List[Node]] = {}
        self.provider_issues: Dict[str, List[ConversionIssue]] = {}
        self.provider_resources: Dict[str, Dict[str, Any]] = {}
        self.dry_run = dry_run
        self.clean_gist = clean_gist
        self._url_cache: Dict[str, str] = {}  # Cache for URL content
        self._staged_artifacts: Dict[str, str] = {}
        self.issues: List[ConversionIssue] = []
        self.batch_uploader = GistBatchUploader(dry_run=dry_run, clean_gist=clean_gist)

        # Age encryption keys
        self.global_age_secret_key = self.config.get("age_secret_key", "")
        self.global_age_public_key = self.config.get("age_public_key", "")

        if self.global_age_secret_key:
            err = age.verify_secret_key(self.global_age_secret_key)
            if err:
                raise ConfigError(f"Invalid global age_secret_key: {err}")

        if self.global_age_public_key:
            err = age.verify_public_key(self.global_age_public_key)
            if err:
                raise ConfigError(f"Invalid global age_public_key: {err}")

        self._validate_config()

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
            raise ConfigError(f"Config file not found: {self.config_path}")
        except Exception as e:
            raise ConfigError(f"Error reading config file: {e}") from e

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
            raise ConfigError(f"Error parsing config ({ext}): {e}") from e

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

        raise ConfigError("Unknown config format (tried toml, json, json5, yaml)")

    def _validate_config(self) -> None:
        if not isinstance(self.config, dict):
            raise ConfigError("Config root must be an object")

        global_allow_errors = self.config.get("allow_conversion_errors", False)
        if not isinstance(global_allow_errors, bool):
            raise ConfigError("'allow_conversion_errors' must be a boolean")

        for section in ("provider", "artifact", "uploader"):
            entries = self.config.get(section, [])
            if not isinstance(entries, list):
                raise ConfigError(f"Config section '{section}' must be a list")
            names: set[str] = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ConfigError(f"Entries in '{section}' must be objects")
                name = entry.get("name")
                if not isinstance(name, str) or not name:
                    raise ConfigError(f"Every '{section}' entry must have a name")
                if name in names:
                    raise ConfigError(f"Duplicate {section} name: {name}")
                names.add(name)
                if section == "artifact" and not isinstance(
                    entry.get("allow_conversion_errors", False), bool
                ):
                    raise ConfigError(
                        f"Artifact '{name}' allow_conversion_errors must be a boolean"
                    )

        provider_names = {item["name"] for item in self.config.get("provider", [])}
        for artifact in self.config.get("artifact", []):
            missing = [
                name
                for name in artifact.get("providers", [])
                if name not in provider_names
            ]
            if missing:
                raise ConfigError(
                    f"Artifact '{artifact['name']}' references missing provider(s): "
                    f"{', '.join(missing)}"
                )

    def run(self) -> WorkflowResult:
        if self.dry_run:
            logger.info("--- Starting SubIO v2 Workflow (DRY-RUN) ---")
        else:
            logger.info("--- Starting SubIO v2 Workflow ---")
        self._staged_artifacts.clear()
        self.issues.clear()
        self.provider_issues.clear()
        self.provider_resources.clear()
        self._load_providers()
        self._generate_artifacts()
        generated = list(self._staged_artifacts)
        queued_uploads = [
            f"{gist_id}:{filename}"
            for gist_id, data in self.batch_uploader._pending.items()
            for filename in data["files"]
        ]
        self._commit_artifacts()
        self.batch_uploader.flush()
        logger.success("--- Finished ---")
        return WorkflowResult(
            generated=generated,
            uploaded=[] if self.dry_run else queued_uploads,
            issues=list(self.issues),
        )

    def _load_providers(self):
        with logger.status("[bold green]Loading providers...") as status:
            for prov_conf in self.config.get("provider", []):
                name = prov_conf.get("name")
                p_type = prov_conf.get("type")
                status.update(f"[bold green]Loading provider: {name} ({p_type})")

                logger.info(
                    f"Processing provider: [bold cyan]{name}[/bold cyan] ({p_type})"
                )
                content = self._fetch_content(prov_conf)
                if not content:
                    raise ProviderLoadError(f"Provider '{name}' returned empty content")

                parser = ParserFactory.get_parser(p_type)
                if parser is None:
                    raise ProviderLoadError(
                        f"Unsupported provider type '{p_type}' for provider '{name}'"
                    )
                try:
                    parse_result = parser.parse_result(content)
                    nodes = parse_result.nodes
                except SystemExit as exc:
                    raise ProviderLoadError(
                        f"Parser for provider '{name}' terminated unexpectedly"
                    ) from exc
                except Exception as exc:
                    raise ProviderLoadError(
                        f"Failed to parse provider '{name}': {exc}"
                    ) from exc
                for node in nodes:
                    node.source_provider = name
                self.provider_issues[name] = [
                    replace(issue, source=name) for issue in parse_result.issues
                ]
                self.provider_resources[name] = copy.deepcopy(parse_result.resources)

                # Apply Rename
                rename_conf = prov_conf.get("rename")
                if rename_conf:
                    processor = RenameProcessor(
                        prefix=rename_conf.get("add_prefix", ""),
                        replace=rename_conf.get("replace", []),
                    )
                    nodes = processor.process(nodes)

                # Apply DialerProxy (dialer-proxy for Clash-like, underlying-proxy for Surge)
                dialer_proxy = prov_conf.get("dialer_proxy")
                if dialer_proxy:
                    processor = DialerProxyProcessor(dialer_proxy=dialer_proxy)
                    nodes = processor.process(nodes)

                # Apply provider-level filter (include/exclude, same structure as global [filters])
                prov_filter_conf = prov_conf.get("filters")
                if prov_filter_conf:
                    prov_filter = FilterProcessor(
                        include=prov_filter_conf.get("include"),
                        exclude=prov_filter_conf.get("exclude"),
                    )
                    nodes = prov_filter.process(nodes)

                logger.info(
                    f"Provider [bold cyan]{name}[/bold cyan] loaded: [bold]{len(nodes)}[/bold] nodes"
                )
                self.providers[name] = nodes

    def _fetch_content(self, conf: Dict[str, Any]) -> str:
        content: str | None = None
        provider_name = conf.get("name", "unknown")

        if "url" in conf:
            # Create cache key based on URL and headers
            headers = {}
            if conf.get("user_agent"):
                headers["User-Agent"] = conf["user_agent"]
            cache_key = (conf["url"], tuple(sorted(headers.items())))

            # Check cache first
            if cache_key in self._url_cache:
                logger.dim(f"Using cached content for provider {provider_name}")
                content = self._url_cache[cache_key]
            else:
                try:
                    # Configure retry strategy
                    retry_strategy = Retry(
                        total=3,  # Total number of retries
                        connect=3,  # Retry on connection errors
                        read=3,  # Retry on read timeout errors
                        status_forcelist=[
                            429,
                            500,
                            502,
                            503,
                            504,
                        ],  # HTTP status codes to retry on
                        backoff_factor=1,  # Backoff factor (1s, 2s, 4s, ...)
                        raise_on_status=False,  # Don't raise on bad status codes initially
                    )

                    # Create adapter with retry strategy
                    adapter = HTTPAdapter(max_retries=retry_strategy)

                    # Create session and mount adapter
                    with requests.Session() as session:
                        session.mount("http://", adapter)
                        session.mount("https://", adapter)

                        resp = session.get(conf["url"], headers=headers, timeout=10)
                        resp.raise_for_status()
                        content = resp.text

                        # Cache the raw content (before decryption)
                        self._url_cache[cache_key] = content

                        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[
                            :12
                        ]
                        logger.dim(
                            f"Fetched provider {provider_name}: {len(content.encode('utf-8'))} "
                            f"bytes (sha256:{digest})"
                        )
                except Exception as e:
                    raise ProviderLoadError(
                        f"Failed to fetch provider '{provider_name}': {type(e).__name__}"
                    ) from e
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
            else:
                # Check 'provider' subfolder
                abs_path = os.path.join(config_dir, "provider", path)
                if os.path.exists(abs_path):
                    with open(abs_path, "r") as f:
                        content = f.read()
                else:
                    raise ProviderLoadError(
                        f"File for provider '{provider_name}' not found: {path}"
                    )

            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]
            logger.dim(
                f"Read provider {provider_name} from {path}: "
                f"{len(content.encode('utf-8'))} bytes (sha256:{digest})"
            )

        if content is None:
            raise ProviderLoadError(
                f"Provider '{provider_name}' must define either 'url' or 'file'"
            )

        # Decrypt age-encrypted content if needed.
        # Provider-level key takes precedence over global key.
        provider_secret_key = conf.get("age_secret_key", "")
        secret_keys = []
        if provider_secret_key:
            secret_keys.append(provider_secret_key)
        if self.global_age_secret_key:
            secret_keys.append(self.global_age_secret_key)

        if secret_keys:
            try:
                content_bytes = content.encode("utf-8", errors="replace")
                # Check if content is age-encrypted before attempting decryption
                # (pass-through for plain text)
                if age.is_age_encrypted(content_bytes):
                    content = age.decrypt_bytes(content_bytes, *secret_keys).decode(
                        "utf-8", errors="replace"
                    )
                    logger.dim(
                        f"Decrypted age-encrypted content for {conf.get('name', conf.get('url', conf.get('file', 'unknown')))}"
                    )
            except Exception as e:
                raise ProviderLoadError(
                    f"Failed to decrypt provider '{provider_name}': {e}"
                ) from e

        return content

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
            if prov_name not in self.providers:
                raise ArtifactGenerationError(
                    f"Artifact '{name}' references unloaded provider '{prov_name}'"
                )
            nodes.extend(self.providers[prov_name])

        # If username specified, process nodes for that user
        if username:
            try:
                nodes = get_nodes_for_user(nodes, username)
            except ValueError as exc:
                raise ArtifactGenerationError(
                    f"Invalid user overrides for artifact '{name}': {exc}"
                ) from exc

        # Apply Global Filter
        if global_filter:
            nodes = global_filter.process(nodes)

        # Emit
        emitter = EmitterFactory.get_emitter(a_type)

        # For Surge, collect keystore from all Surge providers
        if a_type == "surge" and isinstance(emitter, SurgeEmitter):
            merged_keystore = {}
            for prov_name in art_conf.get("providers", []):
                resources = self.provider_resources.get(prov_name, {})
                provider_keystore = resources.get("keystore", {})
                if not isinstance(provider_keystore, dict):
                    raise ArtifactGenerationError(
                        f"Provider '{prov_name}' returned an invalid Surge keystore"
                    )
                for key_id, entry in provider_keystore.items():
                    existing = merged_keystore.get(key_id)
                    if existing is not None and existing != entry:
                        raise ArtifactGenerationError(
                            f"Artifact '{name}' has conflicting Surge "
                            f"keystore entry '{key_id}'"
                        )
                    merged_keystore[key_id] = copy.deepcopy(entry)
            # Create new emitter with merged keystore
            emitter = SurgeEmitter(keystore=merged_keystore)

        if emitter:
            # Determine display name and actual filename
            display_name = name
            if username:
                display_name = f"{name} (user: {username})"

            logger.info(
                f"Generating artifact: [bold cyan]{display_name}[/bold cyan] ({a_type}) - {len(nodes)} nodes"
            )
            try:
                emission = emitter.emit_result(nodes)
            except Exception as exc:
                raise ArtifactGenerationError(
                    f"Failed to emit artifact '{display_name}': {exc}"
                ) from exc

            artifact_issues = [
                replace(issue, artifact=name, user=username)
                for prov_name in art_conf.get("providers", [])
                for issue in self.provider_issues.get(prov_name, [])
            ]
            artifact_issues.extend(
                replace(issue, artifact=name, user=username)
                for issue in emission.issues
            )
            self.issues.extend(artifact_issues)
            emitter.log_issues(artifact_issues)
            errors = [
                issue
                for issue in artifact_issues
                if issue.severity == IssueSeverity.ERROR
            ]
            allow_conversion_errors = bool(
                self.config.get("allow_conversion_errors", False)
                or art_conf.get("allow_conversion_errors", False)
            )
            if errors and not allow_conversion_errors:
                raise ArtifactGenerationError(
                    f"Artifact '{display_name}' has {len(errors)} conversion error(s)",
                    issues=errors,
                )
            if errors:
                logger.warning(
                    f"Artifact '{display_name}' is continuing with {len(errors)} "
                    "conversion error(s) because allow_conversion_errors=true"
                )

            supported_nodes = emission.supported_nodes
            if not supported_nodes and not art_conf.get("allow_empty", False):
                raise ArtifactGenerationError(
                    f"Artifact '{display_name}' has no emit-capable nodes; "
                    "set allow_empty=true to permit this",
                    issues=errors,
                )

            output = emission.content
            node_names = [node.name for node in supported_nodes]
            extra_context: Dict[str, Any] = {"proxies_names": node_names}
            if isinstance(emitter, SurgeEmitter):
                extra_context["proxies_names"] = (
                    f"PROXY = select, {', '.join(node_names)}"
                )
            if isinstance(emitter, DaeEmitter):
                extra_context["proxies_names"] = ", ".join(
                    f"'{n.name}'" for n in supported_nodes
                )
                extra_context["subscription"] = emission.extras["subscription"]

            # Use unified writer
            self._write_artifact(
                name,
                output,
                art_conf.get("template"),
                a_type,
                art_conf.get("options", {}),
                art_conf,
                username,
                extra_context,
            )
        else:
            raise ArtifactGenerationError(
                f"Unsupported artifact type '{a_type}' for artifact '{name}'"
            )

    def _write_artifact(
        self,
        filename: str,
        content: str | Dict[str, Any],
        template_path: str,
        artifact_type: str = None,
        artifact_options: Dict[str, Any] = None,
        artifact_conf: Dict[str, Any] = None,
        username: str = None,
        extra_context: Dict[str, Any] = None,
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
            merged_options = {
                **self.config.get("options", {}),
                **(artifact_options or {}),
            }
            context = {
                "proxies": raw_content_str,  # For Clash, this is the proxies list YAML. For Surge, this is the text block.
                "options": merged_options,
                "user": username,  # Add username to template context
            }

            if is_yaml_data:
                proxies_list = content.get("proxies", [])
                context["proxies_names"] = [p["name"] for p in proxies_list]

            # Platform-specific overrides (e.g., dae's pre-formatted names + subscription)
            if extra_context:
                context.update(extra_context)

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

        if (
            not isinstance(actual_filename, str)
            or not actual_filename
            or actual_filename != os.path.basename(actual_filename)
            or "/" in actual_filename
            or "\\" in actual_filename
            or actual_filename in {".", ".."}
        ):
            raise ArtifactGenerationError(
                f"Invalid artifact filename: {actual_filename!r}"
            )

        # Encrypt output with age if public key is configured.
        # Artifact-level key takes precedence over global key.
        artifact_public_key = (artifact_conf or {}).get("age_public_key", "")
        public_key = artifact_public_key or self.global_age_public_key
        if public_key:
            try:
                final_content_bytes = age.encrypt_bytes(final_content, public_key)
                final_content = final_content_bytes.decode("ascii")
                logger.dim("Encrypted artifact output with age public key")
            except Exception as e:
                raise ArtifactGenerationError(
                    f"Failed to encrypt artifact '{actual_filename}': {e}"
                ) from e

        if actual_filename in self._staged_artifacts:
            raise ArtifactGenerationError(
                f"Multiple artifacts would overwrite 'dist/{actual_filename}'"
            )
        self._staged_artifacts[actual_filename] = final_content

        # Upload
        if artifact_conf and artifact_conf.get("upload"):
            upload(
                final_content,
                artifact_conf,
                self.config.get("uploader", []),
                self.batch_uploader,
                username,
            )

    def _commit_artifacts(self) -> None:
        """Write all generated artifacts only after the whole generation phase succeeds."""
        dist_dir = Path("dist").resolve()
        dist_dir.mkdir(parents=True, exist_ok=True)
        prepared: list[tuple[str, Path]] = []

        try:
            for filename, content in self._staged_artifacts.items():
                target = dist_dir / filename
                if target.parent != dist_dir:
                    raise ArtifactGenerationError(
                        f"Artifact path escapes dist directory: {filename!r}"
                    )
                fd, temp_name = tempfile.mkstemp(
                    prefix=f".{filename}.", suffix=".tmp", dir=dist_dir
                )
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as output:
                        output.write(content)
                        output.flush()
                        os.fsync(output.fileno())
                except Exception:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    raise
                prepared.append((temp_name, target))

            for temp_name, target in prepared:
                os.replace(temp_name, target)
            prepared.clear()
            self._staged_artifacts.clear()
        except ArtifactGenerationError:
            raise
        except Exception as exc:
            raise ArtifactGenerationError(
                f"Failed to write generated artifacts: {exc}"
            ) from exc
        finally:
            for temp_name, _ in prepared:
                try:
                    os.unlink(temp_name)
                except FileNotFoundError:
                    pass

    def _read_template(self, path: str) -> str | None:
        # This method is actually not used by TemplateRenderer directly,
        # but TemplateRenderer uses Jinja2 loader which might fail silently or raise error.
        # TemplateRenderer.render catches FileNotFoundError and logs it.
        # We should probably make TemplateRenderer exit if template not found.
        pass
