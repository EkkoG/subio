import toml
import json
import json5
import hashlib
import requests
import re
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
from subio_v2.platforms import resolve_platform
from subio_v2.parser.factory import ParserFactory
from subio_v2.parser.surge import SurgeParser
from subio_v2.emitter.base import BaseEmitter
from subio_v2.emitter.factory import EmitterFactory
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
        self._warn_platform_type_replacements()

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
        self._validate_options(self.config.get("options"), "Config options")
        self._validate_filters(self.config.get("filters"), "Config filters")

        for section in ("provider", "artifact", "uploader"):
            entries = self.config.get(section, [])
            if not isinstance(entries, list):
                raise ConfigError(f"Config section '{section}' must be a list")
            name_positions: dict[str, int] = {}
            artifact_outputs: dict[str, tuple[int, str | None]] = {}
            for position, entry in enumerate(entries, start=1):
                if not isinstance(entry, dict):
                    raise ConfigError(f"Entries in '{section}' must be objects")
                name = entry.get("name")
                if not isinstance(name, str) or not name:
                    raise ConfigError(f"Every '{section}' entry must have a name")
                if section != "artifact":
                    first_position = name_positions.get(name)
                    if first_position is not None:
                        raise ConfigError(
                            f"Duplicate {section} name {name!r}: {section} entry "
                            f"#{position} duplicates {section} entry #{first_position}"
                        )
                    name_positions[name] = position
                if section == "provider":
                    has_url = "url" in entry
                    has_file = "file" in entry
                    if has_url == has_file:
                        raise ConfigError(
                            f"Provider '{name}' must define exactly one of 'url' or 'file'"
                        )
                    allow_unsafe_external = entry.get("allow_unsafe_external", False)
                    if not isinstance(allow_unsafe_external, bool):
                        raise ConfigError(
                            f"Provider '{name}' allow_unsafe_external must be a boolean"
                        )
                    if allow_unsafe_external and entry.get("type") != "surge":
                        raise ConfigError(
                            f"Provider '{name}' can only enable allow_unsafe_external "
                            "when type is 'surge'"
                        )
                    if allow_unsafe_external and not has_url:
                        raise ConfigError(
                            f"Provider '{name}' can only enable allow_unsafe_external "
                            "for a remote URL source"
                        )
                    self._validate_filters(
                        entry.get("filters"), f"Provider '{name}' filters"
                    )
                if section == "artifact":
                    if not isinstance(entry.get("allow_conversion_errors", False), bool):
                        raise ConfigError(
                            f"Artifact '{name}' allow_conversion_errors must be a boolean"
                        )
                    if not isinstance(entry.get("allow_empty", False), bool):
                        raise ConfigError(
                            f"Artifact '{name}' allow_empty must be a boolean"
                        )
                    providers = entry.get("providers", [])
                    if not isinstance(providers, list) or any(
                        not isinstance(provider, str) or not provider
                        for provider in providers
                    ):
                        raise ConfigError(
                            f"Artifact '{name}' providers must be a list of names"
                        )
                    self._validate_options(
                        entry.get("options"), f"Artifact '{name}' options"
                    )
                    self._validate_artifact_users(entry, name)
                    users = entry.get("users", [])
                    if users and "{user}" not in name:
                        raise ConfigError(
                            f"Artifact entry #{position} {name!r} defines users, "
                            "so its name must contain '{user}'"
                        )
                    usernames = users or (
                        [entry["user"]] if entry.get("user") is not None else [None]
                    )
                    for username in usernames:
                        output_name = (
                            name.replace("{user}", username)
                            if username is not None
                            else name
                        )
                        previous = artifact_outputs.get(output_name)
                        if previous is not None:
                            first_position, first_user = previous
                            if username is None and first_user is None:
                                raise ConfigError(
                                    f"Duplicate artifact name {output_name!r}: "
                                    f"artifact entry #{position} duplicates artifact "
                                    f"entry #{first_position}"
                                )
                            current_context = f"artifact entry #{position}"
                            if username is not None:
                                current_context += f" (user {username!r})"
                            first_context = f"artifact entry #{first_position}"
                            if first_user is not None:
                                first_context += f" (user {first_user!r})"
                            raise ConfigError(
                                f"Duplicate artifact output name {output_name!r}: "
                                f"{current_context} duplicates {first_context}"
                            )
                        artifact_outputs[output_name] = (position, username)
                    self._validate_artifact_uploads(entry.get("upload"), name)
                if section == "uploader":
                    uploader_type = entry.get("type")
                    if not isinstance(uploader_type, str) or not uploader_type:
                        raise ConfigError(
                            f"Uploader '{name}' type must be a non-empty string"
                        )
                    if uploader_type == "gist" and (
                        not isinstance(entry.get("id"), str) or not entry["id"]
                    ):
                        raise ConfigError(
                            f"Uploader '{name}' id must be a non-empty string"
                        )
                    if not isinstance(entry.get("token", ""), str):
                        raise ConfigError(f"Uploader '{name}' token must be a string")
                    if not isinstance(entry.get("clean", False), bool):
                        raise ConfigError(f"Uploader '{name}' clean must be a boolean")

        provider_names = {item["name"] for item in self.config.get("provider", [])}
        uploader_names = {item["name"] for item in self.config.get("uploader", [])}
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
            missing_uploaders = [
                item["to"]
                for item in artifact.get("upload", [])
                if item["to"] not in uploader_names
            ]
            if missing_uploaders:
                raise ConfigError(
                    f"Artifact '{artifact['name']}' references missing uploader(s): "
                    f"{', '.join(missing_uploaders)}"
                )

    def _warn_platform_type_replacements(self) -> None:
        for section in ("provider", "artifact"):
            for entry in self.config.get(section, []):
                platform = entry.get("type")
                resolution = (
                    resolve_platform(platform) if isinstance(platform, str) else None
                )
                if resolution is None:
                    continue
                if resolution.deprecated:
                    logger.warning(
                        f"{section.title()} {entry['name']!r} uses deprecated "
                        f"platform type {platform!r}; use {resolution.replacement!r} "
                        "for modern Mihomo configurations"
                    )
                elif resolution.alias:
                    logger.warning(
                        f"{section.title()} {entry['name']!r} uses platform type "
                        f"alias {platform!r}; use {resolution.replacement!r} instead"
                    )

    @staticmethod
    def _validate_options(value: Any, label: str) -> None:
        if value is not None and not isinstance(value, dict):
            raise ConfigError(f"{label} must be an object")

    @staticmethod
    def _validate_filters(value: Any, label: str) -> None:
        if value is None:
            return
        if not isinstance(value, dict):
            raise ConfigError(f"{label} must be an object")
        for key in ("include", "exclude"):
            pattern = value.get(key)
            if pattern is not None and not isinstance(pattern, str):
                raise ConfigError(f"{label} {key} must be a string")
            if pattern:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ConfigError(f"{label} {key} is not a valid regex") from exc

    @staticmethod
    def _validate_artifact_users(entry: Dict[str, Any], name: str) -> None:
        user = entry.get("user")
        users = entry.get("users", [])
        if user is not None and (not isinstance(user, str) or not user):
            raise ConfigError(f"Artifact '{name}' user must be a non-empty string")
        if not isinstance(users, list) or any(
            not isinstance(item, str) or not item for item in users
        ):
            raise ConfigError(f"Artifact '{name}' users must be a list of names")
        if user is not None and users:
            raise ConfigError(f"Artifact '{name}' cannot define both user and users")

    @staticmethod
    def _validate_artifact_uploads(value: Any, name: str) -> None:
        if value is None:
            return
        if not isinstance(value, list):
            raise ConfigError(f"Artifact '{name}' upload must be a list")
        for item in value:
            if not isinstance(item, dict):
                raise ConfigError(f"Artifact '{name}' upload entries must be objects")
            target = item.get("to")
            if not isinstance(target, str) or not target:
                raise ConfigError(
                    f"Artifact '{name}' upload target must be a non-empty string"
                )
            file_name = item.get("file_name")
            if file_name is not None and (
                not isinstance(file_name, str) or not file_name
            ):
                raise ConfigError(
                    f"Artifact '{name}' upload file_name must be a non-empty string"
                )

    def run(self) -> WorkflowResult:
        if self.dry_run:
            logger.info("--- Starting SubIO v2 Workflow (DRY-RUN) ---")
        else:
            logger.info("--- Starting SubIO v2 Workflow ---")
        self.batch_uploader.begin()
        self._staged_artifacts.clear()
        self.providers.clear()
        self.issues.clear()
        self.provider_issues.clear()
        try:
            self._load_providers()
            self._generate_artifacts()
            generated = list(self._staged_artifacts)
            queued_uploads = self.batch_uploader.pending_uploads()
            self._commit_artifacts()
            self.batch_uploader.flush()
        except BaseException:
            self._staged_artifacts.clear()
            self.batch_uploader.abort()
            raise
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
                if prov_conf.get("allow_unsafe_external", False):
                    logger.warning(
                        f"Provider '{name}' enables remote Surge External passthrough; "
                        "the generated Surge configuration may contain program entries "
                        "supplied by that remote provider"
                    )
                content = self._fetch_content(prov_conf)
                if not content:
                    raise ProviderLoadError(f"Provider '{name}' returned empty content")

                if p_type == "surge":
                    parser = SurgeParser(
                        source_kind="remote" if "url" in prov_conf else "local",
                        allow_unsafe_external=prov_conf.get(
                            "allow_unsafe_external", False
                        ),
                    )
                else:
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
                    issues=artifact_issues,
                )

            output = emission.content
            extra_context = emission.extras.get("template_context", {})
            if not isinstance(extra_context, dict):
                raise ArtifactGenerationError(
                    f"Emitter for artifact '{display_name}' returned an invalid "
                    "template context"
                )

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

            if extra_context:
                context.update(extra_context)

            render_result = self.renderer.render_result(
                template_path, context, artifact_type, self.rulesets
            )
            final_content = render_result.content
            ruleset_issues = [
                replace(issue, artifact=filename, user=username)
                for issue in render_result.issues
            ]
            self.issues.extend(ruleset_issues)
            BaseEmitter.log_issues(ruleset_issues)
            ruleset_errors = [
                issue
                for issue in ruleset_issues
                if issue.severity == IssueSeverity.ERROR
            ]
            allow_conversion_errors = bool(
                self.config.get("allow_conversion_errors", False)
                or (artifact_conf or {}).get("allow_conversion_errors", False)
            )
            if ruleset_errors and not allow_conversion_errors:
                raise ArtifactGenerationError(
                    f"Artifact '{filename}' has {len(ruleset_errors)} ruleset conversion error(s)",
                    issues=ruleset_errors,
                )
            if ruleset_errors:
                logger.warning(
                    f"Artifact '{filename}' is continuing with "
                    f"{len(ruleset_errors)} ruleset conversion error(s) because "
                    "allow_conversion_errors=true"
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
