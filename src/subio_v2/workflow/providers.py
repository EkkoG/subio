import hashlib
import os
from dataclasses import dataclass, replace

from subio_v2.conversion import ConversionIssue
from subio_v2.crypto import age
from subio_v2.errors import ProviderLoadError
from subio_v2.model.nodes import Node
from subio_v2.parser.registry import ParserRegistry
from subio_v2.processor.common import (
    DialerProxyProcessor,
    FilterProcessor,
    RenameProcessor,
)
from subio_v2.remote import RemoteLoadError, RunRemoteLoader
from subio_v2.utils.logger import logger
from subio_v2.workflow.config import ProviderConfig, RunConfig


@dataclass(frozen=True)
class ProviderLoadResult:
    providers: dict[str, list[Node]]
    issues: dict[str, list[ConversionIssue]]


class ProviderLoaderService:
    def __init__(self, config_path: str, global_age_secret_key: str = ""):
        self.config_path = config_path
        self.global_age_secret_key = global_age_secret_key

    def load(
        self, config: RunConfig, remote_loader: RunRemoteLoader
    ) -> ProviderLoadResult:
        providers: dict[str, list[Node]] = {}
        provider_issues: dict[str, list[ConversionIssue]] = {}
        with logger.status("[bold green]Loading providers...") as status:
            for provider_config in config.providers:
                name = provider_config.name
                provider_type = provider_config.provider_type
                status.update(
                    f"[bold green]Loading provider: {name} ({provider_type})"
                )
                logger.info(
                    f"Processing provider: [bold cyan]{name}[/bold cyan] "
                    f"({provider_type})"
                )
                if provider_config.get("allow_unsafe_external", False):
                    logger.warning(
                        f"Provider '{name}' enables remote Surge External passthrough; "
                        "the generated Surge configuration may contain program entries "
                        "supplied by that remote provider"
                    )
                content_bytes = self._fetch_content(provider_config, remote_loader)
                if not content_bytes:
                    raise ProviderLoadError(f"Provider '{name}' returned empty content")
                content = self._decode_content(content_bytes, provider_config)
                parser = ParserRegistry.get_parser(
                    provider_type,
                    source_kind="remote" if "url" in provider_config else "local",
                    allow_unsafe_external=provider_config.get(
                        "allow_unsafe_external", False
                    ),
                )
                if parser is None:
                    raise ProviderLoadError(
                        f"Unsupported provider type '{provider_type}' for provider "
                        f"'{name}'"
                    )
                try:
                    parse_result = parser.parse_result(content)
                except Exception as exc:
                    raise ProviderLoadError(
                        f"Failed to parse provider '{name}': {exc}"
                    ) from exc
                nodes = parse_result.nodes
                for node in nodes:
                    node.source_provider = name
                provider_issues[name] = [
                    replace(issue, source=name) for issue in parse_result.issues
                ]
                nodes = self._process_nodes(nodes, provider_config)
                logger.info(
                    f"Provider [bold cyan]{name}[/bold cyan] loaded: "
                    f"[bold]{len(nodes)}[/bold] nodes"
                )
                providers[name] = nodes
        return ProviderLoadResult(providers, provider_issues)

    @staticmethod
    def _process_nodes(
        nodes: list[Node], provider_config: ProviderConfig
    ) -> list[Node]:
        rename = provider_config.get("rename")
        if isinstance(rename, dict):
            nodes = RenameProcessor(
                prefix=rename.get("add_prefix", ""),
                replace=rename.get("replace", []),
            ).process(nodes)
        dialer_proxy = provider_config.get("dialer_proxy")
        if dialer_proxy:
            nodes = DialerProxyProcessor(dialer_proxy=str(dialer_proxy)).process(nodes)
        filters = provider_config.get("filters")
        if isinstance(filters, dict):
            nodes = FilterProcessor(
                include=filters.get("include"),
                exclude=filters.get("exclude"),
            ).process(nodes)
        return nodes

    def _fetch_content(
        self, config: ProviderConfig, remote_loader: RunRemoteLoader
    ) -> bytes:
        provider_name = str(config.get("name", "unknown"))
        if "url" in config:
            headers = {}
            if config.get("user_agent"):
                headers["User-Agent"] = str(config["user_agent"])
            try:
                content = remote_loader.fetch(str(config["url"]), headers=headers)
            except RemoteLoadError as exc:
                cause = type(exc.__cause__).__name__ if exc.__cause__ else type(exc).__name__
                raise ProviderLoadError(
                    f"Failed to fetch provider '{provider_name}': {cause}"
                ) from exc
            digest = hashlib.sha256(content).hexdigest()[:12]
            logger.dim(
                f"Fetched provider {provider_name}: {len(content)} bytes "
                f"(sha256:{digest})"
            )
            return content
        if "file" not in config:
            raise ProviderLoadError(
                f"Provider '{provider_name}' must define either 'url' or 'file'"
            )
        path = str(config["file"])
        config_dir = os.path.dirname(self.config_path)
        candidates = (os.path.join(config_dir, path), os.path.join(config_dir, "provider", path))
        for absolute_path in candidates:
            if os.path.exists(absolute_path):
                with open(absolute_path, "rb") as handle:
                    content = handle.read()
                digest = hashlib.sha256(content).hexdigest()[:12]
                logger.dim(
                    f"Read provider {provider_name} from {path}: "
                    f"{len(content)} bytes (sha256:{digest})"
                )
                return content
        raise ProviderLoadError(
            f"File for provider '{provider_name}' not found: {path}"
        )

    def _decode_content(
        self, content: bytes, config: ProviderConfig
    ) -> str:
        provider_name = str(config.get("name", "unknown"))
        secret_keys = [
            str(value)
            for value in (config.get("age_secret_key"), self.global_age_secret_key)
            if value
        ]
        if secret_keys:
            try:
                if age.is_age_encrypted(content):
                    content = age.decrypt_bytes(content, *secret_keys)
                    logger.dim(
                        f"Decrypted age-encrypted content for {provider_name}"
                    )
            except Exception as exc:
                raise ProviderLoadError(
                    f"Failed to decrypt provider '{provider_name}': {exc}"
                ) from exc
        try:
            return content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ProviderLoadError(
                f"Provider '{provider_name}' is not valid UTF-8"
            ) from exc
