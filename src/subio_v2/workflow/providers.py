import copy
import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from subio_v2.adapters.catalog import get_parser
from subio_v2.core.errors import ProviderLoadError
from subio_v2.core.nodes import Node
from subio_v2.core.parameters import ParameterValue
from subio_v2.core.results import ConversionIssue, ParseResult
from subio_v2.infrastructure import age
from subio_v2.infrastructure.logging import logger
from subio_v2.infrastructure.remote import (
    RemoteLoadError,
    RemoteMetadata,
    RunRemoteLoader,
)
from subio_v2.workflow.config import ProviderConfig, RunConfig
from subio_v2.workflow.transforms import filter_nodes, rename_nodes, set_dialer_proxy


@dataclass(frozen=True)
class ProviderSummary:
    name: str
    content_sha256: str
    parsed_nodes: int
    selected_nodes: int


@dataclass(frozen=True)
class ProviderLoadResult:
    providers: dict[str, list[Node]]
    issues: dict[str, list[ConversionIssue]]
    metadata: dict[str, RemoteMetadata] = field(default_factory=dict)
    summaries: dict[str, ProviderSummary] = field(default_factory=dict)


@dataclass(frozen=True)
class PreparedProvider:
    config: ProviderConfig = field(repr=False)
    content_sha256: str
    metadata: RemoteMetadata | None = field(default=None, repr=False)
    _static: ProviderLoadResult | None = field(default=None, repr=False)
    _document: object = field(default=None, repr=False)

    def bind(self, parameters: Mapping[str, ParameterValue]) -> ProviderLoadResult:
        if self._static is not None:
            return copy.deepcopy(self._static)
        parser = get_parser(
            self.config.provider_type,
            source_kind="local",
            parameterized=True,
            parameters=parameters,
        )
        # The adapter binder copies the private document before invoking node codecs.
        parsed = parser.parse_document(self._document)
        return ProviderLoaderService._finish_parse(
            parsed, self.config, self.content_sha256, self.metadata
        )


class ProviderLoaderService:
    def __init__(self, config_path: str, global_age_secret_key: str = ""):
        self.config_path = config_path
        self.global_age_secret_key = global_age_secret_key
        self._prepared_content: dict[tuple[str | None, ...], bytes] = {}

    def prepare(
        self, config: ProviderConfig, remote_loader: RunRemoteLoader
    ) -> PreparedProvider:
        parser = get_parser(
            config.provider_type,
            source_kind="remote" if config.url else "local",
            allow_unsafe_external=config.allow_unsafe_external,
            parameterized=config.parameterized,
            parameters={} if config.parameterized else None,
        )
        if parser is None:
            raise ProviderLoadError("Unsupported provider type")
        source_key = (config.url, config.file, config.user_agent)
        if config.url:
            # The run loader owns remote deduplication and last-result metadata.
            content_bytes = self._fetch_content(config, remote_loader)
        else:
            if source_key not in self._prepared_content:
                self._prepared_content[source_key] = self._fetch_content(config, remote_loader)
            content_bytes = self._prepared_content[source_key]
        if not content_bytes:
            raise ProviderLoadError("Provider returned empty content")
        content = self._decode_content(content_bytes, config)
        digest = hashlib.sha256(content_bytes).hexdigest()
        metadata = (
            remote_loader.last_result.metadata
            if config.url and remote_loader.last_result is not None else None
        )
        if config.parameterized:
            return PreparedProvider(
                config, digest, metadata, _document=parser.decode_source(content)
            )
        return PreparedProvider(
            config, digest, metadata,
            _static=self._finish_parse(parser.parse_result(content), config, digest, metadata),
        )

    def load(
        self,
        config: RunConfig,
        remote_loader: RunRemoteLoader,
        *,
        parameters: Mapping[str, ParameterValue] | None = None,
    ) -> ProviderLoadResult:
        if parameters is None and any(item.parameterized for item in config.providers):
            raise ProviderLoadError("Parameterized providers require runtime bindings")
        providers: dict[str, list[Node]] = {}
        provider_issues: dict[str, list[ConversionIssue]] = {}
        provider_metadata: dict[str, RemoteMetadata] = {}
        provider_summaries: dict[str, ProviderSummary] = {}
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
                if provider_config.allow_unsafe_external:
                    logger.warning(
                        f"Provider '{name}' enables remote Surge External passthrough; "
                        "the generated Surge configuration may contain program entries "
                        "supplied by that remote provider"
                    )
                try:
                    parser = get_parser(
                        provider_type,
                        source_kind="remote" if provider_config.url else "local",
                        allow_unsafe_external=provider_config.allow_unsafe_external,
                        parameterized=provider_config.parameterized,
                        parameters=parameters if provider_config.parameterized else None,
                    )
                except ValueError as exc:
                    raise ProviderLoadError(str(exc)) from exc
                content_bytes = self._fetch_content(provider_config, remote_loader)
                if provider_config.url and remote_loader.last_result is not None:
                    provider_metadata[name] = remote_loader.last_result.metadata
                if not content_bytes:
                    raise ProviderLoadError(f"Provider '{name}' returned empty content")
                content = self._decode_content(content_bytes, provider_config)
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
                result = self._finish_parse(
                    parse_result, provider_config,
                    hashlib.sha256(content_bytes).hexdigest(),
                )
                nodes = result.providers[name]
                provider_issues.update(result.issues)
                provider_summaries.update(result.summaries)
                logger.info(
                    f"Provider [bold cyan]{name}[/bold cyan] loaded: "
                    f"[bold]{len(nodes)}[/bold] nodes"
                )
                providers[name] = nodes
        return ProviderLoadResult(
            providers,
            provider_issues,
            provider_metadata,
            provider_summaries,
        )

    @staticmethod
    def _finish_parse(
        result: ParseResult,
        config: ProviderConfig,
        digest: str,
        metadata: RemoteMetadata | None = None,
    ) -> ProviderLoadResult:
        name = config.name
        for node in result.nodes:
            node.source_provider = name
        nodes = ProviderLoaderService._process_nodes(result.nodes, config)
        return ProviderLoadResult(
            {name: nodes},
            {name: [replace(issue, source=name) for issue in result.issues]},
            {name: metadata} if metadata is not None else {},
            {name: ProviderSummary(name, digest, len(result.nodes), len(nodes))},
        )

    @staticmethod
    def _process_nodes(
        nodes: list[Node], provider_config: ProviderConfig
    ) -> list[Node]:
        rename = provider_config.rename
        if rename is not None:
            nodes = rename_nodes(nodes, rename)
        dialer_proxy = provider_config.dialer_proxy
        if dialer_proxy:
            nodes = set_dialer_proxy(nodes, str(dialer_proxy))
        filters = provider_config.filters
        if filters is not None:
            nodes = filter_nodes(nodes, filters)
        return nodes

    def _fetch_content(
        self, config: ProviderConfig, remote_loader: RunRemoteLoader
    ) -> bytes:
        provider_name = config.name
        if config.url:
            headers = {}
            if config.user_agent:
                headers["User-Agent"] = config.user_agent
            try:
                content = remote_loader.fetch(config.url, headers=headers)
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
        if not config.file:
            raise ProviderLoadError(
                f"Provider '{provider_name}' must define either 'url' or 'file'"
            )
        path = config.file
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
        provider_name = config.name
        secret_keys = [
            str(value)
            for value in (config.age_secret_key, self.global_age_secret_key)
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
