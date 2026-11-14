"""Build subscription URLs from configuration without loading source data."""

from dataclasses import dataclass, field
import re
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from subio_v2.adapters.catalog import normalize_format
from subio_v2.workflow.config import RunConfig
from subio_v2.workflow.parameters import (
    RENDER_TOKEN_PATTERN,
    ParameterError,
    normalize_parameters,
)


@dataclass(frozen=True)
class SubscriptionLink:
    file_name: str
    target: str
    url: str = field(repr=False)
    install_url: str | None = field(default=None, repr=False)


def _base_url(value: str) -> str:
    try:
        if not value or any(char.isspace() or ord(char) < 32 or ord(char) == 127
                            for char in value) or any(char in value for char in "\\?#"):
            raise ValueError
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or (parsed.port is not None and parsed.port == 0)):
            raise ValueError
        if re.search(r"%(?![0-9A-Fa-f]{2})", parsed.path):
            raise ValueError
        return urlunsplit((parsed.scheme, parsed.netloc,
                           quote(parsed.path.rstrip("/"), safe="/%:@-._~!$&'()*+,;="), "", ""))
    except ValueError:
        raise ParameterError("Base URL must be HTTP(S), with a host and without credentials, query or fragment") from None


def build_subscription_links(
    config: RunConfig,
    base_url: str,
    token: str,
    *,
    artifact_name: str | None = None,
    parameter_pairs: tuple[tuple[str, str], ...] = (),
) -> list[SubscriptionLink]:
    base = _base_url(base_url)
    if not RENDER_TOKEN_PATTERN.fullmatch(token):
        raise ParameterError("SUBIO_RENDER_TOKEN is missing or invalid")
    links = []
    for artifact in config.artifacts:
        for file_name, _ in artifact.output_names():
            if "/" in file_name or "\\" in file_name or file_name in {".", ".."}:
                raise ParameterError("Subscription names must be filenames")
            if artifact_name is not None and file_name != artifact_name:
                continue
            normalize_parameters(artifact.params, parameter_pairs)
            try:
                path = "/subscription/" + quote(file_name, safe="")
                query = urlencode((("token", token), *parameter_pairs), quote_via=quote)
                if len((path + "?" + query).encode("ascii")) > 8192:
                    raise ParameterError("Subscription request exceeds the service size limit")
            except UnicodeError:
                raise ParameterError("Subscription request must use valid UTF-8") from None
            url = base + path + "?" + query
            target = normalize_format(artifact.artifact_type)
            install_url = None
            if artifact.template and not (artifact.age_public_key or config.age_public_key):
                if target in {"mihomo", "clash"}:
                    install_url = "clash://install-config?" + urlencode({"url": url}, quote_via=quote)
                elif target == "surge":
                    install_url = "surge:///install-config?" + urlencode({"url": url}, quote_via=quote)
            links.append(SubscriptionLink(file_name, target, url, install_url))
    if not links:
        raise ParameterError("No matching subscription output is configured")
    return links
