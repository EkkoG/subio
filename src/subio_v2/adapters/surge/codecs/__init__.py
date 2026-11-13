from subio_v2.adapters.surge.codecs import (
    anytls,
    direct,
    http,
    hysteria2,
    masque,
    reject,
    shadowsocks,
    snell,
    socks5,
    ssh,
    tailscale,
    trojan,
    trusttunnel,
    tuic,
    vless,
    vmess,
    wireguard,
)
from subio_v2.adapters.surge.codecs._base import (
    DEFAULT_SURGE_TARGET as DEFAULT_SURGE_TARGET,
)
from subio_v2.adapters.surge.codecs._base import (
    SURGE_COMMON_PARAMETER_PATHS as SURGE_COMMON_PARAMETER_PATHS,
)
from subio_v2.adapters.surge.codecs._base import (
    SURGE_COMMON_PARAMETERS as SURGE_COMMON_PARAMETERS,
)
from subio_v2.adapters.surge.codecs._base import (
    SurgeCodecSpec as SurgeCodecSpec,
)
from subio_v2.adapters.surge.codecs._base import (
    SurgePolicyKind as SurgePolicyKind,
)
from subio_v2.adapters.surge.codecs._base import (
    SurgeUdpBehavior as SurgeUdpBehavior,
)
from subio_v2.core.nodes import Protocol

SURGE_CODEC_SPECS = (
    *shadowsocks.CODECS,
    *vmess.CODECS,
    *vless.CODECS,
    *trojan.CODECS,
    *socks5.CODECS,
    *http.CODECS,
    *anytls.CODECS,
    *ssh.CODECS,
    *snell.CODECS,
    *tuic.CODECS,
    *hysteria2.CODECS,
    *wireguard.CODECS,
    *tailscale.CODECS,
    *masque.CODECS,
    *trusttunnel.CODECS,
    *direct.CODECS,
    *reject.CODECS,
)

SURGE_CODEC_BY_KEYWORD = {spec.keyword: spec for spec in SURGE_CODEC_SPECS}
if len(SURGE_CODEC_BY_KEYWORD) != len(SURGE_CODEC_SPECS):
    raise RuntimeError("Duplicate Surge codec keyword")

SURGE_PROTOCOL_CODECS = {}
for _spec_item in SURGE_CODEC_SPECS:
    if (
        _spec_item.protocol is not None
        and _spec_item.protocol not in SURGE_PROTOCOL_CODECS
    ):
        SURGE_PROTOCOL_CODECS[_spec_item.protocol] = _spec_item

SURGE_NODE_PROTOCOLS = frozenset(
    spec.protocol.value
    for spec in SURGE_CODEC_SPECS
    if spec.policy_kind == SurgePolicyKind.NODE and spec.protocol is not None
)
SURGE_PROTOCOL_PARAMETERS = {
    spec.keyword: spec.consumed_parameters
    for spec in SURGE_CODEC_SPECS
    if spec.policy_kind == SurgePolicyKind.NODE
}
SURGE_MULTI_VALUE_PARAMETERS = {
    spec.keyword: spec.multi_value_parameters
    for spec in SURGE_CODEC_SPECS
    if spec.multi_value_parameters
}
SURGE_BUILTIN_ALIAS_TYPES = frozenset(
    {"direct", "reject", "reject-drop", "reject-no-drop", "reject-tinygif"}
)


def get_surge_codec(keyword: str) -> SurgeCodecSpec | None:
    return SURGE_CODEC_BY_KEYWORD.get(keyword.lower())


def get_surge_protocol_codec(protocol: Protocol) -> SurgeCodecSpec | None:
    return SURGE_PROTOCOL_CODECS.get(protocol)
