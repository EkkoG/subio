from collections.abc import Callable
from dataclasses import dataclass

from subio_v2.formats import normalize_format


@dataclass(frozen=True)
class TargetCommonPolicy:
    tfo: bool
    mptcp: bool
    dialer_proxy: bool

    def as_feature_map(self) -> dict[str, bool]:
        return {
            "tfo": self.tfo,
            "mptcp": self.mptcp,
            "dialer_proxy": self.dialer_proxy,
        }


def _clash_family_protocols(dialect: str) -> frozenset[str]:
    import subio_v2.protocols as protocol_registry

    return frozenset(
        descriptor.protocol.value
        for descriptor in protocol_registry.all()
        if descriptor.supports_dialect(dialect)
    )


def _surge_protocols() -> frozenset[str]:
    from subio_v2.surge.codecs import SURGE_NODE_PROTOCOLS

    return frozenset(SURGE_NODE_PROTOCOLS)


def _link_protocols(target: str) -> frozenset[str]:
    from subio_v2.links import protocols_for_target as link_protocols_for_target

    return link_protocols_for_target(target)


_TARGET_PROTOCOL_PROVIDERS: dict[str, Callable[[], frozenset[str]]] = {
    "mihomo": lambda: _clash_family_protocols("mihomo"),
    "clash": lambda: _clash_family_protocols("clash"),
    "stash": lambda: _clash_family_protocols("stash"),
    "surge": _surge_protocols,
    "dae": lambda: _link_protocols("dae"),
    "v2rayn": lambda: _link_protocols("v2rayn"),
}

_TARGET_COMMON_POLICIES = {
    "mihomo": TargetCommonPolicy(tfo=True, mptcp=True, dialer_proxy=True),
    "clash": TargetCommonPolicy(tfo=False, mptcp=False, dialer_proxy=False),
    "stash": TargetCommonPolicy(tfo=True, mptcp=False, dialer_proxy=True),
    "surge": TargetCommonPolicy(tfo=True, mptcp=False, dialer_proxy=True),
    "dae": TargetCommonPolicy(tfo=False, mptcp=True, dialer_proxy=True),
    "v2rayn": TargetCommonPolicy(tfo=False, mptcp=False, dialer_proxy=False),
}


def protocols_for_target(platform: str) -> frozenset[str]:
    provider = _TARGET_PROTOCOL_PROVIDERS.get(normalize_format(platform))
    return provider() if provider else frozenset()


def target_platforms() -> frozenset[str]:
    return frozenset(_TARGET_PROTOCOL_PROVIDERS)


def common_policy_for_target(platform: str) -> TargetCommonPolicy | None:
    return _TARGET_COMMON_POLICIES.get(normalize_format(platform))
