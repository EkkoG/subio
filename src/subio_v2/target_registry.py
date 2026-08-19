from collections.abc import Callable

from subio_v2.platforms import normalize_platform


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
    from subio_v2.emitter.link import link_protocols_for_target

    return link_protocols_for_target(target)


_TARGET_PROTOCOL_PROVIDERS: dict[str, Callable[[], frozenset[str]]] = {
    "mihomo": lambda: _clash_family_protocols("mihomo"),
    "clash": lambda: _clash_family_protocols("clash"),
    "stash": lambda: _clash_family_protocols("stash"),
    "surge": _surge_protocols,
    "dae": lambda: _link_protocols("dae"),
    "v2rayn": lambda: _link_protocols("v2rayn"),
}


def protocols_for_target(platform: str) -> frozenset[str]:
    provider = _TARGET_PROTOCOL_PROVIDERS.get(normalize_platform(platform))
    return provider() if provider else frozenset()


def target_platforms() -> frozenset[str]:
    return frozenset(_TARGET_PROTOCOL_PROVIDERS)
