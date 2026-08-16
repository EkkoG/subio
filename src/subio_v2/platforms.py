from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformSpec:
    name: str
    aliases: frozenset[str] = frozenset()
    deprecated: bool = False
    replacement: str | None = None


@dataclass(frozen=True)
class PlatformResolution:
    requested: str
    canonical: str
    alias: bool
    deprecated: bool
    replacement: str | None


PLATFORM_SPECS: dict[str, PlatformSpec] = {
    "mihomo": PlatformSpec("mihomo", aliases=frozenset({"clash-meta"})),
    "clash": PlatformSpec("clash", deprecated=True, replacement="mihomo"),
    "stash": PlatformSpec("stash"),
    "surge": PlatformSpec("surge"),
    "dae": PlatformSpec("dae"),
    "v2rayn": PlatformSpec("v2rayn"),
    "subio": PlatformSpec("subio"),
}


_PLATFORM_NAMES = {
    name: spec
    for spec in PLATFORM_SPECS.values()
    for name in (spec.name, *spec.aliases)
}


def resolve_platform(platform: str) -> PlatformResolution | None:
    spec = _PLATFORM_NAMES.get(platform)
    if spec is None:
        return None
    return PlatformResolution(
        requested=platform,
        canonical=spec.name,
        alias=platform != spec.name,
        deprecated=spec.deprecated,
        replacement=spec.replacement,
    )


def normalize_platform(platform: str) -> str:
    resolution = resolve_platform(platform)
    return resolution.canonical if resolution is not None else platform
