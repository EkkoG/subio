from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


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


@dataclass(frozen=True)
class FormatSpec:
    name: str
    aliases: frozenset[str] = frozenset()
    deprecated: bool = False
    replacement: str | None = None
    parser_factory: Callable[..., Any] | None = None
    emitter_factory: Callable[[], Any] | None = None
    common_policy: TargetCommonPolicy | None = None


@dataclass(frozen=True)
class FormatResolution:
    requested: str
    canonical: str
    alias: bool
    deprecated: bool
    replacement: str | None


def _clash_parser(**_: Any) -> Any:
    from subio_v2.dialect import DialectContext
    from subio_v2.parser.clash import ClashParser

    return ClashParser(DialectContext("mihomo", "yaml"))


def _clash_parser_for_clash(**_: Any) -> Any:
    from subio_v2.dialect import DialectContext
    from subio_v2.parser.clash import ClashParser

    return ClashParser(DialectContext("clash", "yaml"))


def _stash_parser(**_: Any) -> Any:
    from subio_v2.parser.stash import StashParser

    return StashParser()


def _surge_parser(
    *, source_kind: str = "unknown", allow_unsafe_external: bool = False, **_: Any
) -> Any:
    from subio_v2.parser.surge import SurgeParser

    return SurgeParser(
        source_kind=source_kind,
        allow_unsafe_external=allow_unsafe_external,
    )


def _subio_parser(**_: Any) -> Any:
    from subio_v2.parser.subio import SubioParser

    return SubioParser()


def _v2rayn_parser(**_: Any) -> Any:
    from subio_v2.parser.v2rayn import V2RayNParser

    return V2RayNParser()


def _clash_emitter() -> Any:
    from subio_v2.emitter.clash import ClashEmitter

    return ClashEmitter(platform="mihomo")


def _clash_emitter_for_clash() -> Any:
    from subio_v2.emitter.clash import ClashEmitter

    return ClashEmitter(platform="clash")


def _stash_emitter() -> Any:
    from subio_v2.emitter.stash import StashEmitter

    return StashEmitter()


def _surge_emitter() -> Any:
    from subio_v2.emitter.surge import SurgeEmitter

    return SurgeEmitter()


def _dae_emitter() -> Any:
    from subio_v2.emitter.dae import DaeEmitter

    return DaeEmitter()


def _v2rayn_emitter() -> Any:
    from subio_v2.emitter.v2rayn import V2RayNEmitter

    return V2RayNEmitter()


_FORMAT_SPECS = (
    FormatSpec(
        "mihomo",
        aliases=frozenset({"clash-meta"}),
        parser_factory=_clash_parser,
        emitter_factory=_clash_emitter,
        common_policy=TargetCommonPolicy(tfo=True, mptcp=True, dialer_proxy=True),
    ),
    FormatSpec(
        "clash",
        deprecated=True,
        replacement="mihomo",
        parser_factory=_clash_parser_for_clash,
        emitter_factory=_clash_emitter_for_clash,
        common_policy=TargetCommonPolicy(tfo=False, mptcp=False, dialer_proxy=False),
    ),
    FormatSpec(
        "stash",
        parser_factory=_stash_parser,
        emitter_factory=_stash_emitter,
        common_policy=TargetCommonPolicy(tfo=True, mptcp=False, dialer_proxy=True),
    ),
    FormatSpec(
        "surge",
        parser_factory=_surge_parser,
        emitter_factory=_surge_emitter,
        common_policy=TargetCommonPolicy(tfo=True, mptcp=False, dialer_proxy=True),
    ),
    FormatSpec(
        "dae",
        emitter_factory=_dae_emitter,
        common_policy=TargetCommonPolicy(tfo=False, mptcp=True, dialer_proxy=True),
    ),
    FormatSpec(
        "v2rayn",
        parser_factory=_v2rayn_parser,
        emitter_factory=_v2rayn_emitter,
        common_policy=TargetCommonPolicy(tfo=False, mptcp=False, dialer_proxy=False),
    ),
    FormatSpec("subio", parser_factory=_subio_parser),
)


_FORMAT_BY_NAME = {spec.name: spec for spec in _FORMAT_SPECS}
_FORMAT_BY_REQUESTED = {
    requested: spec
    for spec in _FORMAT_SPECS
    for requested in (spec.name, *spec.aliases)
}
if len(_FORMAT_BY_NAME) != len(_FORMAT_SPECS):
    raise RuntimeError("Duplicate format name")
if len(_FORMAT_BY_REQUESTED) != sum(1 + len(spec.aliases) for spec in _FORMAT_SPECS):
    raise RuntimeError("Duplicate format alias")


def all_formats() -> tuple[FormatSpec, ...]:
    return _FORMAT_SPECS


def resolve_format(format_name: str) -> FormatResolution | None:
    spec = _FORMAT_BY_REQUESTED.get(format_name)
    if spec is None:
        return None
    alias = format_name != spec.name
    return FormatResolution(
        requested=format_name,
        canonical=spec.name,
        alias=alias,
        deprecated=spec.deprecated,
        replacement=spec.name if alias else spec.replacement,
    )


def normalize_format(format_name: str) -> str:
    resolution = resolve_format(format_name)
    return resolution.canonical if resolution is not None else format_name


def get_format(format_name: str) -> FormatSpec | None:
    return _FORMAT_BY_REQUESTED.get(format_name)


def common_policy_for_format(format_name: str) -> TargetCommonPolicy | None:
    spec = get_format(format_name)
    return spec.common_policy if spec is not None else None


def get_parser(
    format_name: str,
    *,
    source_kind: str = "unknown",
    allow_unsafe_external: bool = False,
) -> Any | None:
    spec = get_format(format_name)
    if spec is None or spec.parser_factory is None:
        return None
    return spec.parser_factory(
        source_kind=source_kind,
        allow_unsafe_external=allow_unsafe_external,
    )


def get_emitter(format_name: str) -> Any | None:
    spec = get_format(format_name)
    return spec.emitter_factory() if spec and spec.emitter_factory else None
