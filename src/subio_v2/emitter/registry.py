from collections.abc import Callable
from types import MappingProxyType

from subio_v2.emitter.base import BaseEmitter
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.dae import DaeEmitter
from subio_v2.emitter.stash import StashEmitter
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.emitter.v2rayn import V2RayNEmitter
from subio_v2.platforms import normalize_platform

_CONSTRUCTORS = MappingProxyType(
    {
        "clash": lambda: ClashEmitter(platform="clash"),
        "mihomo": lambda: ClashEmitter(platform="mihomo"),
        "stash": StashEmitter,
        "surge": SurgeEmitter,
        "v2rayn": V2RayNEmitter,
        "dae": DaeEmitter,
    }
)


def get_emitter(emitter_type: str) -> BaseEmitter | None:
    constructor: Callable[[], BaseEmitter] | None = _CONSTRUCTORS.get(
        normalize_platform(emitter_type)
    )
    return constructor() if constructor else None
