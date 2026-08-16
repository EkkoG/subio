from typing import Callable, Dict

from subio_v2.emitter.base import BaseEmitter
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.dae import DaeEmitter
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.emitter.stash import StashEmitter
from subio_v2.emitter.v2rayn import V2RayNEmitter
from subio_v2.platforms import normalize_platform


class EmitterFactory:
    _factories: Dict[str, Callable[[], BaseEmitter]] = {
        "clash": lambda: ClashEmitter(platform="clash"),
        "mihomo": lambda: ClashEmitter(platform="clash-meta"),
        "stash": StashEmitter,
        "surge": SurgeEmitter,
        "v2rayn": V2RayNEmitter,
        "dae": DaeEmitter,
    }

    @classmethod
    def get_emitter(cls, emitter_type: str) -> BaseEmitter | None:
        factory = cls._factories.get(normalize_platform(emitter_type))
        return factory() if factory else None
