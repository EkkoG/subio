from typing import Callable, Dict

from subio_v2.emitter.base import BaseEmitter
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.dae import DaeEmitter
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.emitter.v2rayn import V2RayNEmitter


class EmitterFactory:
    _factories: Dict[str, Callable[[], BaseEmitter]] = {
        "clash": lambda: ClashEmitter(platform="clash"),
        "clash-meta": lambda: ClashEmitter(platform="clash-meta"),
        "stash": lambda: ClashEmitter(platform="stash"),
        "surge": SurgeEmitter,
        "v2rayn": V2RayNEmitter,
        "dae": DaeEmitter,
    }

    @classmethod
    def get_emitter(cls, emitter_type: str) -> BaseEmitter | None:
        factory = cls._factories.get(emitter_type)
        return factory() if factory else None
