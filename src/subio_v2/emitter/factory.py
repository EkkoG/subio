from typing import Dict
from src.subio_v2.emitter.base import BaseEmitter
from src.subio_v2.emitter.clash import ClashEmitter
from src.subio_v2.emitter.surge import SurgeEmitter
from src.subio_v2.emitter.v2rayn import V2RayNEmitter

class EmitterFactory:
    _emitters: Dict[str, BaseEmitter] = {}

    @classmethod
    def get_emitter(cls, emitter_type: str) -> BaseEmitter | None:
         if not cls._emitters:
             cls._initialize_emitters()
         return cls._emitters.get(emitter_type)

    @classmethod
    def _initialize_emitters(cls):
        clash = ClashEmitter()
        surge = SurgeEmitter()
        v2rayn = V2RayNEmitter()
        
        cls._emitters["clash"] = clash
        cls._emitters["clash-meta"] = clash
        cls._emitters["stash"] = clash
        cls._emitters["surge"] = surge
        cls._emitters["v2rayn"] = v2rayn

