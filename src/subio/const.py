platform_map = {
    'clash': 'Clash',
    'clash-meta': 'Clash.Meta',
    'stash': 'Stash',
    'surge': 'Surge',
    'dae': 'Dae'
}

from enum import EnumMeta

class MyEnumMeta(EnumMeta): 
    def __contains__(cls, item): 
        return isinstance(item, cls) or item in [v.value for v in cls.__members__.values()] 

class SubIOPlatform(MyEnumMeta):
    CLASH = 'clash'
    CLASH_META = 'clash-meta'
    STASH = 'stash'
    SURGE = 'surge'
    DAE = 'dae'
    CUSTOM = 'custom'
    SUBIO = 'subio'

    @staticmethod
    def supported_provider():
        return [SubIOPlatform.CLASH, SubIOPlatform.CLASH_META, SubIOPlatform.STASH, SubIOPlatform.CUSTOM, SubIOPlatform.SURGE, SubIOPlatform.DAE, SubIOPlatform.SUBIO]

    @staticmethod
    def supported_artifact():
        return [SubIOPlatform.CLASH, SubIOPlatform.CLASH_META, SubIOPlatform.STASH, SubIOPlatform.SURGE, SubIOPlatform.DAE]

    @staticmethod
    def clash_like():
        return [SubIOPlatform.CLASH, SubIOPlatform.CLASH_META, SubIOPlatform.STASH]
    
    @staticmethod
    def surge_like():
        return [SubIOPlatform.SURGE]

