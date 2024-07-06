platform_map = {
    "clash": "Clash",
    "clash-meta": "Clash.Meta",
    "stash": "Stash",
    "surge": "Surge",
    "dae": "Dae",
    "v2rayn": "v2rayN",
}

from enum import StrEnum


class SubIOPlatform(StrEnum):
    CLASH = "clash"
    CLASH_META = "clash-meta"
    STASH = "stash"
    SURGE = "surge"
    DAE = "dae"
    SUBIO = "subio"
    V2RAYN = "v2rayn"

    def __str__(self):
        return platform_map[self.value]

    @staticmethod
    def supported_provider():
        return [
            SubIOPlatform.CLASH,
            SubIOPlatform.CLASH_META,
            SubIOPlatform.STASH,
            SubIOPlatform.SURGE,
            SubIOPlatform.DAE,
            SubIOPlatform.SUBIO,
            SubIOPlatform.V2RAYN,
        ]

    @staticmethod
    def supported_artifact():
        return [
            SubIOPlatform.CLASH,
            SubIOPlatform.CLASH_META,
            SubIOPlatform.STASH,
            SubIOPlatform.SURGE,
            SubIOPlatform.DAE,
            SubIOPlatform.V2RAYN,
        ]

    @staticmethod
    def clash_like():
        return [SubIOPlatform.CLASH, SubIOPlatform.CLASH_META, SubIOPlatform.STASH]

    @staticmethod
    def surge_like():
        return [SubIOPlatform.SURGE]
