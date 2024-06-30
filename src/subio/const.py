platform_map = {
    "clash": "Clash",
    "clash-meta": "Clash.Meta",
    "stash": "Stash",
    "surge": "Surge",
    "dae": "Dae",
}

from enum import StrEnum


class SubIOPlatform(StrEnum):
    CLASH = "clash"
    CLASH_META = "clash-meta"
    STASH = "stash"
    SURGE = "surge"
    DAE = "dae"
    SUBIO = "subio"

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
        ]

    @staticmethod
    def supported_artifact():
        return [
            SubIOPlatform.CLASH,
            SubIOPlatform.CLASH_META,
            SubIOPlatform.STASH,
            SubIOPlatform.SURGE,
            SubIOPlatform.DAE,
        ]

    @staticmethod
    def clash_like():
        return [SubIOPlatform.CLASH, SubIOPlatform.CLASH_META, SubIOPlatform.STASH]

    @staticmethod
    def surge_like():
        return [SubIOPlatform.SURGE]
