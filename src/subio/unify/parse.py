from .parser import clash, v2rayn, subio
from ..const import SubIOPlatform
from subio.model import Base
from subio.log import log


def parse(origin: SubIOPlatform, file: str) -> list[Base]:
    if origin == "subio":
        return subio.parse(file)

    if origin == "clash" or origin == "clash-meta" or origin == "stash":
        nodes = clash.parse(file)
        return nodes
    if origin == "v2rayn":
        nodes = v2rayn.parse(file)
        return nodes
    if origin == "surge":
        log.logger.error("Surge format is not supported yet")
    if origin == "quantumultx":
        log.logger.error("QuantumultX format is not supported yet")
    if origin == "dae":
        log.logger.error("Dae format is not supported yet")
    return []
