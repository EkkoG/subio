
from .parser import clash, surge
from . import tools
from ..subio_platform import surge_like, clash_like

def parse(config, origin, sub_text):
    if origin in clash_like: 
        nodes = clash.parse(config, sub_text)

        unify_map = tools.build_map(origin)

        return clash.transform_list(nodes, unify_map)
    elif origin in surge_like:
        nodes = surge.parse(sub_text)

        unify_map = tools.build_map(origin)

        return surge.transform_list(nodes, unify_map)
    return []
