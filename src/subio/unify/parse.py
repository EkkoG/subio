
from .parser import clash, surge
from . import tools
from ..const import SubIOPlatform
from ..tools.tools import load_with_ext

def parse(origin, file):
    if origin == 'subio':
        d = load_with_ext(file)
        return d['nodes']

    unify_map = tools.build_map(origin)
    if origin in SubIOPlatform.clash_like(): 
        nodes = clash.parse(file)

        return clash.origin_to_unify_trans(nodes, unify_map)
    elif origin in SubIOPlatform.surge_like():
        nodes = surge.parse(file)

        return surge.origin_to_unify_trans(nodes, unify_map)
    return []
