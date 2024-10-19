import yaml

from ..const import SubIOPlatform
from subio.model import Base
from subio.tools.tools import build_proxy_cache
import copy

def convert_privacy_node(data: list[Base], type: SubIOPlatform) -> list[Base]:
    cache = build_proxy_cache(data)

    def mm(x: Base) -> Base:
        if x.privacy_endpoint and x.dialer_proxy:
            raise ValueError(f"节点 {x.name} 不能同时指定 privacy_endpoint 和 dialer_proxy")

        if x.privacy_endpoint:
            privacy_node = cache.get(x.privacy_endpoint)
            if privacy_node is None:
                raise ValueError(f"找不到 {x.privacy_endpoint}")
            privacy_node = copy.copy(privacy_node)
            x.privacy_endpoint_node = privacy_node

        if x.dialer_proxy:
            dialer_node = cache.get(x.dialer_proxy)
            if dialer_node is None:
                raise ValueError(f"找不到 {x.dialer_proxy}")
            dialer_node = copy.copy(dialer_node)
            x.dialer_proxy_node = dialer_node

        return x
    return list(map(mm, data))

def to_v2rayn(data: list[Base]) -> str:
    return "\n".join(map(lambda x: x.to_v2rayn(), data))

def _to_dae_line(x: Base, data: list[Base]) -> str:

    line = x.to_v2rayn()
    if x.dialer_proxy and x.dialer_proxy_node:
        line = f"{line} -> {x.dialer_proxy_node.to_v2rayn()}"

    if x.privacy_endpoint and x.privacy_endpoint_node:
        line = f"{x.privacy_endpoint_node.to_v2rayn()} -> {line}"
    return line
    

def to_dae(data: list[Base]) -> str:
    def mm(x: Base) -> dict:
        line = _to_dae_line(x, data)
        return f"'{x.name}': '{line}'"

    return "\n".join(map(mm, data))

def to_dae_subscription(data: list[Base]) -> str:
    return "\n".join(map(lambda x: _to_dae_line(x, data), data))

def to_surge(data: list[Base]) -> str:
    return "\n".join(map(lambda x: x.to_surge(), data))


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True

def to_clash_meta(data: list[Base]) -> str:
    def mm(x: Base) -> dict:
        new = None
        if x.privacy_endpoint and x.privacy_endpoint_node:
            new = copy.copy(x.privacy_endpoint_node)
            new.dialer_proxy = x.name
        else:
            new = copy.copy(x)
            
        return {k: v for k, v in new.to_clash_meta().items() if v}
    dict_data = list(map(mm, data))
    return yaml.dump(dict_data, Dumper=NoAliasDumper, allow_unicode=True)


def to_name(data: list[Base]) -> list[str]:
    return list(map(lambda x: x.name, data))


# 只接受字符串数组参数
def list_to_names(type: SubIOPlatform, nodelist: list[str]):
    if type in SubIOPlatform.clash_like():
        return nodelist
    if type == SubIOPlatform.DAE:
        return ", ".join(map(lambda x: f"'{x}'", nodelist))
    if type == SubIOPlatform.SURGE:
        return ", ".join(nodelist)
    return nodelist
