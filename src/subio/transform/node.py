import yaml

from ..const import SubIOPlatform
from subio.model import Base
from subio.tools.tools import build_proxy_cache
import copy

def convert_privacy_node(data: list[Base], type: SubIOPlatform) -> list[Base]:
    privacy_cache = build_proxy_cache(data)

    def mm(x: Base) -> Base:
        if x.privacy_endpoint is None:
            return x

        if x.privacy_endpoint not in privacy_cache:
            raise ValueError(f"找不到 {x.privacy_endpoint}")
        # copy, to avoid cache
        privacy_node: Base = copy.copy(privacy_cache[x.privacy_endpoint])
        privacy_node.dialer_proxy = x.name
        if type in SubIOPlatform.clash_like():
            privacy_node.name = f"{x.name} -> {privacy_node.name}"
        return privacy_node
    return list(map(mm, data))

def to_v2rayn(data: list[Base]) -> str:
    return "\n".join(map(lambda x: x.to_v2rayn(), data))

def _to_dae_line(x: Base, data: list[Base]) -> str:
    proxy_cache = build_proxy_cache(data)

    line = x.to_v2rayn()
    if x.dialer_proxy is not None:
        dialer_proxy: Base = proxy_cache.get(x.dialer_proxy)
        if dialer_proxy is None:
            raise ValueError(f"找不到 {x.dialer_proxy}")
        line = f"{line} -> {dialer_proxy.to_v2rayn()}"

    if x.privacy_endpoint is not None:
        privacy_proxy: Base = proxy_cache.get(x.privacy_endpoint)
        if privacy_proxy is None:
            raise ValueError(f"找不到 {x.privacy_endpoint}")
        line = f"{privacy_proxy.to_v2rayn()} -> {line}"
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
        return {k: v for k, v in x.to_clash_meta().items() if v is not None}
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
