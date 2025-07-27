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

        # if x.privacy_endpoint:
        #     privacy_node: Base = cache.get(x.privacy_endpoint)
        #     if privacy_node is None:
        #         raise ValueError(f"找不到 {x.privacy_endpoint}")
        #     privacy_node = copy.copy(privacy_node)
        #     privacy_node.dialer_proxy = x.name
        #     privacy_node.dialer_proxy_node = x
        #     if type in SubIOPlatform.clash_like():
        #         privacy_node.name = f"{x.name} -> {privacy_node.name}"
        #     # 为什么要返回 privacy_node 而不是 x？
        #     # 对于 dae 来说，只要不改变节点的 name 和 privacy_node.name 就行，因为改了以后，会和 dae 本身的节点名组合重复
        #     # dae 既可以处理 privacy_node 也可以处理 dialer_proxy_node，只是一个顺序问题
        #     # 
        #     # 对于 clash 来说，需要转换成 privacy_node
        #     # clash 需要解决的问题
        #     # 1. 如果这里不转换，而延迟到渲染时转换, 中间还有一个节点名的转换，会导致渲染的节点信息和策略组中的节点名不一致
        #     #    解决这个问题，需要在节点名的转换中实现相同的逻辑，容易出错
        #     # 
        #     return privacy_node


        # if x.dialer_proxy:
        #     dialer_node: Base = cache.get(x.dialer_proxy)
        #     if dialer_node is None:
        #         raise ValueError(f"找不到 {x.dialer_proxy}")
        #     dialer_node = copy.copy(dialer_node)
        #     x.dialer_proxy_node = dialer_node
        #     return x

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
