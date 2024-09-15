import yaml

from ..const import SubIOPlatform
from subio.model import Base


def to_v2rayn(data: list[Base]) -> str:
    return "\n".join(map(lambda x: x.to_v2rayn(), data))


def to_dae(data: list[Base]) -> str:
    def mm(x: Base) -> dict:
        line = x.to_v2rayn()
        return f"'{x.name}': {line}"

    return "\n".join(map(mm, data))


def to_surge(data: list[Base]) -> str:
    return "\n".join(map(lambda x: x.to_surge(), data))


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def to_clash_meta(data: list[Base]):
    def mm(x: Base) -> dict:
        return {k: v for k, v in x.to_clash_meta().items() if v is not None}

    dict_data = list(map(mm, data))
    return yaml.dump(dict_data, Dumper=NoAliasDumper, allow_unicode=True)


def to_name(data):
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
