"""
节点过滤器

支持两种使用方式：
1. 直接调用: hk_filter(data)
2. 函数式组合: union(F.hk, F.jp)(data) 或 intersect(F.hk, keyword("IPLC"))(data)
"""

import re
from typing import List, Any, Callable

# 过滤器类型
FilterFunc = Callable[[List[Any]], List[Any]]


def _get_name(item: Any) -> str:
    """获取项目名称"""
    if isinstance(item, str):
        return item
    if hasattr(item, "name"):
        return item.name
    return str(item)


# ============== 基础过滤器 ==============


def regex_filter(data: List[Any], regex: str) -> List[Any]:
    """正则过滤"""
    pattern = re.compile(regex, re.IGNORECASE)
    return [item for item in data if pattern.search(_get_name(item))]


def exclude(data: List[Any], regex: str) -> List[Any]:
    """排除匹配项"""
    pattern = re.compile(regex, re.IGNORECASE)
    return [item for item in data if not pattern.search(_get_name(item))]


# ============== 地区过滤器 ==============


def hk_filter(data: List[Any]) -> List[Any]:
    """香港"""
    return regex_filter(data, r"香港|Hong\s*Kong|HK(?![a-zA-Z])")


def tw_filter(data: List[Any]) -> List[Any]:
    """台湾"""
    return regex_filter(data, r"台湾|Taiwan|TW(?![a-zA-Z])")


def sg_filter(data: List[Any]) -> List[Any]:
    """新加坡"""
    return regex_filter(data, r"新加坡|Singapore|SG(?![a-zA-Z])")


def jp_filter(data: List[Any]) -> List[Any]:
    """日本"""
    return regex_filter(data, r"日本|Japan|JP(?![a-zA-Z])")


def kr_filter(data: List[Any]) -> List[Any]:
    """韩国"""
    return regex_filter(data, r"韩国|Korea|KR(?![a-zA-Z])")


def us_filter(data: List[Any]) -> List[Any]:
    """美国"""
    return regex_filter(data, r"美国|United\s*States|USA?(?![a-zA-Z])")


# ============== 工厂函数（返回过滤器）==============


def keyword(kw: str) -> FilterFunc:
    """
    创建关键词过滤器

    用法: keyword("IPLC")(data) 或 intersect(F.hk, keyword("IPLC"))(data)
    """

    def _filter(data: List[Any]) -> List[Any]:
        return regex_filter(data, kw)

    return _filter


def regex(pattern: str) -> FilterFunc:
    r"""
    创建正则过滤器

    用法: regex(r"node-\d+")(data)
    """

    def _filter(data: List[Any]) -> List[Any]:
        return regex_filter(data, pattern)

    return _filter


def excluding(pattern: str) -> FilterFunc:
    """
    创建排除过滤器

    用法: excluding("剩余流量")(data)
    """

    def _filter(data: List[Any]) -> List[Any]:
        return exclude(data, pattern)

    return _filter


# ============== 组合器 ==============


def union(*filters: FilterFunc) -> FilterFunc:
    """
    并集（OR）- 合并多个过滤器的结果

    用法: union(F.hk, F.jp, F.us)(data)
    """

    def _filter(data: List[Any]) -> List[Any]:
        if not filters:
            return data
        result = set()
        for f in filters:
            result |= set(f(data))
        return list(result)

    return _filter


def intersect(*filters: FilterFunc) -> FilterFunc:
    """
    交集（AND）- 取多个过滤器结果的交集

    用法: intersect(F.hk, keyword("IPLC"))(data)
    """

    def _filter(data: List[Any]) -> List[Any]:
        if not filters:
            return data
        result = set(filters[0](data))
        for f in filters[1:]:
            result &= set(f(data))
        return list(result)

    return _filter


def chain(*filters: FilterFunc) -> FilterFunc:
    """
    链式过滤 - 依次应用过滤器（前一个的输出是后一个的输入）

    用法: chain(F.hk, excluding("普通"))(data)
    等价于: excluding("普通")(hk_filter(data))
    """

    def _filter(data: List[Any]) -> List[Any]:
        result = data
        for f in filters:
            result = f(result)
        return result

    return _filter


# ============== 过滤器集合（用于模板）==============


class F:
    """
    过滤器快捷访问

    用法:
        F.hk(data)                           # 直接过滤
        union(F.hk, F.jp)(data)              # 香港 OR 日本
        intersect(F.hk, keyword("IPLC"))(data)  # 香港 AND IPLC
        chain(F.hk, excluding("普通"))(data)    # 香港节点中排除"普通"
    """

    hk = staticmethod(hk_filter)
    tw = staticmethod(tw_filter)
    sg = staticmethod(sg_filter)
    jp = staticmethod(jp_filter)
    kr = staticmethod(kr_filter)
    us = staticmethod(us_filter)


# ============== 兼容旧 API ==============


def keyWord_filter(data: List[Any], keyWord: str) -> List[Any]:
    """[兼容] 关键词过滤"""
    return regex_filter(data, keyWord)


def combine(
    data: List[Any],
    left_func,
    right_func,
    left_args=None,
    right_args=None,
    relation=False,
) -> List[Any]:
    """[兼容] 组合过滤器"""

    def call_func(func, args):
        if args is not None:
            return func(data, args)
        return func(data)

    left_result = call_func(left_func, left_args)
    right_result = call_func(right_func, right_args)

    s_left = set(left_result)
    s_right = set(right_result)

    if relation:
        return list(s_left & s_right)
    else:
        return list(s_left | s_right)


class FilterCollection:
    """[兼容] 过滤器集合"""

    def __init__(self):
        self.hk_filter = hk_filter
        self.tw_filter = tw_filter
        self.sg_filter = sg_filter
        self.jp_filter = jp_filter
        self.kr_filter = kr_filter
        self.us_filter = us_filter
        self.keyWord_filter = keyWord_filter
        self.regex_filter = regex_filter
        self.exclude = exclude
        self.combine = combine
        # 新 API
        self.keyword = keyword
        self.regex = regex
        self.excluding = excluding
        self.union = union
        self.intersect = intersect
        self.chain = chain


all_filters = FilterCollection()
