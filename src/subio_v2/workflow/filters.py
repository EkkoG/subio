import re
from typing import List, Any, Union

def _get_name(item: Any) -> str:
    if isinstance(item, str):
        return item
    if hasattr(item, 'name'):
        return item.name
    return str(item)

def regex_filter(data: List[Any], regex: str) -> List[Any]:
    pattern = re.compile(regex, re.IGNORECASE)
    return [item for item in data if pattern.search(_get_name(item))]

def exclude(data: List[Any], regex: str) -> List[Any]:
    pattern = re.compile(regex, re.IGNORECASE)
    return [item for item in data if not pattern.search(_get_name(item))]

def hk_filter(data: List[Any]) -> List[Any]:
    return regex_filter(data, "香港|hk|Hong Kong|Hong-Kong|Hong_Kong|HongKong|HK|HK-|HK_|HK-_|HK_|HK-")

def tw_filter(data: List[Any]) -> List[Any]:
    return regex_filter(data, "台湾|tw|Taiwan||TW|tw|TW-|TW_|TW-_|TW_|TW-")

def sg_filter(data: List[Any]) -> List[Any]:
    return regex_filter(data, "新加坡|sg|Singapore|SG|sg|SG-|SG_|SG-_|SG_|SG-")

def jp_filter(data: List[Any]) -> List[Any]:
    return regex_filter(data, "日本|jp|Japan|JP|jp|JP-|JP_|JP-_|JP_|JP-")

def kr_filter(data: List[Any]) -> List[Any]:
    return regex_filter(data, "韩国|kr|Korea|KR|kr|KR-|KR_|KR-_|KR_|KR-")

def us_filter(data: List[Any]) -> List[Any]:
    return regex_filter(data, "美国|us|America|US|United States|UnitedStates|United-States|United_States|USA")

def keyWord_filter(data: List[Any], keyWord: str) -> List[Any]:
    return regex_filter(data, keyWord)

def combine(data: List[Any], left_func, right_func, left_args=None, right_args=None, relation=False) -> List[Any]:
    # Helper to handle optional args
    def call_func(func, args):
        if args is not None:
            return func(data, args)
        return func(data)

    left_result = call_func(left_func, left_args)
    right_result = call_func(right_func, right_args)

    # Need to preserve objects or strings. 
    # If they are objects, set() might not work if __hash__/sz__eq__ isn't robust.
    # If they are strings, it's fine.
    # Let's assume list of strings (names) or objects with hash.
    
    # Convert to set for operations
    s_left = set(left_result)
    s_right = set(right_result)
    
    if relation:
        # Intersection (AND)
        res = s_left & s_right
    else:
        # Union (OR)
        res = s_left | s_right
        
    return list(res)

class FilterCollection:
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

all_filters = FilterCollection()

