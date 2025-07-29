"""Node filter functions compatible with v1."""

import re
from typing import List, Union
from ..models import Node


def hk_filter(data: List[Union[Node, str]]) -> List[Union[Node, str]]:
    """Filter Hong Kong nodes."""
    r = "香港|hk|Hong Kong|Hong-Kong|Hong_Kong|HongKong|HK|HK-|HK_|HK-_|HK_|HK-"
    return regex_filter(data, r)


def tw_filter(data: List[Union[Node, str]]) -> List[Union[Node, str]]:
    """Filter Taiwan nodes."""
    r = "台湾|tw|Taiwan||TW|tw|TW-|TW_|TW-_|TW_|TW-"
    return regex_filter(data, r)


def sg_filter(data: List[Union[Node, str]]) -> List[Union[Node, str]]:
    """Filter Singapore nodes."""
    r = "新加坡|sg|Singapore|SG|sg|SG-|SG_|SG-_|SG_|SG-"
    return regex_filter(data, r)


def jp_filter(data: List[Union[Node, str]]) -> List[Union[Node, str]]:
    """Filter Japan nodes."""
    r = "日本|jp|Japan|JP|jp|JP-|JP_|JP-_|JP_|JP-"
    return regex_filter(data, r)


def kr_filter(data: List[Union[Node, str]]) -> List[Union[Node, str]]:
    """Filter Korea nodes."""
    r = "韩国|kr|Korea|KR|kr|KR-|KR_|KR-_|KR_|KR-"
    return regex_filter(data, r)


def us_filter(data: List[Union[Node, str]]) -> List[Union[Node, str]]:
    """Filter US nodes."""
    r = "美国|us|America|US|United States|UnitedStates|United-States|United_States|USA"
    return regex_filter(data, r)


def keyWord_filter(
    data: List[Union[Node, str]], keyWord: str
) -> List[Union[Node, str]]:
    """Filter nodes by keyword."""
    return regex_filter(data, keyWord)


def regex_filter(data: List[Union[Node, str]], regex: str) -> List[Union[Node, str]]:
    """Filter nodes by regex pattern."""

    def isRegex(s: Union[Node, str]) -> bool:
        # if s contains regex, what ever the case, it is regex
        name = s if isinstance(s, str) else s.name
        if re.search(regex, name, re.IGNORECASE):
            return True
        return False

    return list(filter(isRegex, data))


def exclude(data: List[Union[Node, str]], regex: str) -> List[Union[Node, str]]:
    """Exclude nodes matching regex pattern."""

    def isRegex(s: Union[Node, str]) -> bool:
        # if s contains regex, what ever the case, it is regex
        name = s if isinstance(s, str) else s.name
        if re.search(regex, name, re.IGNORECASE):
            return False
        return True

    return list(filter(isRegex, data))


def combine(data: List[Union[Node, str]], *filters_and_args) -> List[Union[Node, str]]:
    """Combine multiple filter results.

    Usage patterns from v1:
    - combine(proxies_names, filter.hk_filter, filter.keyWord_filter, None, 'us')

    The pattern appears to be: filter1, filter2, ..., None, arg_for_last_filter
    """
    if not filters_and_args:
        return data

    # Find where None appears - it separates filters from args
    filters = []
    args = []
    found_none = False

    for item in filters_and_args:
        if item is None:
            found_none = True
        elif found_none:
            args.append(item)
        elif callable(item):
            filters.append(item)

    # Apply filters
    result = data
    for i, filter_func in enumerate(filters):
        if i == len(filters) - 1 and args:
            # Last filter gets the arguments
            result = filter_func(result, *args)
        else:
            # Other filters get no arguments
            result = filter_func(result)

    return result


# Create a filter object that can be accessed with dot notation
class FilterObject:
    """Filter object for template compatibility."""

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


# Export all filters as dictionary for backward compatibility
all_filters = FilterObject()
