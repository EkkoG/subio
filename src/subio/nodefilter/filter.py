import re


def hk_filter(data):
    r = "香港|hk|Hong Kong|HongKong|Hong-Kong|Hong_Kong|Hong-Kong|Hong_Kong|HongKong|HK|hk|HK-|HK_|HK-_|HK_|HK-"
    return regex_filter(data, r)

def tw_filter(data):
    r = "台湾|tw|Taiwan|Taiwan|Taiwan|Taiwan|Taiwan|Taiwan|Taiwan|TW|tw|TW-|TW_|TW-_|TW_|TW-"
    return regex_filter(data, r)

def sg_filter(data):
    r = "新加坡|sg|Singapore|Singapore|Singapore|Singapore|Singapore|Singapore|Singapore|SG|sg|SG-|SG_|SG-_|SG_|SG-"
    return regex_filter(data, r)

def jp_filter(data):
    r = "日本|jp|Japan|Japan|Japan|Japan|Japan|Japan|Japan|JP|jp|JP-|JP_|JP-_|JP_|JP-"
    return regex_filter(data, r)


def kr_filter(data):
    r = "韩国|kr|Korea|Korea|Korea|Korea|Korea|Korea|Korea|KR|kr|KR-|KR_|KR-_|KR_|KR-"
    return regex_filter(data, r)

def us_filter(data):
    r = "美国|us|America|US|United States|UnitedStates|United-States|United_States|USA"
    return regex_filter(data, r)


def keyWord_filter(data, keyWord):
    return regex_filter(data, keyWord)

def regex_filter(data, regex):
    def isRegex(s):
        # if s contains regex, what ever the case, it is regex
        name = s if isinstance(s, str) else s["name"]
        if re.search(regex, name, re.IGNORECASE):
            return True
        return False

    return list(filter(isRegex, data))


def exclude(data, regex):
    def isRegex(s):
        # if s contains regex, what ever the case, it is regex
        name = s if isinstance(s, str) else s["name"]
        if re.search(regex, name, re.IGNORECASE):
            return False
        return True

    return list(filter(isRegex, data))


def combine(data, left, right, left_args=None, right_args=None, relation=False):
    if left_args is not None:
        left_result = left(data, left_args)
    else:
        left_result = left(data)

    if right_args is not None:
        right_result = right(data, right_args)
    else:
        right_result = right(data)
    if relation:
        return list(set(left_result) & set(right_result))
    else:
        return list(set(left_result) | set(right_result))


all_filters = {
    "hk_filter": hk_filter,
    "tw_filter": tw_filter,
    "sg_filter": sg_filter,
    "jp_filter": jp_filter,
    "kr_filter": kr_filter,
    "us_filter": us_filter,
    "keyWord_filter": keyWord_filter,
    "regex_filter": regex_filter,
    "exclude": exclude,
    "combine": combine,
}
