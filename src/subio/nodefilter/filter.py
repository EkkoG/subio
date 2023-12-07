import re


def hk_filter(data):
    def isHK(s):
        # if s contains HK, what ever the case, it is HK
        name = s if isinstance(s, str) else s['name']
        if re.search('hk', name, re.IGNORECASE):
            return True
        if '香港' in s:
            return True
        return False

    return list(filter(isHK, data))


def tw_filter(data):
    def isTW(s):
        # if s contains TW, what ever the case, it is TW
        name = s if isinstance(s, str) else s['name']
        if re.search('tw', name, re.IGNORECASE):
            return True
        if '台湾' in s:
            return True
        return False

    return list(filter(isTW, data))


def sg_filter(data):
    def isSG(s):
        # if s contains SG, what ever the case, it is SG
        name = s if isinstance(s, str) else s['name']
        if re.search('sg', name, re.IGNORECASE):
            return True
        if '新加坡' in s:
            return True
        return False

    return list(filter(isSG, data))


def jp_filter(data):
    def isJP(s):
        # if s contains JP, what ever the case, it is JP
        name = s if isinstance(s, str) else s['name']
        if re.search('jp', name, re.IGNORECASE):
            return True
        if '日本' in s:
            return True
        return False

    return list(filter(isJP, data))


def kr_filter(data):
    def isKR(s):
        # if s contains KR, what ever the case, it is KR
        name = s if isinstance(s, str) else s['name']
        if re.search('kr', name, re.IGNORECASE):
            return True
        if '韩国' in s:
            return True
        return False

    return list(filter(isKR, data))


def us_filter(data):
    def isUS(s):
        # if s contains US, what ever the case, it is US
        name = s if isinstance(s, str) else s['name']
        if re.search('us', name, re.IGNORECASE):
            return True
        if '美国' in s:
            return True
        return False

    return list(filter(isUS, data))


def keyWord_filter(data, keyWord):
    def isKeyWord(s):
        # if s contains keyWord, what ever the case, it is keyWord
        name = s if isinstance(s, str) else s['name']
        if re.search(keyWord, name, re.IGNORECASE):
            return True
        return False

    return list(filter(isKeyWord, data))


def regex_filter(data, regex):
    def isRegex(s):
        # if s contains regex, what ever the case, it is regex
        name = s if isinstance(s, str) else s['name']
        if re.search(regex, name, re.IGNORECASE):
            return True
        return False

    return list(filter(isRegex, data))

def exclude(data, regex):
    def isRegex(s):
        # if s contains regex, what ever the case, it is regex
        name = s if isinstance(s, str) else s['name']
        if re.search(regex, name, re.IGNORECASE):
            return False
        return True

    return list(filter(isRegex, data))


def combine(data, left, right,left_args=None, right_args=None, relation=False):
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
    'hk_filter': hk_filter,
    'tw_filter': tw_filter,
    'sg_filter': sg_filter,
    'jp_filter': jp_filter,
    'kr_filter': kr_filter,
    'us_filter': us_filter,
    'keyWord_filter': keyWord_filter,
    'regex_filter': regex_filter,
    'exclude': exclude,
    'combine': combine
}
