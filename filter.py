import re
def hkFilter(data):
    def isHK(s):
        #if s contains HK, what ever the case, it is HK
        if re.search('hk', s, re.IGNORECASE):
            return True
        if '香港' in s:
            return True
        return False
        

    return list(filter(isHK, data))

def twFilter(data):
    def isTW(s):
        #if s contains TW, what ever the case, it is TW
        if re.search('tw', s, re.IGNORECASE):
            return True
        if '台湾' in s:
            return True
        return False
        

    return list(filter(isTW, data))

def sgFilter(data):
    def isSG(s):
        #if s contains SG, what ever the case, it is SG
        if re.search('sg', s, re.IGNORECASE):
            return True
        if '新加坡' in s:
            return True
        return False
        

    return list(filter(isSG, data))

def jpFilter(data):
    def isJP(s):
        #if s contains JP, what ever the case, it is JP
        if re.search('jp', s, re.IGNORECASE):
            return True
        if '日本' in s:
            return True
        return False
        

    return list(filter(isJP, data))

def krFilter(data):
    def isKR(s):
        #if s contains KR, what ever the case, it is KR
        if re.search('kr', s, re.IGNORECASE):
            return True
        if '韩国' in s:
            return True
        return False
        

    return list(filter(isKR, data))

def usFilter(data):
    def isUS(s):
        #if s contains US, what ever the case, it is US
        if re.search('us', s, re.IGNORECASE):
            return True
        if '美国' in s:
            return True
        return False
        

    return list(filter(isUS, data))

def keyWordFilter(data, keyWord):
    def isKeyWord(s):
        #if s contains keyWord, what ever the case, it is keyWord
        if re.search(keyWord, s, re.IGNORECASE):
            return True
        return False
        

    return list(filter(isKeyWord, data))

def regexFilter(data, regex):
    def isRegex(s):
        #if s contains regex, what ever the case, it is regex
        if re.search(regex, s, re.IGNORECASE):
            return True
        return False
        

    return list(filter(isRegex, data))

def combine(data, left, right, relation = False):
    left_result = left(data)
    right_result = right(data)
    if relation:
        return list(set(left_result) & set(right_result))
    else:
        return list(set(left_result) | set(right_result))



all_filters = {
    'hkFilter': hkFilter,
    'twFilter': twFilter,
    'sgFilter': sgFilter,
    'jpFilter': jpFilter,
    'krFilter': krFilter,
    'usFilter': usFilter,
    'keyWordFilter': keyWordFilter,
    'regexFilter': regexFilter,
    'combine': combine
}