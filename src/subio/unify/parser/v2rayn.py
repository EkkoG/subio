import base64
import urllib

def line_to_proxy(line):
    # parse text as url
    url = urllib.parse.urlparse(line)
    server = url.hostname
    port = url.port
    username = url.username
    password = url.password
    netloc = url.netloc
    str_before_at = netloc.split('@')[0]
    q = urllib.parse.parse_qs(url.query)

    print(url)
    print(server, port, password, str_before_at, q)

    if url.scheme == 'http' or url.scheme == 'https':
        p = {}
        p['type'] = 'http'
        if url.scheme == 'https':
            p['tls'] = True
        p['server'] = server
        p['port'] = port
        p['password'] = password
        p['username'] = username

        return p
    elif url.scheme == 'socks5' or url.scheme == 'socks5-tls':
        p = {}
        p['type'] = 'socks5'
        if url.scheme == 'socks5-tls':
            p['tls'] = True
        p['server'] = server
        p['port'] = port
        p['password'] = password
        p['username'] = username
        return p
    elif url.scheme == 'ss':
        p = {}
        p['type'] = 'ss'
        p['server'] = server
        p['port'] = port
        # ss2022
        if ':' in str_before_at:
            p['cipher'] = username
            p['password'] = password
        else:
            # padding
            str_before_a = str_before_at + '=' * (4 - len(str_before_at) % 4)
            t = base64.b64decode(str_before_a).decode('utf-8')
            method = t.split(':')[0]
            password = t.split(':')[1]
            p['password'] = password
            p['cipher'] = method
        if url.fragment:
            tag = urllib.parse.unquote(url.fragment)
            p['name'] = tag
        return p

    return None