import sys

PY3 = sys.version_info[0] == 3

if PY3:
    string_types = str,
    from urllib.parse import urlencode
    from http import client as http_client
    from http import cookies as http_cookies
else:
    string_types = basestring,
    from urllib import urlencode
    import httplib as http_client
    import Cookie as http_cookies
