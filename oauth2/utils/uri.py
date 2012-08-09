# -*- coding: utf-8 -*-

import re
import unicodedata
import urlparse
from urllib import quote, unquote, urlencode

"""
URI Normalization function:
 * Take care of IDN domains.
 * Always provide the URI scheme in lowercase characters.
 * Always provide the host, if any, in lowercase characters.
 * Only perform percent-encoding where it is essential.
 * Always use uppercase A-through-F characters when percent-encoding.
 * Prevent dot-segments appearing in non-relative URI paths.
 * For schemes that define a default authority, use an empty authority if the
   default is desired.
 * For schemes that define an empty path to be equivalent to a path of "/",
   use "/".
 * For schemes that define a port, use an empty port if the default is desired
 * All portions of the URI must be utf-8 encoded NFC from Unicode strings

Inspired by Sam Ruby's urlnorm.py: http://intertwingly.net/blog/2004/08/04/Urlnorm
This fork author: Nikolay Panov (<pythoneer@niksite.ru>)

History:
 * 10 Feb 2010: support for shebang (#!) urls
 * 28 Feb 2010: using 'http' schema by default when appropriate
 * 28 Feb 2010: added handling of IDN domains
 * 28 Feb 2010: code pep8-zation
 * 27 Feb 2010: forked from Sam Ruby's urlnorm.py
"""

__license__ = "Python"
__version__ = 1.1

def add_parameters(url, parameters):
    """Parses URL and appends parameters. 

    **Args:**

    * *url:* URL string.
    * *parameters:* Dict of parameters

    *Returns str*"""
    parts = list(urlparse.urlparse(url))
    parts[4] = urlencode(urlparse.parse_qsl(parts[4]) + parameters.items())
    return urlparse.urlunparse(parts)

def add_fragments(url, fragments):
    """Parses URL and appends fragments. 

    **Args:**

    * *url:* URL string.
    * *fragments:* Dict of fragments

    *Returns str*"""
    parts = list(urlparse.urlparse(url))
    parts[5] = urlencode(urlparse.parse_qsl(parts[5]) + fragments.items())
    return urlparse.urlunparse(parts)

def normalize(url, charset='utf-8'):
    """Sometimes you get an URL by a user that just isn't a real
    URL because it contains unsafe characters like ' ' and so on.  This
    function can fix some of the problems in a similar way browsers
    handle data entered by the user:

    >>> url_fix(u'http://de.wikipedia.org/wiki/Elf (Begriffsklärung)')
    'http://de.wikipedia.org/wiki/Elf%20%28Begriffskl%C3%A4rung%29'

    :param charset: The target charset for the URL if the url was
                    given as unicode string.
    """

    def _clean(string):
        string = unicode(unquote(string), 'utf-8', 'replace')
        return unicodedata.normalize('NFC', string).encode('utf-8')

    default_port = {
        'ftp': 21,
        'telnet': 23,
        'http': 80,
        'gopher': 70,
        'news': 119,
        'nntp': 119,
        'prospero': 191,
        'https': 443,
        'snews': 563,
        'snntp': 563,
    }
    if isinstance(url, unicode):
        url = url.encode(charset, 'ignore')

    # if there is no scheme use http as default scheme
    if url[0] not in ['/', '-'] and ':' not in url[:7]:
        url = 'http://' + url

    # shebang urls support
    url = url.replace('#!', '?_escaped_fragment_=')

    # splitting url to useful parts
    scheme, auth, path, query, fragment = urlparse.urlsplit(url.strip())
    (userinfo, host, port) = re.search('([^@]*@)?([^:]*):?(.*)', auth).groups()

    # Always provide the URI scheme in lowercase characters.
    scheme = scheme.lower()

    # Always provide the host, if any, in lowercase characters.
    host = host.lower()
    if host and host[-1] == '.':
        host = host[:-1]
    # take care about IDN domains
    host = host.decode(charset).encode('idna')  # IDN -> ACE

    # Only perform percent-encoding where it is essential.
    # Always use uppercase A-through-F characters when percent-encoding.
    # All portions of the URI must be utf-8 encoded NFC from Unicode strings
    path = quote(_clean(path), "~:/?#[]@!$&'()*+,;=")
    fragment = quote(_clean(fragment), "~")

    # note care must be taken to only encode & and = characters as values
    query = "&".join(["=".join([quote(_clean(t), "~:/?#[]@!$'()*+,;=") for t in q.split("=", 1)]) for q in query.split("&")])

    # Prevent dot-segments appearing in non-relative URI paths.
    if scheme in ["", "http", "https", "ftp", "file"]:
        output = []
        for part in path.split('/'):
            if part == "":
                if not output:
                    output.append(part)
            elif part == ".":
                pass
            elif part == "..":
                if len(output) > 1:
                    output.pop()
            else:
                output.append(part)
        if part in ["", ".", ".."]:
            output.append("")
        path = '/'.join(output)

    # For schemes that define a default authority, use an empty authority if
    # the default is desired.
    if userinfo in ["@", ":@"]:
        userinfo = ""

    # For schemes that define an empty path to be equivalent to a path of "/",
    # use "/".
    if path == "" and scheme in ["http", "https", "ftp", "file"]:
        path = "/"

    # For schemes that define a port, use an empty port if the default is
    # desired
    if port and scheme in default_port.keys():
        if port.isdigit():
            port = str(int(port))
            if int(port) == default_port[scheme]:
                port = ''

    # Put it all back together again
    auth = (userinfo or "") + host
    if port:
        auth += ":" + port
    if url.endswith("#") and query == "" and fragment == "":
        path += "#"
    return urlparse.urlunsplit((scheme, auth, path, query, fragment))
