# -*- coding: utf-8 -*-

import unittest
from ..utils.uri import normalize

class Test(unittest.TestCase):
    suite = unittest.TestSuite()

    """ from http://www.intertwingly.net/wiki/pie/PaceCanonicalIds """
    tests1 = [
        (False, "http://:@example.com/"),
        (False, "http://@example.com/"),
        (False, "http://example.com"),
        (False, "HTTP://example.com/"),
        (False, "http://EXAMPLE.COM/"),
        (False, "http://example.com/%7Ejane"),
        (False, "http://example.com/?q=%C7"),
        (False, "http://example.com/?q=%5c"),
        (False, "http://example.com/?q=C%CC%A7"),
        (False, "http://example.com/a/../a/b"),
        (False, "http://example.com/a/./b"),
        (False, "http://example.com:80/"),
        (True, "http://example.com/"),
        (True, "http://example.com/?q=%C3%87"),
        (True, "http://example.com/?q=%E2%85%A0"),
        (True, "http://example.com/?q=%5C"),
        (True, "http://example.com/~jane"),
        (True, "http://example.com/a/b"),
        (True, "http://example.com:8080/"),
        (True, "http://user:password@example.com/"),

        # from rfc2396bis
        (True, "ftp://ftp.is.co.za/rfc/rfc1808.txt"),
        (True, "http://www.ietf.org/rfc/rfc2396.txt"),
        (True, "ldap://[2001:db8::7]/c=GB?objectClass?one"),
        (True, "mailto:John.Doe@example.com"),
        (True, "news:comp.infosystems.www.servers.unix"),
        (True, "tel:+1-816-555-1212"),
        (True, "telnet://192.0.2.16:80/"),
        (True, "urn:oasis:names:specification:docbook:dtd:xml:4.1.2"),

        # other
        (True, "http://127.0.0.1/"),
        (False, "http://127.0.0.1:80/"),
        (True, "http://www.w3.org/2000/01/rdf-schema#"),
        (False, "http://example.com:081/"),
    ]

    def testcase1(self, expected, value):

        class test(unittest.TestCase):

            def runTest(self):
                assert (normalize(value) == value) == expected, (expected, value, normalize(value))
        return test()

    for (expected, value) in tests1:
        suite.addTest(testcase1(expected, value))

    """ mnot test suite; three tests updated for rfc2396bis. """
    tests2 = {
        '/foo/bar/.':
            '/foo/bar/',
        '/foo/bar/./':
            '/foo/bar/',
        '/foo/bar/..':
            '/foo/',
        '/foo/bar/../':
            '/foo/',
        '/foo/bar/../baz':
            '/foo/baz',
        '/foo/bar/../..':
            '/',
        '/foo/bar/../../':
            '/',
        '/foo/bar/../../baz':
            '/baz',
        '/foo/bar/../../../baz':
            '/baz', #was: '/../baz',
        '/foo/bar/../../../../baz':
            '/baz',
        '/./foo':
            '/foo',
        '/../foo':
            '/foo', #was: '/../foo',
        '/foo.':
            '/foo.',
        '/.foo':
            '/.foo',
        '/foo..':
            '/foo..',
        '/..foo':
            '/..foo',
        '/./../foo':
            '/foo', #was: '/../foo',
        '/./foo/.':
            '/foo/',
        '/foo/./bar':
            '/foo/bar',
        '/foo/../bar':
            '/bar',
        '/foo//':
            '/foo/',
        '/foo///bar//':
            '/foo/bar/',
        'http://www.foo.com:80/foo':
            'http://www.foo.com/foo',
        'http://www.foo.com:8000/foo':
            'http://www.foo.com:8000/foo',
        'http://www.foo.com./foo/bar.html':
            'http://www.foo.com/foo/bar.html',
        'http://www.foo.com.:81/foo':
            'http://www.foo.com:81/foo',
        'http://www.foo.com/%7ebar':
            'http://www.foo.com/~bar',
        'http://www.foo.com/%7Ebar':
            'http://www.foo.com/~bar',
        'ftp://user:pass@ftp.foo.net/foo/bar':
             'ftp://user:pass@ftp.foo.net/foo/bar',
        'http://USER:pass@www.Example.COM/foo/bar':
             'http://USER:pass@www.example.com/foo/bar',
        'http://www.example.com./':
            'http://www.example.com/',
        '-':
            '-',
        'пример.испытание/Служебная:Search/Test':
            'http://xn--e1afmkfd.xn--80akhbyknj4f/%D0%A1%D0%BB%D1%83%D0%B6%D0%B5%D0%B1%D0%BD%D0%B0%D1%8F:Search/Test',
        'http://lifehacker.com/#!5753509/hello-world-this-is-the-new-lifehacker':
            'http://lifehacker.com/?_escaped_fragment_=5753509/hello-world-this-is-the-new-lifehacker',
    }

    def testcase2(self, original, normalized):

        class test(unittest.TestCase):

            def runTest(self):
                assert normalize(original) == normalized, (original, normalized, normalize(original))
        return test()

    for (original, normalized) in tests2.items():
        suite.addTest(testcase2(original, normalized))

    """ execute tests """
    unittest.TextTestRunner().run(suite)

    def testName(self):
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()