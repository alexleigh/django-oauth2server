#-*- coding: utf-8 -*-

from django.utils import unittest
from oauth2.exceptions import OAuth2Exception
from oauth2.views import ClientAuthorizationView
from oauth2 import authenticate

class ConfigTestCase(unittest.TestCase):
    
    def test_00_authorize(self):
        self.assertRaises(OAuth2Exception, ClientAuthorizationView, response_type=-1)
        self.assertRaises(OAuth2Exception, ClientAuthorizationView, authentication_method=-1)

    def test_01_authenticate(self):
        self.assertRaises(OAuth2Exception, authenticate, authentication_method=-1)
    