from django.http import HttpResponse

import oauth2
from oauth2.exceptions import OAuth2Exception
from oauth2.models import Scope

def automatic_error_str(request):
    return oauth2.error_response()

def automatic_error_json(request):
    return oauth2.json_error_response()

def first_name_str(request):
    scope = Scope.objects.get(key="first_name")
    authenticator = Authenticator(scope=scope)
    try:
        authenticator.validate(request)
    except OAuth2Exception:
        return authenticator.error_response()
    return HttpResponse(authenticator.user.first_name)


def last_name_str(request):
    scope = Scope.objects.get(key="last_name")
    authenticator = Authenticator(scope=scope)
    try:
        authenticator.validate(request)
    except OAuth2Exception:
        return authenticator.error_response()
    return HttpResponse(authenticator.user.last_name)

def first_and_last_name_str(request):
    scope = Scope.objects.filter(key__in=["first_name", "last_name"])
    authenticator = Authenticator(scope=scope)
    try:
        authenticator.validate(request)
    except OAuth2Exception:
        return authenticator.error_response()
    return HttpResponse(authenticator.user.first_name +  " " + authenticator.user.last_name)

def email_str(request):
    authenticator = Authenticator()
    try:
        authenticator.validate(request)
    except OAuth2Exception:
        return authenticator.error_response()
    return HttpResponse(authenticator.user.email)


def email_json(request):
    authenticator = JSONAuthenticator()
    try:
        authenticator.validate(request)
    except OAuth2Exception:
        return authenticator.error_response()
    return authenticator.response({"email":authenticator.user.email})


