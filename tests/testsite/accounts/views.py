from django.http import HttpResponseRedirect, HttpResponse
from django.contrib.auth.decorators import login_required

from oauth2.views import ClientAuthorizationView
from oauth2.exceptions import UnvalidatedRequest, UnauthenticatedUser, AuthorizationException, MissingRedirectURI
from oauth2.models import Scope
from oauth2.constants import MAC, CODE, TOKEN, CODE_AND_TOKEN


@login_required
def missing_redirect_uri(request):
    return HttpResponse("Missing Redirect URI")


@login_required
def authorize_not_refreshable(request):
    authorizer = Authorizer(refreshable=False)
    try:
        return authorizer(request)
    except MissingRedirectURI, e:
        return HttpResponseRedirect("/oauth2/missing_redirect_uri")

@login_required
def authorize_mac(request):
    authorizer = Authorizer(authentication_method=MAC)
    try:
        return authorizer(request)
    except MissingRedirectURI, e:
        return HttpResponseRedirect("/oauth2/missing_redirect_uri")


@login_required
def authorize_first_name(request):
    scope = Scope.objects.get(key="first_name")
    authorizer = Authorizer(scope=scope)
    try:
        return authorizer(request)
    except MissingRedirectURI, e:
        return HttpResponseRedirect("/oauth2/missing_redirect_uri")


@login_required
def authorize_first_and_last_name(request):
    scope = Scope.objects.filter(key__in=["first_name", "last_name"])
    authorizer = Authorizer(scope=scope)
    try:
        return authorizer(request)
    except MissingRedirectURI, e:
        return HttpResponseRedirect("/oauth2/missing_redirect_uri")


@login_required
def authorize_last_name(request):
    scope = Scope.objects.get(key="last_name")
    authorizer = Authorizer(scope=scope)
    try:
        return authorizer(request)
    except MissingRedirectURI, e:
        return HttpResponseRedirect("/oauth2/missing_redirect_uri")


@login_required
def authorize_no_scope(request):
    authorizer = Authorizer()
    try:
        return authorizer(request)
    except MissingRedirectURI, e:
        return HttpResponseRedirect("/oauth2/missing_redirect_uri")


@login_required
def authorize_code(request):
    authorizer = Authorizer(response_type=CODE)
    try:
        return authorizer(request)
    except MissingRedirectURI, e:
        return HttpResponseRedirect("/oauth2/missing_redirect_uri")

@login_required
def authorize_token_mac(request):
    authorizer = Authorizer(response_type=TOKEN, authentication_method=MAC)
    try:
        return authorizer(request)
    except MissingRedirectURI, e:
        return HttpResponseRedirect("/oauth2/missing_redirect_uri")

@login_required
def authorize_token(request):
    authorizer = Authorizer(response_type=TOKEN)
    try:
        return authorizer(request)
    except MissingRedirectURI, e:
        return HttpResponseRedirect("/oauth2/missing_redirect_uri")

@login_required
def authorize_code_and_token(request):
    authorizer = Authorizer(response_type=CODE_AND_TOKEN)
    try:
        return authorizer(request)
    except MissingRedirectURI, e:
        return HttpResponseRedirect("/oauth2/missing_redirect_uri")
