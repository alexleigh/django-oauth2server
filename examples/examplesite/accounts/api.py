from django.contrib.auth.models import User

import oauth2
from oauth2.exceptions import OAuth2Exception, InsufficientScope

def email(request, user_id):
    try:
        user, scopes = oauth2.authenticate(request)
    except OAuth2Exception as e:
        return oauth2.json_error_response(e)
    if oauth2.has_scope_name('user_info', scopes):
        if user_id == user.id:
            return authenticator.response({"email":authenticator.user.email})
        else:
            return Unauthorized()
    else:
        return oauth2.json_error_response(InsufficientScope('user_info'))
        
def date_joined(request):
    scope = AccessRange.objects.get(key="date_joined")
    authenticator = JSONAuthenticator(scope=scope)
    try:
        authenticator.validate(request)
    except AuthenticationException:
        return authenticator.error_response()
    return authenticator.response({
        "date_joined":str(authenticator.user.date_joined)})

def last_login(request):
    scope = AccessRange.objects.get(key="last_login")
    authenticator = JSONAuthenticator(scope=scope)
    try:
        authenticator.validate(request)
    except AuthenticationException:
        return authenticator.error_response()
    data = {"date_joined":str(request.user.date_joined)}
    return authenticator.response({
        "last_login":str(authenticator.user.last_login)})
