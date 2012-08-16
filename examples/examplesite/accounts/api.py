from django.http import HttpResponse
from django.utils import simplejson

import oauth2
from oauth2.exceptions import OAuth2Exception, InsufficientScope

def email(request, user_id):
    try:
        user, scopes = oauth2.authenticate(request)
    except OAuth2Exception as e:
        return oauth2.json_error_response(e)
    if user_id == user.id:
        context = {
            'email': user.email
        }
        return HttpResponse(simplejson.dumps(context), mimetype='application/json')
    else:
        return oauth2.json_error_response(OAuth2Exception)
        
def date_joined(request, user_id):
    try:
        user, scopes = oauth2.authenticate(request)
    except OAuth2Exception as e:
        return oauth2.json_error_response(e)
    if oauth2.has_scope_name('date_joined', scopes):
        if user_id == user.id:
            context = {
                'date_joined': user.date_joined
            }
            return HttpResponse(simplejson.dumps(context), mimetype='application/json')
        else:
            return oauth2.json_error_response(OAuth2Exception)
    else:
        return oauth2.json_error_response(InsufficientScope('date_joined'))

def last_login(request, user_id):
    try:
        user, scopes = oauth2.authenticate(request)
    except OAuth2Exception as e:
        return oauth2.json_error_response(e)
    if oauth2.has_scope_name('last_login', scopes):
        if user_id == user.id:
            context = {
                'last_login': user.last_login
            }
            return HttpResponse(simplejson.dumps(context), mimetype='application/json')
        else:
            return oauth2.json_error_response(OAuth2Exception)
    else:
        return oauth2.json_error_response(InsufficientScope('last_login'))
