import logging
from urllib import urlencode
from base64 import b64decode

from django.http import HttpResponse, HttpResponseRedirect, absolute_http_url_re
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from django.utils.decorators import method_decorator
from django.utils import simplejson

from . import constants, settings
from .models import Client, Scope, Code, Token
from .forms import AuthorizationForm
from .utils import KeyGenerator, TimestampGenerator
from .utils.uri import add_parameters, add_fragments, normalize
from .exceptions import *

log = logging.getLogger(__name__)

class ClientAuthorizationView(View):
    '''
    Client authorization endpoint. Validates client access requests and
    generates a response with an authorization code passed as a parameter to
    the redirect URI, an access token passed as a URI fragment to the redirect
    URI, or both.

    **Kwargs:**
    * *authentication_method:* Type of token to generate. Possible values are
      oauth2.constants.BEARER and oauth2.constants.MAC.
    * *refreshable:* Whether issued tokens are refreshable.
    * *allowed_response_type:* Type of response the authorizer can generate.
      Possible values are oauth2.constants.CODE, oauth2.constants.TOKEN,
      and oauth2.constants.CODE_AND_TOKEN.
    * *allowed_scopes:* An iterable of oauth2.models.Scope objects representing
      the scopes the authorizer can grant. None means no limit, an empty list
      means the authorizer can only grant requests with no scopes.
      *Default None*
    '''

    RESPONSE_TYPES = {
        'code': constants.CODE,
        'token': constants.TOKEN
    }
    authentication_method = settings.AUTHENTICATION_METHOD
    refreshable = settings.REFRESHABLE
    allowed_response_type = settings.ALLOWED_RESPONSE_TYPE
    allowed_scopes = None
    
    def __init__(self, **kwargs):
        for key, value in kwargs.iteritems():
            setattr(self, key, value)

        if self.authentication_method not in [constants.BEARER, constants.MAC]:
            raise OAuth2Exception(
                'Possible values for authentication_method are '
                'oauth2.constants.BEARER and oauth2.constants.MAC.'
            )
        
        if self.allowed_response_type not in [
            constants.CODE,
            constants.TOKEN,
            constants.CODE_AND_TOKEN
        ]:
            raise OAuth2Exception(
                'Possible values for allowed_response_type are '
                'oauth2.constants.CODE, oauth2.constants.TOKEN, '
                'and oauth2.constants.CODE_AND_TOKEN.'
            )

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(ClientAuthorizationView, self).dispatch(*args, **kwargs)
    
    def validate(self, request):
        client_id = request.GET.get('client_id')
        redirect_uri = request.GET.get('redirect_uri')
        response_type = request.GET.get('response_type')
        scope = request.GET.get('scope')
            
        # check client_id
        client = None
        if client_id is None:
            raise InvalidClientId('Missing required parameter: client_id')
        try:
            client = Client.objects.get(client_id=client_id)
        except Client.DoesNotExist:
            raise InvalidClient('client_id %s doesn\'t exist' % client_id)
        
        # check redirect URI
        if redirect_uri is None:
            raise InvalidRedirectURI('Missing required parameter: redirect_uri')
        if client.redirect_uri is not None:
            if normalize(redirect_uri) != normalize(client.redirect_uri):
                raise RedirectURIMismatch('Registered redirect_uri doesn\'t match provided redirect_uri.')
        if not absolute_http_url_re.match(redirect_uri):
            raise InvalidRedirectURI('Absolute URI required for redirect_uri')
        
        # check response type
        if response_type is None:
            raise InvalidResponseType('Missing required parameter: response_type')
        if response_type not in ['code', 'token']:
            raise InvalidResponseType('No such response type %s' % response_type)
        if self.allowed_response_type & self.RESPONSE_TYPES[response_type] == 0:
            raise InvalidResponseType('Response type %s not allowed.' % response_type)
        
        # check scope
        scopes = []
        if scope is not None:
            scope_names = set(scope.split())
            invalid_scope_names = []
            for scope_name in scope_names:
                try:
                    scope = Scope.objects.get(name=scope_name)
                    scopes.append(scope)
                except Scope.DoesNotExist:
                    invalid_scope_names.append(scope_name)
            if len(invalid_scope_names) > 0:
                raise InvalidScope('The following scopes do not exist: %s' % ', '.join(invalid_scope_names))
            if self.allowed_scopes is not None:
                allowed_scope_names = set(self.allowed_scopes.values_list('name', flat=True))
                disallowed_scope_names = scope_names - allowed_scope_names
                if len(disallowed_scope_names) > 0:
                    raise InvalidScope('The following scopes cannot be requested: %s' % ','.join(disallowed_scope_names))

        return (client, redirect_uri, response_type, scopes)
    
    def error_response(self, exception):
        context = {
            'error': exception.error,
            'error_description': u'%s' % exception.message
        }
        
        response = render_to_response('oauth2/error.html', context, RequestContext(self.request))
        if isinstance(exception, InvalidClient):
            response.status_code = 401
        else:
            response.status_code = 400
        return response
    
    def error_redirect(self, exception, redirect_uri, state=None):
        parameters = {
            'error': exception.error,
            'error_description': u'%s' % exception.message
        }
    
        if state is not None:
            parameters['state'] = state
    
        if self.allowed_response_type & constants.CODE != 0:
            redirect_uri = add_parameters(redirect_uri, parameters)
    
        if self.allowed_response_type & constants.TOKEN != 0:
            redirect_uri = add_fragments(redirect_uri, parameters)
    
        return HttpResponseRedirect(redirect_uri)
    
    def get(self, request):
        # optional state parameter
        state = request.GET.get('state')
        
        try:
            client, redirect_uri, response_type, scopes = self.validate(request)
        
        # do not redirect to requesting client for these errors
        except (OAuth2ClientException, OAuth2RedirectURIException) as e:
            return self.error_response(e)
        
        # redirect to requesting client for other kinds of oauth2 errors
        except OAuth2Exception as e:
            return self.error_redirect(e, state)
        
        query = {
            'client_id': client.client_id,
            'response_type': response_type,
            'redirect_uri': redirect_uri
        }
        if state is not None:
            query['state'] = state
        if len(scopes) > 0:
            query['scope'] = ' '.join([ scope.name for scope in scopes ])
        form_action = '%sauthorize/?%s' % (settings.URL, urlencode(query))
        
        context = {
            'client': client, 
            'scopes': scopes,
            'form': AuthorizationForm(),
            'form_action': form_action
        }
        return render_to_response('oauth2/authorize.html', context, RequestContext(request))

    def post(self, request):
        # optional state parameter
        state = request.GET.get('state')
        
        try:
            client, redirect_uri, response_type, scopes = self.validate(request)
            
        # do not redirect to requesting client for these errors
        except (OAuth2ClientException, OAuth2RedirectURIException) as e:
            return self.error_response(e)
        
        # redirect to requesting client for other kinds of oauth2 errors
        except OAuth2Exception as e:
            return self.error_redirect(e, redirect_uri, state)
        
        form = AuthorizationForm(request.POST)
        
        if form.is_valid():
            if request.POST.get('authorize') == 'Allow access':
                parameters = {}
                fragments = {}
                
                if self.RESPONSE_TYPES[response_type] & constants.CODE != 0:
                    code = Code.objects.create(
                        user=request.user,
                        client=client,
                        redirect_uri=redirect_uri
                    )
                    code.scopes.add(*scopes)
                    code.save()
                    parameters['code'] = code.code
                
                if self.RESPONSE_TYPES[response_type] & constants.TOKEN != 0:
                    token = Token.objects.create(
                        user=request.user,
                        client=client,
                        refreshable=self.REFRESHABLE
                    )
                    token.scopes.add(*scopes)
                    
                    fragments['access_token'] = token.access_token
                    if token.refreshable:
                        fragments['refresh_token'] = token.refresh_token
                    fragments['expires_in'] = settings.ACCESS_TOKEN_EXPIRATION
                    
                    if len(scopes) > 0:
                        fragments['scope'] = ' '.join([ scope.name for scope in scopes ])
                    
                    if self.authentication_method == constants.MAC:
                        token.mac_key = KeyGenerator(settings.MAC_KEY_LENGTH)()
                        fragments['mac_key'] = token.mac_key
                        fragments['mac_algorithm'] = 'hmac-sha-256'
                        fragments['token_type'] = 'mac'
                    
                    elif self.authentication_method == constants.BEARER:
                        fragments['token_type'] = 'bearer'
                    
                    token.save()
                
                if state is not None:
                    parameters['state'] = state
                
                redirect_uri = add_parameters(redirect_uri, parameters)
                redirect_uri = add_fragments(redirect_uri, fragments)
                return HttpResponseRedirect(redirect_uri)
            
            else:
                return self.error_redirect(AccessDenied('Access denied'), redirect_uri, state)
        
        return self.error_response(OAuth2Exception('Unknown error'))
    
class TokenView(View):
    '''
    Token endpoint. Validates authorization codes, refresh tokens,
    username/password pairs, or client credentials, and generates a JSON
    formatted response.

    **Kwargs:**
    * *authentication_method:* Type of token to generate. Possible values are
      oauth2.constants.BEARER and oauth2.constants.MAC.
    * *refreshable:* Whether issued tokens are refreshable.
    * *requires_client_authentication:* Whether client authentication is
      required before issuing tokens.
    * *allowed_scopes:* An iterable of oauth2.models.Scope objects representing
      the scopes the token generator can grant. None means no limit, an empty
      list means the generator can only grant requests with no scopes.
      *Default None*
    '''
    
    authentication_method = settings.AUTHENTICATION_METHOD
    refreshable = settings.REFRESHABLE
    requires_client_authentication = settings.REQUIRES_CLIENT_AUTHENTICATION
    allowed_scopes=None
    
    def __init__(self, **kwargs):
        for key, value in kwargs.iteritems():
            setattr(self, key, value)

        if self.authentication_method not in [constants.BEARER, constants.MAC]:
            raise OAuth2Exception(
                'Possible values for authentication_method are '
                'oauth2.constants.BEARER and oauth2.constants.MAC.'
            )

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(TokenView, self).dispatch(*args, **kwargs)
    
    def authenticate_client(self, request):
        client_id = request.POST.get('client_id')
        client_secret = request.POST.get('client_secret')
        
        if 'HTTP_AUTHORIZATION' in request.META:
            auth_type, auth_value = request.META['HTTP_AUTHORIZATION'].split()[0:2]
            if auth_type.lower() == 'basic':
                credentials = b64decode(auth_value)
                client_id, client_secret = credentials.split(':')[0:2]
        
        if client_id is not None:
            try:
                client = Client.objects.get(client_id=client_id)
                if client_secret is not None:
                    if client_secret == client.client_secret:
                        return client
            except Client.DoesNotExist:
                pass
        
        return None
    
    def validate_authorization_code(self, request):
        # authenticate client
        client = self.authenticate_client(request)
        
        if client is None:
            if self.requires_client_authentication:
                raise InvalidClient('Client authentication failed')
            
            # if the client is not authenticating, the client_id is required, per 4.1.3.
            client_id = request.POST.get('client_id')
            if client_id is None:
                raise InvalidClientId('Missing required parameter: client_id')
            try:
                client = Client.objects.get(client_id=client_id)
            except Client.DoesNotExist:
                raise InvalidClient('client_id %s doesn\'t exist' % client_id)
        
        # check authorization code
        authorization_code = request.POST.get('code')
        if authorization_code is None:
            raise InvalidGrant('Missing required parameter: authorization_code')
        try:
            code = Code.objects.get(code=authorization_code)
        except Code.DoesNotExist:
            raise InvalidGrant('No such authorization code: %s' % authorization_code)
        now = TimestampGenerator()()
        if code.expire < now:
            raise InvalidGrant('Provided authorization code is expired')
        
        # check redirect uri
        redirect_uri = request.POST.get('redirect_uri')
        if redirect_uri is None:
            raise InvalidRedirectURI('Missing required parameter: redirect_uri')
        if normalize(redirect_uri) != normalize(code.redirect_uri):
            raise RedirectURIMismatch('Authorized redirect_uri doesn\'t match provided redirect_uri')
        
        return code
        
    def validate_refresh_token(self, request):
        # authenticate client
        client = self.authenticate_client(request)
        
        if client is None:
            if self.requires_client_authentication:
                raise InvalidClient('Client authentication failed')
            
        # check refresh token
        refresh_token = request.POST.get('refresh_token')
        if refresh_token is None:
            raise InvalidGrant('Missing required parameter: refresh_token')
        try:
            token = Token.objects.get(refresh_token=refresh_token)
        except Token.DoesNotExist:
            raise InvalidGrant('No such refresh token: %s' % refresh_token)
        if not token.refreshable:
            raise InvalidGrant('Access token is not refreshable.')
        
        # check scope
        scope = request.POST.get('scope')
        if scope is None:
            scopes = token.scopes.all()
        else:
            scopes = []
            scope_names = set(scope.split())
            invalid_scope_names = []
            for scope_name in scope_names:
                try:
                    scope = Scope.objects.get(name=scope_name)
                    scopes.append(scope)
                except Scope.DoesNotExist:
                    invalid_scope_names.append(scope_name)
            if len(invalid_scope_names) > 0:
                raise InvalidScope('The following scopes do not exist: %s' % ', '.join(invalid_scope_names))
            allowed_scope_names = set(token.scopes.all().values_list('name', flat=True))
            disallowed_scope_names = scope_names - allowed_scope_names
            if len(disallowed_scope_names) > 0:
                raise InvalidScope('Refresh request requested scopes beyond initial grant: %s' % disallowed_scope_names)
        
        return (token, scopes)

    def validate_password(self, request):
        # authenticate client
        client = self.authenticate_client(request)
        
        if client is None:
            if self.requires_client_authentication:
                raise InvalidClient('Client authentication failed')
        
        # check username and password
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username is None:
            raise AuthenticationFailed('Missing required parameter: username')
        if password is None:
            raise AuthenticationFailed('Missing required parameter: password')
        user = auth.authenticate(username=username, password=password)
        if user is not None:
            if not user.is_active:
                raise AuthenticationFailed('Inactive user.')
        else:
            raise AuthenticationFailed('User authentication failed.')
        
        # check scope
        scope = request.POST.get('scope')
        scopes = []
        if scope is not None:
            scope_names = set(scope.split())
            invalid_scope_names = []
            for scope_name in scope_names:
                try:
                    scope = Scope.objects.get(name=scope_name)
                    scopes.append(scope)
                except Scope.DoesNotExist:
                    invalid_scope_names.append(scope_name)
            if len(invalid_scope_names) > 0:
                raise InvalidScope('The following scopes do not exist: %s' % ', '.join(invalid_scope_names))
            if self.allowed_scopes is not None:
                allowed_scope_names = set(self.allowed_scopes.values_list('name', flat=True))
                disallowed_scope_names = scope_names - allowed_scope_names
                if len(disallowed_scope_names) > 0:
                    raise InvalidScope('The following scopes cannot be requested: %s' % ','.join(disallowed_scope_names))
        
        return (user, client, scopes)

    def validate_client_credentials(self, request):
        # authenticate client
        client = self.authenticate_client(request)
        
        if client is None:
            raise InvalidClient('Client authentication failed')
        
        # check scope
        scope = request.POST.get('scope')
        scopes = []
        if scope is not None:
            scope_names = set(scope.split())
            invalid_scope_names = []
            for scope_name in scope_names:
                try:
                    scope = Scope.objects.get(name=scope_name)
                    scopes.append(scope)
                except Scope.DoesNotExist:
                    invalid_scope_names.append(scope_name)
            if len(invalid_scope_names) > 0:
                raise InvalidScope('The following scopes do not exist: %s' % ', '.join(invalid_scope_names))
            if self.allowed_scopes is not None:
                allowed_scope_names = set(self.allowed_scopes.values_list('name', flat=True))
                disallowed_scope_names = scope_names - allowed_scope_names
                if len(disallowed_scope_names) > 0:
                    raise InvalidScope('The following scopes cannot be requested: %s' % ','.join(disallowed_scope_names))
        
        return (client, scopes)
            
    def error_response(self, exception, callback=None):
        context = {
            'error': exception.error,
            'error_description': u'%s' % exception.message
        }
        
        if callback is not None:
            json_context = '%s(%s);' % (callback, simplejson.dumps(context))
            return HttpResponse(json_context, content_type='application/json')
        
        else:
            response = HttpResponse(simplejson.dumps(context), content_type='application/json')
            if isinstance(exception, InvalidClient):
                response.status_code = 401
            else:
                response.status_code = 400
            return response

    def grant_response(self, token, callback=None):
        context = {
            'access_token': token.access_token,
            'expires_in': settings.ACCESS_TOKEN_EXPIRATION
        }
        
        if self.authentication_method == constants.MAC:
            context['token_type'] = 'mac'
            context['mac_key'] = token.mac_key
            context['mac_algorithm'] = 'hmac-sha-256'
        
        elif self.authentication_method == constants.BEARER:
            context['token_type'] = 'bearer'
        
        if token.refreshable:
            context['refresh_token'] = token.refresh_token
        
        if token.scopes is not None:
            context['scope'] = ' '.join(set(token.scopes.values_list('name', flat=True)))
        
        json_context = simplejson.dumps(context)
        if callback is not None:
            json_context = '%s(%s);' % (callback, json_context)
        
        response = HttpResponse(json_context, content_type='application/json')
        response['Cache-Control'] = 'no-store'
        return response

    def post(self, request):
        # optional JSON callback parameter
        callback = request.REQUEST.get('callback')
        
        grant_type = request.POST.get('grant_type')
        
        if grant_type is None:
            raise InvalidGrantType('Missing required parameter: grant_type')
        
        # authorization_code, see 4.1.3. Access Token Request
        if grant_type == 'authorization_code':
            try:
                code = self.validate_authorization_code(request)
            
            except OAuth2Exception as e:
                return self.error_response(e, callback)
            
            token = Token.objects.create(
                user=code.user,
                client=code.client,
                refreshable=self.refreshable
            )
            scopes = code.scopes.all()
            token.scopes.add(*scopes)
            if self.authentication_method == constants.MAC:
                token.mac_key = KeyGenerator(settings.MAC_KEY_LENGTH)()
            token.save()
            
            code.delete()
            
            return self.grant_response(token, callback)
            
        # refresh_token, see 6. Refreshing an Access Token
        elif grant_type == 'refresh_token':
            try:
                token, scopes = self.validate_refresh_token(request)
            
            except OAuth2Exception as e:
                return self.error_response(e, callback)
            
            token.access_token = KeyGenerator(settings.ACCESS_TOKEN_LENGTH)()
            token.refresh_token = KeyGenerator(settings.REFRESH_TOKEN_LENGTH)()
            token.expire = TimestampGenerator(settings.ACCESS_TOKEN_EXPIRATION)()
            token.scopes = [ scope.id for scope in scopes ]
            token.save()
        
            return self.grant_response(token, callback)
            
        # password, see 4.3.2. Access Token Request
        elif grant_type == 'password':
            try:
                user, client, scopes = self.validate_password(request)
                
            except OAuth2Exception as e:
                return self.error_response(e, callback)
            
            token = Token.objects.create(
                user=user,
                client=client,
                refreshable=self.refreshable
            )
            token.scopes.add(*scopes)
            if self.authentication_method == constants.MAC:
                token.mac_key = KeyGenerator(settings.MAC_KEY_LENGTH)()
            token.save()
            
            return self.grant_response(token, callback)
        
        # client_credentials, see 4.4.2. Access Token Request
        elif grant_type == 'client_credentials':
            try:
                client, scopes = self.validate_client_credentials(request)
            except OAuth2Exception as e:
                return self.error_response(e, callback)
            
            token = Token.objects.create(
                # TODO: the user should be a user representing the client, not the client's owner.
                user=client.owner,
                client=client,
                refreshable=self.refreshable
            )
            token.scopes.add(*scopes)
            if self.authentication_method == constants.MAC:
                token.mac_key = KeyGenerator(settings.MAC_KEY_LENGTH)()
            token.save()
        
            return self.grant_response(token, callback)
            
        else:
            raise InvalidGrantType('No such grant type: %s' % grant_type)
        