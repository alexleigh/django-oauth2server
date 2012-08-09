import logging
from urllib import urlencode
from base64 import b64encode
from json import dumps

from django.http import HttpResponse, HttpResponseRedirect, absolute_http_url_re
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from django.utils.decorators import method_decorator

from . import constants
from . import settings
from .models import Client, Scope, Code, Token
from .forms import AuthorizationForm
from .utils import KeyGenerator, TimestampGenerator
from .utils.uri import add_parameters, add_fragments, normalize
from .exceptions import OAuth2Exception, InvalidClient, MissingRedirectURI, UnvalidatedRequest, UnauthenticatedUser, InvalidScope, UnauthorizedScope
from .exceptions import InvalidAuthorizationRequest, AccessDenied, UnsupportedResponseType, UnauthorizedResponseType
from .exceptions import InvalidTokenRequest, UnsupportedGrantType, InvalidGrant

log = logging.getLogger(__name__)

RESPONSE_TYPES = {
    'code': constants.CODE,
    'token': constants.TOKEN
}

@login_required
def missing_redirect_uri(request):
    return render_to_response('oauth2/missing_redirect_uri.html', context_instance=RequestContext(request))

class ClientAuthorizationView(View):
    '''
    Client authorization. Validates access credentials and generates a response
    with an authorization code passed as a parameter to the redirect URI, an
    access token passed as a URI fragment to the redirect URI, or both.

    **Kwargs:**

    * *authentication_method:* Type of token to generate. Possible values are
      oauth2.constants.MAC and oauth2.constants.BEARER.
    * *refreshable:* Whether issued tokens are refreshable.
    * *allowed_response_type:* Type of response the authorizer can generate.
      Possible values are oauth2.constants.CODE, oauth2.constants.TOKEN,
      and oauth2.constants.CODE_AND_TOKEN.
    * *allowed_scopes:* An iterable of oauth2.models.Scope objects representing
      the scopes the authorizer can grant.
      *Default None*
    '''
    query = {}
    user = None
    client = None
    redirect_uri = None
    scopes = []
    error = None
    valid = False

    @property
    def query_string(self):
        '''
        Returns a url encoded query string useful for resending request
        parameters when a user authorizes the request via a form POST.

        Raises UnvalidatedRequest if the request has not been validated.

        *Returns str*
        '''
        if not self.valid:
            raise UnvalidatedRequest('This request is invalid or has not been validated.')
        
        parameters = {
            'response_type': self.query['response_type'],
            'client_id': self.query['client_id']
        }
        
        if self.query['redirect_uri'] is not None:
            parameters['redirect_uri'] = self.query['redirect_uri']
        
        if self.query['state'] is not None:
            parameters['state'] = self.query['state']
        
        if self.query['scope'] is not None:
            parameters['scope'] = self.query['scope']
        
        return urlencode(parameters)

    def __init__(
            self,
            authentication_method=settings.AUTHENTICATION_METHOD,
            refreshable=settings.REFRESHABLE,
            allowed_response_type=settings.ALLOWED_RESPONSE_TYPE,
            allowed_scopes=None
        ):
        
        if authentication_method not in [constants.BEARER, constants.MAC]:
            raise OAuth2Exception('Possible values for authentication_method '
                'are oauth2.constants.MAC and oauth2.constants.BEARER.')
        self.authentication_method = authentication_method
        
        self.refreshable = refreshable
        
        if allowed_response_type not in [constants.CODE, constants.TOKEN, constants.CODE_AND_TOKEN]:
            raise OAuth2Exception('Possible values for allowed_response_type '
                'are oauth2.constants.CODE, oauth2.constants.TOKEN, '
                'oauth2.constants.CODE_AND_TOKEN.')
        self.allowed_response_type = allowed_response_type
        
        self.allowed_scopes = allowed_scopes

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(ClientAuthorizationView, self).dispatch(*args, **kwargs)
    
    def get(self, request, *args, **kwargs):
        try:
            self.validate(request, *args, **kwargs)
        
        except MissingRedirectURI as e:
            log.info('Authorization error %s' % e)
            return HttpResponseRedirect('/oauth2/missing_redirect_uri/')
        
        except (InvalidClient, InvalidScope, UnauthorizedScope, InvalidAuthorizationRequest, UnsupportedResponseType, UnauthorizedResponseType, AccessDenied) as e:
            # The request is malformed or invalid. Automatically redirect to the provided redirect URL.
            log.info('Authorization error %s' % e)
            return self.error_redirect()
        
        # Make sure the authorizer has validated before requesting the client or scopes as otherwise they will be None.
        form = AuthorizationForm()
            
        context = {
            'client': self.client, 
            'scopes': self.scopes,
            'form': form,
        }
        return render_to_response('oauth2/authorize.html', context, RequestContext(request))

    def post(self, request, *args, **kwargs):
        try:
            self.validate(request, *args, **kwargs)
        
        except MissingRedirectURI as e:
            log.info('Authorization error %s' % e)
            return HttpResponseRedirect('/oauth2/missing_redirect_uri/')
        
        except (InvalidClient, InvalidScope, UnauthorizedScope, InvalidAuthorizationRequest, UnsupportedResponseType, UnauthorizedResponseType, AccessDenied) as e:
            # The request is malformed or invalid. Automatically redirect to the provided redirect URL.
            log.info('Authorization error %s' % e)
            return self.error_redirect()
        
        form = AuthorizationForm(request.POST)
        if form.is_valid():
            if request.POST.get('authorize') == 'Allow access':
                return self.grant_redirect()
            else:
                return self.error_redirect()
        
        return HttpResponseRedirect('/')
        
    def validate(self, request, *args, **kwargs):
        '''
        Validate the request. Raises an AuthorizationException if the
        request fails authorization, or a MissingRedirectURI if no
        redirect_uri is available.

        **Args:**

        *Returns None*
        '''
        self.query = {
            'client_id': request.REQUEST.get('client_id'),
            'redirect_uri': request.REQUEST.get('redirect_uri'),
            'response_type': request.REQUEST.get('response_type'),
            'scope': request.REQUEST.get('scope'),
            'state': request.REQUEST.get('state'),
        }
        
        self.user = request.user
        
        try:
            self._validate()
        except (InvalidClient, InvalidScope, UnauthorizedScope, InvalidAuthorizationRequest, UnsupportedResponseType, UnauthorizedResponseType, AccessDenied) as e:
            self._check_redirect_uri()
            self.error = e
            raise e
        
        self.valid = True

    def _validate(self):
        # check client_id
        if self.query['client_id'] is None:
            raise InvalidAuthorizationRequest('No client_id provided')
        try:
            self.client = Client.objects.get(client_id=self.query['client_id'])
        except Client.DoesNotExist:
            raise InvalidClient("client_id %s doesn't exist" % self.query['client_id'])
        
        # check redirect URI
        if self.query['redirect_uri'] is None:
            if self.client.redirect_uri is None:
                raise MissingRedirectURI('No redirect_uri provided or registered.')
        elif self.client.redirect_uri is not None:
            if normalize(self.query['redirect_uri']) != normalize(self.client.redirect_uri):
                self.redirect_uri = self.client.redirect_uri
                raise InvalidAuthorizationRequest('Registered redirect_uri doesn\'t match provided redirect_uri.')
        self.redirect_uri = self.query['redirect_uri'] or self.client.redirect_uri
        if not absolute_http_url_re.match(self.redirect_uri):
            raise InvalidAuthorizationRequest('Absolute URI required for redirect_uri')
        
        # check response type
        if self.query['response_type'] is None:
            raise InvalidAuthorizationRequest('response_type is a required parameter.')
        if self.query['response_type'] not in ['code', 'token']:
            raise UnsupportedResponseType('No such response type %s' % self.query['response_type'])
        if self.allowed_response_type & RESPONSE_TYPES[self.query['response_type']] == 0:
            raise UnauthorizedResponseType('Response type %s not allowed.' % self.query['response_type'])
        
        # check scope
        if self.query['scope'] is not None:
            scope_names = set(self.query['scope'].split())
            invalid_scope_names = []
            for scope_name in scope_names:
                try:
                    scope = Scope.objects.get(name=scope_name)
                    self.scopes.append(scope)
                except Scope.DoesNotExist:
                    invalid_scope_names.append(scope_name)
            if len(invalid_scope_names) > 0:
                raise InvalidScope('The following scopes do not exist: %s' % ', '.join(invalid_scope_names))
            if self.allowed_scopes is not None:
                allowed_scope_names = set(self.allowed_scopes.values_list('name', flat=True))
                disallowed_scope_names = scope_names - allowed_scope_names
                if len(disallowed_scope_names) > 0:
                    raise UnauthorizedScope('The following scopes cannot be requested: %s' % ','.join(disallowed_scope_names))

    def _check_redirect_uri(self):
        '''
        Raise MissingRedirectURI if no redirect_uri is available.
        '''
        if self.redirect_uri is None:
            raise MissingRedirectURI('No redirect_uri to send response.')
        if not absolute_http_url_re.match(self.redirect_uri):
            raise MissingRedirectURI('Absolute redirect_uri required.')

    def error_redirect(self):
        '''
        In the event of an error, return a Django HttpResponseRedirect
        with the appropriate error parameters.

        Raises MissingRedirectURI if no redirect_uri is available.

        *Returns HttpResponseRedirect*
        '''
        
        self._check_redirect_uri()
        
        if self.error is not None:
            e = self.error
        else:
            e = AccessDenied('Access Denied.')
        
        parameters = {'error': e.error, 'error_description': u'%s' % e.message}
        
        if self.state is not None:
            parameters['state'] = self.state
        redirect_uri = self.redirect_uri
        
        if self.authorized_response_type & constants.CODE != 0:
            redirect_uri = add_parameters(redirect_uri, parameters)
        
        if self.authorized_response_type & constants.TOKEN != 0:
            redirect_uri = add_fragments(redirect_uri, parameters)
        
        return HttpResponseRedirect(redirect_uri)

    def grant_redirect(self):
        '''
        On successful authorization of the request, return a Django
        HttpResponseRedirect with the appropriate authorization code parameters
        or access token URI fragments.

        Raises UnvalidatedRequest if the request has not been validated.

        *Returns HttpResponseRedirect*
        '''
        
        if not self.valid:
            raise UnvalidatedRequest('This request is invalid or has not been validated.')
        
        if self.user.is_authenticated():
            parameters = {}
            fragments = {}
            
            if RESPONSE_TYPES[self.query['response_type']] & constants.CODE != 0:
                code = Code.objects.create(
                    user=self.user,
                    client=self.client,
                    redirect_uri=self.redirect_uri
                )
                
                code.scopes.add(*self.scopes)
                code.save()
                parameters['code'] = code.code
            
            if RESPONSE_TYPES[self.query['response_type']] & constants.TOKEN != 0:
                token = Token.objects.create(
                    user=self.user,
                    client=self.client
                )
                token.scopes.add(*self.scopes)
                
                fragments['access_token'] = token.access_token
                if token.refreshable:
                    fragments['refresh_token'] = token.refresh_token
                fragments['expires_in'] = settings.ACCESS_TOKEN_EXPIRATION
                
                if self.query['scope'] is not None:
                    fragments['scope'] = self.query['scope']
                
                if self.authentication_method == constants.MAC:
                    token.mac_key = KeyGenerator(settings.MAC_KEY_LENGTH)()
                    fragments['mac_key'] = token.mac_key
                    fragments['mac_algorithm'] = 'hmac-sha-256'
                    fragments['token_type'] = 'mac'
                
                elif self.authentication_method == constants.BEARER:
                    fragments['token_type'] = 'bearer'
                
                token.save()
            
            if self.query['state'] is not None:
                parameters['state'] = self.query['state']
            
            redirect_uri = add_parameters(self.redirect_uri, parameters)
            redirect_uri = add_fragments(redirect_uri, fragments)
            return HttpResponseRedirect(redirect_uri)
        
        else:
            raise UnauthenticatedUser('User object associated with the request is not authenticated.')

class TokenView(View):
    '''
    Token access handler. Validates authorization codes, refresh tokens,
    username/password pairs, and generates a JSON formatted authorization code.

    **Args:**

    * *request:* Django HttpRequest object.

    **Kwargs:**

    * *scope:* An iterable of oauth2app.models.AccessRange objects representing
      the scope the token generator will grant. *Default None*
    * *authentication_method:* Type of token to generate. Possible
      values are: oauth2.constants.BEARER and oauth2.constants.MAC
    * *refreshable:* Boolean value indicating whether issued tokens are
      refreshable.
    '''
    client = None
    user = None
    code = None
    token = None
    scopes = []
    valid = False
    error = None

    def __init__(
            self,
            authentication_method=settings.AUTHENTICATION_METHOD,
            refreshable=settings.REFRESHABLE,
            allowed_scopes=None
        ):
        self.refreshable = refreshable
        
        if authentication_method not in [constants.BEARER, constants.MAC]:
            raise OAuth2Exception("Possible values for authentication_method"
                " are oauth2.constants.MAC and oauth2.constants.BEARER")
        self.authentication_method = authentication_method
        
        self.allowed_scopes = allowed_scopes

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(TokenView, self).dispatch(*args, **kwargs)
    
    def get(self, request, *args, **kwargs):
        return self.valiate(request)
    
    def validate(self, request):
        '''
        Validate the request. Raises an AccessTokenException if the
        request fails authorization.

        *Returns None*
        '''
        self.grant_type = request.REQUEST.get('grant_type')
        self.client_id = request.REQUEST.get('client_id')
        self.client_secret = request.POST.get('client_secret')
        self.scope = request.REQUEST.get('scope')
        
        self.http_authorization = self.request.META['HTTP_AUTHORIZATION']
        
        # authorization_code, see 4.1.3.  Access Token Request
        self.authorization_code = request.REQUEST.get('code')
        self.redirect_uri = request.REQUEST.get('redirect_uri')
        
        # refresh_token, see 6.  Refreshing an Access Token
        self.refresh_token = request.REQUEST.get('refresh_token')
        
        # password, see 4.3.2. Access Token Request
        self.email = request.REQUEST.get('email')
        self.username = request.REQUEST.get('username')
        self.password = request.REQUEST.get('password')
        
        # optional json callback
        self.callback = request.REQUEST.get('callback')
        
        try:
            self._validate()
        except (InvalidTokenRequest, UnsupportedGrantType, InvalidGrant, InvalidClient, InvalidScope, UnauthorizedScope) as e:
            self.error = e
            return self.error_response()
        
        self.valid = True
        return self.grant_response()

    def _validate(self):
        # check client
        if self.client_id is None:
            raise InvalidTokenRequest('No client_id')
        try:
            self.client = Client.objects.get(client_id=self.client_id)
        except Client.DoesNotExist:
            raise InvalidClient('client_id %s doesn\'t exist' % self.client_id)
        
        # check scope
        if self.scope is not None:
            scope_names = set(self.scope.split())
            invalid_scope_names = []
            for scope_name in scope_names:
                try:
                    scope = Scope.objects.get(name=scope_name)
                    self.scopes.append(scope)
                except Scope.DoesNotExist:
                    invalid_scope_names.append(scope_name)
            if len(invalid_scope_names) > 0:
                raise InvalidScope('The following scopes do not exist: %s' % ', '.join(invalid_scope_names))
        
        # check grant type
        if self.grant_type is None:
            raise InvalidTokenRequest('No grant_type provided.')
        if self.grant_type == 'authorization_code':
            self._validate_authorization_code()
        elif self.grant_type == 'refresh_token':
            self._validate_refresh_token()
        elif self.grant_type == 'password':
            self._validate_password()
        elif self.grant_type == 'client_credentials':
            self._validate_client_credentials()
        else:
            raise UnsupportedGrantType('No such grant type: %s' % self.grant_type)

    def _validate_access_credentials(self):
        """Validate the request's access credentials."""
        if self.client_secret is None and "HTTP_AUTHORIZATION" in self.request.META:
            authorization = self.request.META["HTTP_AUTHORIZATION"]
            auth_type, auth_value = authorization.split()[0:2]
            if auth_type.lower() == "basic":
                credentials = "%s:%s" % (self.client.key, self.client.secret)
                if auth_value != b64encode(credentials):
                    raise InvalidClient('Client authentication failed.')
            else:
                raise InvalidClient('Client authentication failed.')
        elif self.client_secret != self.client.secret:
            raise InvalidClient('Client authentication failed.')

    def _validate_client_credentials(self):
        """Validate a client_credentials request."""
        self._validate_access_credentials()

    def _validate_authorization_code(self):
        """Validate an authorization_code request."""
        if self.authorization_code is None:
            raise InvalidTokenRequest('No authorization_code provided')
        
        self._validate_access_credentials()
        
        try:
            self.code = Code.objects.get(code=self.authorization_code)
        except Code.DoesNotExist:
            raise InvalidTokenRequest('No such code: %s' % self.authorization_code)
        
        now = TimestampGenerator()()
        if self.code.expire < now:
            raise InvalidGrant('Provided code is expired')
        
        self.scopes = self.code.scopes.all()
        
        if self.redirect_uri is None:
            raise InvalidTokenRequest('No redirect_uri')
        
        if normalize(self.redirect_uri) != normalize(self.code.redirect_uri):
            raise InvalidTokenRequest("redirect_uri doesn't match")

    def _validate_password(self):
        """Validate a password request."""
        if self.username is None and self.email is None:
            raise InvalidTokenRequest('No username')
        if self.password is None:
            raise InvalidTokenRequest('No password')
        
        if len(self.scopes) > 0:
            if self.allowed_scopes is not None:
                scope_names = set(self.scopes.values_list('name', flat=True))
                allowed_scope_names = set(self.allowed_scopes.values_list('name', flat=True))
                disallowed_scope_names = scope_names - allowed_scope_names
                if len(disallowed_scope_names) > 0:
                    raise UnauthorizedScope('The following scopes cannot be requested: %s' % ','.join(disallowed_scope_names))

        if "HTTP_AUTHORIZATION" in self.request.META:
            authorization = self.request.META["HTTP_AUTHORIZATION"]
            auth_type, auth_value = authorization.split()[0:2]
            if auth_type.lower() == "basic":
                credentials = "%s:%s" % (self.client.key, self.client.secret)
                if auth_value != b64encode(credentials):
                    raise InvalidClient('Client authentication failed.')
            else:
                raise InvalidClient('Client authentication failed.')
        else:
            raise InvalidClient('Client authentication failed.')
        
        if self.username is not None:
            user = authenticate(username=self.username, password=self.password)
        else:
            user = authenticate(email=self.email, password=self.password)
        
        if user is not None:
            if not user.is_active:
                raise InvalidTokenRequest('Inactive user.')
        else:
            raise InvalidTokenRequest('User authentication failed.')
        
        self.user = user

    def _validate_refresh_token(self):
        """Validate a refresh token request."""
        if self.refresh_token is None:
            raise InvalidTokenRequest('No refresh_token')
        
        try:
            self.token = Token.objects.get(refresh_token=self.refresh_token)
        except Token.DoesNotExist:
            raise InvalidTokenRequest('No such refresh token: %s' % self.refresh_token)
        
        self._validate_access_credentials()
        
        if not self.token.refreshable:
            raise InvalidGrant("Access token is not refreshable.")
        
        if len(self.scopes) > 0:
            scope_names = set(self.scopes.values_list('name', flat=True))
            allowed_scope_names = set(self.token.scopes.all().values_list('name', flat=True))
            disallowed_scope_names = scope_names - allowed_scope_names
            if len(disallowed_scope_names) > 0:
                raise UnauthorizedScope('Refresh request requested scopes beyond initial grant: %s' % disallowed_scope_names)

    def error_response(self):
        """In the event of an error, return a Django HttpResponse
        with the appropriate JSON encoded error parameters.

        *Returns HttpResponse*"""
        if self.error is not None:
            e = self.error
        else:
            e = InvalidTokenRequest("Access Denied.")
        data = {'error': e.error, 'error_description': u'%s' % e.message}
        json_data = dumps(data)
        if self.callback is not None:
            json_data = "%s(%s);" % (self.callback, json_data)
            return HttpResponse(
                content=json_data,
                content_type='application/json')
        else:
            response = HttpResponse(
                content=json_data,
                content_type='application/json')
            if isinstance(self.error, InvalidClient):
                response.status_code = 401
            else:
                response.status_code = 400
            return response

    def grant_response(self):
        """Returns a JSON formatted authorization code."""
        if not self.valid:
            raise UnvalidatedRequest("This request is invalid or has not been"
                " validated.")
        
        if self.grant_type == "authorization_code":
            access_token = self._get_authorization_code_token()
        elif self.grant_type == "refresh_token":
            access_token = self._get_refresh_token()
        elif self.grant_type == "password":
            access_token = self._get_password_token()
        elif self.grant_type == "client_credentials":
            access_token = self._get_client_credentials_token()
        
        data = {
            'access_token': access_token.token,
            'expires_in': settings.ACCESS_TOKEN_EXPIRATION
        }
        
        if self.authentication_method == constants.MAC:
            data["token_type"] = "mac"
            data["mac_key"] = access_token.mac_key
            data["mac_algorithm"] = "hmac-sha-256"
        elif self.authentication_method == constants.BEARER:
            data["token_type"] = "bearer"
        
        if access_token.refreshable:
            data['refresh_token'] = access_token.refresh_token
        
        if self.scope is not None:
            data['scope'] = ' '.join(self.scope)
        
        json_data = dumps(data)
        if self.callback is not None:
            json_data = "%s(%s);" % (self.callback, json_data)
        
        response = HttpResponse(
            content=json_data,
            content_type='application/json'
        )
        response['Cache-Control'] = 'no-store'
        return response

    def _get_authorization_code_token(self):
        """Generate an access token after authorization_code authorization."""
        access_token = Token.objects.create(
            user=self.code.user,
            client=self.client,
            refreshable=self.refreshable)
        
        if self.authentication_method == constants.MAC:
            access_token.mac_key = KeyGenerator(settings.MAC_KEY_LENGTH)()
        
        access_ranges = Scope.objects.filter(key__in=self.scope) if self.scope else [] # TODO: fix
        access_token.scope = access_ranges
        
        access_token.save()
        
        self.code.delete()
        
        return access_token

    def _get_password_token(self):
        """Generate an access token after password authorization."""
        access_token = Token.objects.create(
            user=self.user,
            client=self.client,
            refreshable=self.refreshable)
        
        if self.authentication_method == constants.MAC:
            access_token.mac_key = KeyGenerator(settings.MAC_KEY_LENGTH)()
        
        access_ranges = Scope.objects.filter(key__in=self.scope) if self.scope else [] # TODO: fix
        access_token.scope = access_ranges
        
        access_token.save()
        
        return access_token

    def _get_refresh_token(self):
        """Generate an access token after refresh authorization."""
        self.access_token.token = KeyGenerator(settings.ACCESS_TOKEN_LENGTH)()
        self.access_token.refresh_token = KeyGenerator(settings.REFRESH_TOKEN_LENGTH)()
        self.access_token.expire = TimestampGenerator(settings.ACCESS_TOKEN_EXPIRATION)()
        
        access_ranges = Scope.objects.filter(key__in=self.scope) if self.scope else [] # TODO: fix
        self.access_token.scope = access_ranges
        
        self.access_token.save()
        
        return self.access_token

    def _get_client_credentials_token(self):
        """Generate an access token after client_credentials authorization."""
        access_token = Token.objects.create(
            user=self.client.user,
            client=self.client,
            refreshable=self.refreshable)
        
        if self.authentication_method == constants.MAC:
            access_token.mac_key = KeyGenerator(settings.MAC_KEY_LENGTH)()
        
        access_ranges = Scope.objects.filter(key__in=self.scope) if self.scope else [] # TODO: fix
        self.access_token.scope = access_ranges
        
        self.access_token.save()
        
        return self.access_token
