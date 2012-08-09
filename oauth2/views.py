import logging
from hashlib import sha256
from urlparse import parse_qsl
from urllib import urlencode
from base64 import b64encode
from json import dumps

from django.http import HttpResponse, HttpResponseRedirect, absolute_http_url_re
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings as django_settings

from . import constants
from . import settings
from .models import Client, Scope, Code, Token
from .forms import AuthorizationForm
from .utils import KeyGenerator, TimestampGenerator
from .utils.uri import add_parameters, add_fragments, normalize
from .exceptions import OAuth2Exception, InvalidClient, MissingRedirectURI, UnvalidatedRequest, UnauthenticatedUser, InvalidScope, UnauthorizedScope
from .exceptions import AuthorizationException, InvalidAuthorizationRequest, AccessDenied, UnsupportedResponseType, UnauthorizedResponseType
from .exceptions import TokenException, InvalidTokenRequest, UnsupportedGrantType, InvalidGrant
from .exceptions import ValidationException, InvalidRequest, InvalidToken, InsufficientScope

log = logging.getLogger(__name__)

RESPONSE_TYPES = {
    'code': constants.CODE,
    'token': constants.TOKEN
}

@login_required
def missing_redirect_uri(request):
    return render_to_response('oauth2/missing_redirect_uri.html', context_instance=RequestContext(request))

class Authorizer(object):
    '''
    Client authorizer. Validates access credentials and generates a response
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
    client = None
    user = None
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

    def validate(self, user, query):
        '''
        Validate the request. Raises an AuthorizationException if the
        request fails authorization, or a MissingRedirectURI if no
        redirect_uri is available.

        **Args:**

        * *user:*
        * *query:*

        *Returns None*
        '''
        self.query = query
        self.user = user
        
        try:
            self._validate()
        except (AuthorizationException, InvalidClient, InvalidScope, UnauthorizedScope) as e:
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
                self.query['redirect_uri'] = self.client.redirect_uri
                raise InvalidAuthorizationRequest('Registered redirect_uri doesn\'t match provided redirect_uri.')
        self.query['redirect_uri'] = self.query['redirect_uri'] or self.client.redirect_uri
        if not absolute_http_url_re.match(self.query['redirect_uri']):
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
        if self.query['redirect_uri'] is None:
            raise MissingRedirectURI('No redirect_uri to send response.')
        if not absolute_http_url_re.match(self.query['redirect_uri']):
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
        redirect_uri = self.query['redirect_uri']
        
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
                    redirect_uri=self.redirect_uri,
                    scopes=self.scopes
                )
                
                code.save()
                parameters['code'] = code.code
            
            if RESPONSE_TYPES[self.query['response_type']] & constants.TOKEN != 0:
                token = Token.objects.create(
                    user=self.user,
                    client=self.client,
                    scopes=self.scopes
                )
                
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
            
            redirect_uri = add_parameters(self.query['redirect_uri'], parameters)
            redirect_uri = add_fragments(redirect_uri, fragments)
            return HttpResponseRedirect(redirect_uri)
        
        else:
            raise UnauthenticatedUser('User object associated with the request is not authenticated.')

@login_required
def authorize(request):
    authorizer = Authorizer()
    
    query = {
        'client_id': request.REQUEST.get('client_id'),
        'redirect_uri': request.REQUEST.get('redirect_uri'),
        'response_type': request.REQUEST.get('response_type'),
        'scope': request.REQUEST.get('scope'),
        'state': request.REQUEST.get('state'),
    }
    
    try:
        authorizer.validate(request.user, query)
    
    except MissingRedirectURI, e:
        log.info('Authorization error %s' % e)
        return HttpResponseRedirect('/oauth2/missing_redirect_uri/')
    
    except AuthorizationException, e:
        # The request is malformed or invalid. Automatically redirect to the provided redirect URL.
        log.info('Authorization error %s' % e)
        return authorizer.error_redirect()
    
    if request.method == 'GET':
        # Make sure the authorizer has validated before requesting the client or scopes as otherwise they will be None.
        form = AuthorizationForm()
        
        context = {
            'client': authorizer.client, 
            'scopes': authorizer.scopes,
            'form': form,
        }
        return render_to_response('oauth2/authorize.html', context, RequestContext(request))
    
    elif request.method == 'POST':
        form = AuthorizationForm(request.POST)
        if form.is_valid():
            if request.POST.get('authorize') == 'Allow access':
                return authorizer.grant_redirect()
            else:
                return authorizer.error_redirect()
    
    return HttpResponseRedirect('/')

class TokenGenerator(object):
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
        except (TokenException, InvalidClient, InvalidScope, UnauthorizedScope) as e:
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

@csrf_exempt
def token(request):
    token_generator = TokenGenerator()
    return token_generator.validate(request)

class Validator(object):
    '''
    Django HttpRequest validator. Checks a request for valid credentials and
    scope.

    **Kwargs:**

    * *scope:* An iterable of oauth2.models.AccessRange objects representing
      the scope the authenticator will authenticate.
      *Default None*
    * *authentication_method:* Accepted authentication methods. Possible
      values are: oauth2.constants.BEARER, oauth2.constants.MAC, 
      oauth2.constants.BEARER_AND_MAC
      *Default oauth2.constants.BEARER*
    '''

    valid = False
    access_token = None
    auth_type = None
    auth_value = None
    error = None
    attempted_validation = False

    @property
    def user(self):
        '''
        The user associated with the valid access token.

        *django.auth.User object*
        '''
        
        if not self.valid:
            raise UnvalidatedRequest("This request is invalid or has not "
                "been validated.")
        
        return self.access_token.user

    @property
    def scope(self):
        '''
        The client scope associated with the valid access token.

        *QuerySet of Scope objects.*
        '''
        
        if not self.valid:
            raise UnvalidatedRequest("This request is invalid or has not "
                "been validated.")
        
        return self.access_token.scope.all()
    
    @property
    def client(self):
        '''
        The client associated with the valid access token.

        *oauth2.models.Client object*
        '''
        
        if not self.valid:
            raise UnvalidatedRequest("This request is invalid or has not "
                "been validated.")
        
        return self.access_token.client

    def __init__(
            self,
            authentication_method=settings.AUTHENTICATION_METHOD,
            allowed_scope=None
        ):
        if authentication_method not in [constants.BEARER, constants.MAC, constants.BEARER_AND_MAC]:
            raise OAuth2Exception('Possible values for authentication_method '
                'are oauth2.constants.BEARER, oauth2.constants.MAC, '
                'oauth2.constants.BEARER_AND_MAC')
        self.authentication_method = authentication_method
        
        if allowed_scope is None:
            self.allowed_scope = None
        elif isinstance(allowed_scope, Scope):
            self.allowed_scope = set([allowed_scope.key])
        else:
            self.allowed_scope = set([x.key for x in allowed_scope])

    def validate(self, request):
        '''
        Validate the request. Raises an ValidationException if the request
        fails validation.

        **Args:**

        * *request:* Django HttpRequest object.

        *Returns None*
        '''
        
        self.request = request
        
        if 'HTTP_AUTHORIZATION' in self.request.META:
            auth = self.request.META['HTTP_AUTHORIZATION'].split()
            self.auth_type = auth[0].lower()
            self.auth_value = ' '.join(auth[1:]).strip()
            
        if self.auth_type not in ['bearer', 'mac']:
            access_token = request.REQUEST.get('access_token')
            if access_token is not None:
                self.auth_type = 'bearer'
                self.auth_value = access_token
        
        self.request_hostname = self.request.META.get('REMOTE_HOST')
        self.request_port = self.request.META.get('SERVER_PORT')
        
        try:
            self._validate()
        except ValidationException as e:
            self.error = e
            raise e
        self.valid = True

    def _validate(self):
        if self.auth_type in ['bearer', 'mac']:
            self.attempted_validation = True
            
            if self.auth_type == 'bearer':
                self._validate_bearer(self.auth_value)
            
            elif self.auth_type == 'mac':
                self._validate_mac(self.auth_value)
            
            self.valid = True

        else:
            raise InvalidRequest('Request authentication failed, no authentication credentials provided.')
        
        if self.allowed_scope is not None:
            token_scope = set([x.key for x in self.access_token.scope.all()])
            new_scope = self.allowed_scope - token_scope
            
            if len(new_scope) > 0:
                raise InsufficientScope(('Access token has insufficient '
                    'scope: %s') % ','.join(self.allowed_scope))
        
        now = TimestampGenerator()()
        if self.access_token.expire < now:
            raise InvalidToken('Token is expired')

    def _validate_bearer(self, token):
        '''
        Validate Bearer token.
        '''
        
        if self.authentication_method & constants.BEARER == 0:
            raise InvalidToken('Bearer authentication is not supported.')

        try:
            self.access_token = Token.objects.get(token=token)
        
        except Token.DoesNotExist:
            raise InvalidToken('Token doesn\'t exist')

    def _validate_mac(self, mac_header):
        '''
        Validate MAC authentication. Not implemented.
        '''
        
        if self.authentication_method & constants.MAC == 0:
            raise InvalidToken("MAC authentication is not supported.")
        
        mac_header = parse_qsl(mac_header.replace(",","&").replace('"', ''))
        mac_header = dict([(x[0].strip(), x[1].strip()) for x in mac_header])
        for parameter in ["id", "nonce", "mac"]:
            if "parameter" not in mac_header:
                raise InvalidToken("MAC Authorization header does not contain"
                    " required parameter '%s'" % parameter)
        if "bodyhash" in mac_header:
            bodyhash = mac_header["bodyhash"]
        else:
            bodyhash = ""
        if "ext" in mac_header:
            ext = mac_header["ext"]
        else:
            ext = ""
        if self.request_hostname is None:
            raise InvalidRequest("Request does not contain a hostname.")
        if self.request_port is None:
            raise InvalidRequest("Request does not contain a port.")
        nonce_timestamp, nonce_string = mac_header["nonce"].split(":")
        mac = sha256("\n".join([
            mac_header["nonce"], # The nonce value generated for the request
            self.request.method.upper(), # The HTTP request method 
            "XXX", # The HTTP request-URI
            self.request_hostname, # The hostname included in the HTTP request
            self.request_port, # The port as included in the HTTP request
            bodyhash,
            ext
        ])).hexdigest()
        log.debug('%s %s %s' % (nonce_timestamp, nonce_string, mac))
        raise NotImplementedError()

        # Todo:
        # 1.  Recalculate the request body hash (if included in the request) as
        # described in Section 3.2 and request MAC as described in
        # Section 3.3 and compare the request MAC to the value received
        # from the client via the "mac" attribute.
        # 2.  Ensure that the combination of nonce and MAC key identifier
        # received from the client has not been used before in a previous
        # request (the server MAY reject requests with stale timestamps;
        # the determination of staleness is left up to the server to
        # define).
        # 3.  Verify the scope and validity of the MAC credentials.

    def error_response(self,
            content='',
            mimetype=None,
            content_type=django_settings.DEFAULT_CONTENT_TYPE
        ):
        '''
        Error response generator. Returns a Django HttpResponse with status
        401 and the appropriate headers set. See Django documentation for details.

        **Kwargs:**

        * *content:* See Django docs. *Default ''*
        * *mimetype:* See Django docs. *Default None*
        * *content_type:* See Django docs. *Default DEFAULT_CONTENT_TYPE*
        '''
        
        response = HttpResponse(
            content=content,
            mimetype=mimetype,
            content_type=content_type
        )
        
        if not self.attempted_validation:
            response['WWW-Authenticate'] = 'Bearer realm="%s"' % settings.REALM
            response.status_code = 401
            return response

        else:
            if self.error is not None:
                error = getattr(self.error, "error", "invalid_request")
                error_description = self.error.message
            else:
                error = "invalid_request"
                error_description = "Invalid Request."
            header = [
                'Bearer realm="%s"' % settings.REALM,
                'error="%s"' % error,
                'error_description="%s"' % error_description]
            if isinstance(self.error, InsufficientScope):
                header.append('scope=%s' % ' '.join(self.authorized_scope))
                response.status_code = 403
            elif isinstance(self.error, InvalidToken):
                response.status_code = 401
            elif isinstance(self.error, InvalidRequest):
                response.status_code = 400
            else:
                response.status_code = 401
            response['WWW-Authenticate'] = ', '.join(header)
            return response

class JSONValidator(Validator):
    '''
    Wraps Authenticator, adds support for a callback parameter and JSON related
    convenience methods.

    **Args:**

    * *request:* Django HttpRequest object.

    **Kwargs:**

    * *scope:* A iterable of oauth2.models.AccessRange objects.
    '''
    
    callback = None
    
    def __init__(self, allowed_scope=None):
        Validator.__init__(self, allowed_scope=allowed_scope)
        
    def validate(self, request):
        self.callback = request.REQUEST.get('callback')
        return Validator.validate(self, request)
        
    def response(self, data):
        '''
        Returns a HttpResponse object of JSON serialized data.

        **Args:**

        * *data:* Object to be JSON serialized and returned.
        '''
        
        json_data = dumps(data)
        if self.callback is not None:
            json_data = "%s(%s);" % (self.callback, json_data)
        
        return HttpResponse(
            content=json_data,
            content_type='application/json'
        )

    def error_response(self):
        '''
        Returns a HttpResponse object of JSON error data.
        '''
        
        if self.error is not None:
            content = dumps({
                "error":getattr(self.error, "error", "invalid_request"),
                "error_description":self.error.message})
        
        else:
            content = ({
                "error":"invalid_request",
                "error_description":"Invalid Request."})
        
        if self.callback is not None:
            content = "%s(%s);" % (self.callback, content)
            
        response = Validator.error_response(
            self,
            content=content,
            content_type='application/json')
        if self.callback is not None:
            response.status_code = 200
        return response
