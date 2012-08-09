from base64 import b64encode
from json import dumps

from django.http import HttpResponse
from django.contrib.auth import authenticate

from . import constants
from . import settings
from .exceptions import OAuth2Exception
from .lib.uri import normalize
from .models import Client, Scope, Code, Token
from .utils import KeyGenerator, TimestampGenerator

class AccessTokenException(OAuth2Exception):
    '''
    Access Token exception base class.
    '''
    pass

class UnvalidatedRequest(OAuth2Exception):
    '''
    The method requested requires a validated request to continue.
    '''
    pass

class InvalidRequest(AccessTokenException):
    '''
    The request is missing a required parameter, includes an
    unsupported parameter or parameter value, repeats a
    parameter, includes multiple credentials, utilizes more
    than one mechanism for authenticating the client, or is
    otherwise malformed.
    '''
    error = 'invalid_request'

class InvalidClient(AccessTokenException):
    '''
    Client authentication failed (e.g. unknown client, no
    client credentials included, multiple client credentials
    included, or unsupported credentials type).
    '''
    error = 'invalid_client'

class UnauthorizedClient(AccessTokenException):
    '''
    The client is not authorized to request an authorization code using this
    method.
    '''
    error = 'unauthorized_client'

class InvalidGrant(AccessTokenException):
    '''
    The provided authorization grant is invalid, expired,
    revoked, does not match the redirection URI used in the
    authorization request, or was issued to another client.
    '''
    error = 'invalid_grant'

class UnsupportedGrantType(AccessTokenException):
    '''
    The authorization grant type is not supported by the authorization server.
    '''
    error = 'unsupported_grant_type'

class InvalidScope(AccessTokenException):
    '''
    The requested scope is invalid, unknown, malformed, or exceeds the scope
    granted by the resource owner.
    '''
    error = 'invalid_scope'

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
    request = None
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
        self.request = request
        
        try:
            self._validate()
        except AccessTokenException as e:
            self.error = e
            return self.error_response()
        
        self.valid = True
        return self.grant_response()

    def _validate(self):
        # check client
        if self.client_id is None:
            raise InvalidRequest('No client_id')
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
            raise InvalidRequest('No grant_type provided.')
        if self.grant_type == 'authorization_code':
            self._validate_authorization_code()
        elif self.grant_type == 'refresh_token':
            self._validate_refresh_token()
        elif self.grant_type == 'password':
            self._validate_password()
        elif self.grant_type == 'client_credentials':
            self._validate_client_credentials()
        else:
            raise UnsupportedGrantType('No grant type: %s' % self.grant_type)

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
            raise InvalidRequest('No authorization_code provided')
        
        self._validate_access_credentials()
        
        try:
            self.code = Code.objects.get(code=self.authorization_code)
        except Code.DoesNotExist:
            raise InvalidRequest('No such code: %s' % self.authorization_code)
        
        now = TimestampGenerator()()
        if self.code.expire < now:
            raise InvalidGrant('Provided code is expired')
        
        self.scopes = self.code.scopes.all()
        
        if self.redirect_uri is None:
            raise InvalidRequest('No redirect_uri')
        
        if normalize(self.redirect_uri) != normalize(self.code.redirect_uri):
            raise InvalidRequest("redirect_uri doesn't match")

    def _validate_password(self):
        """Validate a password request."""
        if self.username is None and self.email is None:
            raise InvalidRequest('No username')
        if self.password is None:
            raise InvalidRequest('No password')
        
        if len(self.scopes) > 0:
            if self.allowed_scopes is not None:
                scope_names = set(self.scopes.values_list('name', flat=True))
                allowed_scope_names = set(self.allowed_scopes.values_list('name', flat=True))
                disallowed_scope_names = scope_names - allowed_scope_names
                if len(disallowed_scope_names) > 0:
                    raise InvalidScope('Invalid scopes: %s' % ','.join(disallowed_scope_names))

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
                raise InvalidRequest('Inactive user.')
        else:
            raise InvalidRequest('User authentication failed.')
        
        self.user = user

    def _validate_refresh_token(self):
        """Validate a refresh token request."""
        if self.refresh_token is None:
            raise InvalidRequest('No refresh_token')
        
        try:
            self.token = Token.objects.get(refresh_token=self.refresh_token)
        except Token.DoesNotExist:
            raise InvalidRequest('No such refresh token: %s' % self.refresh_token)
        
        self._validate_access_credentials()
        
        if not self.token.refreshable:
            raise InvalidGrant("Access token is not refreshable.")
        
        if len(self.scopes) > 0:
            scope_names = set(self.scopes.values_list('name', flat=True))
            allowed_scope_names = set(self.token.scopes.all().values_list('name', flat=True))
            disallowed_scope_names = scope_names - allowed_scope_names
            if len(disallowed_scope_names) > 0:
                raise InvalidScope('Refresh request requested scopes beyond initial grant: %s' % disallowed_scope_names)

    def error_response(self):
        """In the event of an error, return a Django HttpResponse
        with the appropriate JSON encoded error parameters.

        *Returns HttpResponse*"""
        if self.error is not None:
            e = self.error
        else:
            e = InvalidRequest("Access Denied.")
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
