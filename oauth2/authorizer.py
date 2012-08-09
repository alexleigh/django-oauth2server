import logging
from urllib import urlencode

from django.http import absolute_http_url_re, HttpResponseRedirect

from . import constants
from . import settings
from .lib.uri import add_parameters, add_fragments, normalize
from .exceptions import OAuth2Exception
from .models import Client, Scope, Code, Token
from .utils import KeyGenerator

log = logging.getLogger(__name__)

RESPONSE_TYPES = {
    'code': constants.CODE,
    'token': constants.TOKEN
}
        
class AuthorizationException(OAuth2Exception):
    '''
    Authorization exception base class.
    '''
    pass

class MissingRedirectURI(OAuth2Exception):
    '''
    Neither the request nor the client specify a redirect_uri.
    '''
    pass

class UnauthenticatedUser(OAuth2Exception):
    '''
    The provided user is not internally authenticated, via user.is_authenticated()
    '''
    pass

class UnvalidatedRequest(OAuth2Exception):
    '''
    The method requested requires a validated request to continue.
    '''
    pass

class InvalidRequest(AuthorizationException):
    '''
    The request is missing a required parameter, includes an unsupported
    parameter or parameter value, or is otherwise malformed.
    '''
    error = 'invalid_request'

class InvalidClient(AuthorizationException):
    '''
    Client authentication failed (e.g. unknown client, no client credentials
    included, multiple client credentials included, or unsupported credentials
    type).
    '''
    error = 'invalid_client'

class UnauthorizedClient(AuthorizationException):
    '''
    The client is not authorized to request an authorization code using this
    method.
    '''
    error = 'unauthorized_client'

class AccessDenied(AuthorizationException):
    '''
    The resource owner or authorization server denied the request.
    '''
    error = 'access_denied'

class UnsupportedResponseType(AuthorizationException):
    '''
    The authorization server does not support obtaining an
    authorization code using this method.
    '''
    error = 'unsupported_response_type'

class InvalidScope(AuthorizationException):
    '''
    The requested scope is invalid, unknown, or malformed.
    '''
    error = 'invalid_scope'

class Authorizer(object):
    '''
    Client authorizer. Validates access credentials and generates a response
    with an authorization code passed as a parameter to the redirect URI, an
    access token passed as a URI fragment to the redirect URI, or both.

    **Kwargs:**

    * *scope:* An iterable of oauth2.models.Scope objects representing
      the scope the authorizer can grant.
      *Default None*
    * *response_type:* Type of response to generate.
    * *authentication_method:* Type of token to generate. Possible
      values are: oauth2.constants.MAC and oauth2.constants.BEARER
    * *refreshable:* Boolean value indicating whether issued tokens are
      refreshable.
      *Default True*
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

    def validate(self, request):
        '''
        Validate the request. Raises an AuthorizationException if the
        request fails authorization, or a MissingRedirectURI if no
        redirect_uri is available.

        **Args:**

        * *request:* Django HttpRequest object.

        *Returns None*
        '''
        # store query parameters
        self.query['client_id'] = request.REQUEST.get('client_id')
        self.query['redirect_uri'] = request.REQUEST.get('redirect_uri')
        self.query['response_type'] = request.REQUEST.get('response_type')
        self.query['scope'] = request.REQUEST.get('scope')
        self.query['state'] = request.REQUEST.get('state')
        
        self.user = request.user
        
        try:
            self._validate()
        except AuthorizationException as e:
            self._check_redirect_uri()
            self.error = e
            raise e
        
        self.valid = True

    def _validate(self):
        # check client_id
        if self.query['client_id'] is None:
            raise InvalidRequest('No client_id provided')
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
                raise InvalidRequest('Registered redirect_uri doesn\'t match provided redirect_uri.')
        self.query['redirect_uri'] = self.query['redirect_uri'] or self.client.redirect_uri
        if not absolute_http_url_re.match(self.query['redirect_uri']):
            raise InvalidRequest('Absolute URI required for redirect_uri')
        
        # check response type
        if self.query['response_type'] is None:
            raise InvalidRequest('response_type is a required parameter.')
        if self.query['response_type'] not in ['code', 'token']:
            raise InvalidRequest('No such response type %s' % self.query['response_type'])
        if self.authorized_response_type & RESPONSE_TYPES[self.query['response_type']] == 0:
            raise UnauthorizedClient('Response type %s not allowed.' % self.query['response_type'])
        
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
                    raise InvalidScope('Invalid scopes: %s' % ','.join(disallowed_scope_names))

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
