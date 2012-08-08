from urllib import urlencode

from django.http import absolute_http_url_re, HttpResponseRedirect

from . import constants
from . import settings
from .lib.uri import add_parameters, add_fragments, normalize
from .exceptions import OAuth2Exception
from .models import Client, Scope, Code, AccessToken
from .utils import KeyGenerator

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
    Access authorizer. Validates access credentials and generates a response
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
    
    client = None
    access_ranges = None
    valid = False
    error = None

    @property
    def query_string(self):
        '''
        Returns the a url encoded query string useful for resending request
        parameters when a user authorizes the request via a form POST.

        Raises UnvalidatedRequest if the request has not been validated.

        *Returns str*
        '''
        
        if not self.valid:
            raise UnvalidatedRequest('This request is invalid or has not been validated.')
        
        parameters = {
            'response_type': self.response_type,
            'client_id': self.client_id
        }
        
        if self.redirect_uri is not None:
            parameters['redirect_uri'] = self.redirect_uri
        
        if self.state is not None:
            parameters['state'] = self.state
        
        if self.scope is not None:
            parameters['scope'] = ' '.join(self.scope)
        
        return urlencode(parameters)

    def __init__(
            self,
            authentication_method=settings.AUTHENTICATION_METHOD,
            refreshable=settings.REFRESHABLE,
            allowed_response_type=settings.ALLOWED_RESPONSE_TYPE,
            allowed_scope=None
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
        
        if allowed_scope is None:
            self.allowed_scope = None
        elif isinstance(allowed_scope, Scope):
            self.authorized_scope = set([allowed_scope.key])
        else:
            self.authorized_scope = set([x.key for x in allowed_scope])

    def validate(self, request):
        '''
        Validate the request. Raises an AuthorizationException if the
        request fails authorization, or a MissingRedirectURI if no
        redirect_uri is available.

        **Args:**

        * *request:* Django HttpRequest object.

        *Returns None*
        '''
        
        self.client_id = request.REQUEST.get('client_id')
        self.redirect_uri = request.REQUEST.get('redirect_uri')
        self.response_type = request.REQUEST.get('response_type')
        self.scope = request.REQUEST.get('scope')
        if self.scope is not None:
            self.scope = set(self.scope.split())
        self.state = request.REQUEST.get('state')
        self.user = request.user
        self.request = request
        
        try:
            self._validate()
        except AuthorizationException as e:
            self._check_redirect_uri()
            self.error = e
            raise e
        
        self.valid = True

    def _validate(self):
        if self.client_id is None:
            raise InvalidRequest('No client_id')
        
        # check client
        try:
            self.client = Client.objects.get(key=self.client_id)
        except Client.DoesNotExist:
            raise InvalidClient("client_id %s doesn't exist" % self.client_id)
        
        # check redirect URI
        if self.redirect_uri is None:
            if self.client.redirect_uri is None:
                raise MissingRedirectURI('No redirect_uri provided or registered.')
        elif self.client.redirect_uri is not None:
            if normalize(self.redirect_uri) != normalize(self.client.redirect_uri):
                self.redirect_uri = self.client.redirect_uri
                raise InvalidRequest('Registered redirect_uri doesn\'t match provided redirect_uri.')
        self.redirect_uri = self.redirect_uri or self.client.redirect_uri
        if not absolute_http_url_re.match(self.redirect_uri):
            raise InvalidRequest('Absolute URI required for redirect_uri')
        
        # check response type
        if self.response_type is None:
            raise InvalidRequest('response_type is a required parameter.')
        if self.response_type not in ['code', 'token']:
            raise InvalidRequest('No such response type %s' % self.response_type)
        if self.authorized_response_type & RESPONSE_TYPES[self.response_type] == 0:
            raise UnauthorizedClient('Response type %s not allowed.' % self.response_type)
        
        # check scope
        if self.authorized_scope is not None and self.scope is None:
            self.scope = self.authorized_scope
        if self.scope is not None:
            self.access_ranges = Scope.objects.filter(key__in=self.scope) # TODO: fix
            access_ranges = set(self.access_ranges.values_list('key', flat=True))
            difference = access_ranges.symmetric_difference(self.scope)
            if len(difference) != 0:
                raise InvalidScope("Following access ranges do not "
                    "exist: %s" % ', '.join(difference))
            if self.authorized_scope is not None:
                new_scope = self.scope - self.authorized_scope
                if len(new_scope) > 0:
                    raise InvalidScope("Invalid scope: %s" % ','.join(new_scope))

    def _check_redirect_uri(self):
        """Raise MissingRedirectURI if no redirect_uri is available."""
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
            
            if self.scope is not None:
                access_ranges = list(Scope.objects.filter(key__in=self.scope)) # TODO: fix
            else:
                access_ranges = []
            
            if RESPONSE_TYPES[self.response_type] & constants.CODE != 0:
                code = Code.objects.create(
                    user=self.user,
                    client=self.client,
                    redirect_uri=self.redirect_uri
                )
                
                code.scope.add(*access_ranges)
                code.save()
                parameters['code'] = code.key
            
            if RESPONSE_TYPES[self.response_type] & constants.TOKEN != 0:
                access_token = AccessToken.objects.create(
                    user=self.user,
                    client=self.client
                )
                
                access_token.scope = access_ranges
                fragments['access_token'] = access_token.token
                if access_token.refreshable:
                    fragments['refresh_token'] = access_token.refresh_token
                fragments['expires_in'] = settings.ACCESS_TOKEN_EXPIRATION
                
                if self.scope is not None:
                    fragments['scope'] = ' '.join(self.scope)
                
                if self.authentication_method == constants.MAC:
                    access_token.mac_key = KeyGenerator(settings.MAC_KEY_LENGTH)()
                    fragments["mac_key"] = access_token.mac_key
                    fragments["mac_algorithm"] = "hmac-sha-256"
                    fragments["token_type"] = "mac"
                
                elif self.authentication_method == constants.BEARER:
                    fragments["token_type"] = "bearer"
                
                access_token.save()
            
            if self.state is not None:
                parameters['state'] = self.state
            
            redirect_uri = add_parameters(self.redirect_uri, parameters)
            redirect_uri = add_fragments(redirect_uri, fragments)
            return HttpResponseRedirect(redirect_uri)
        
        else:
            raise UnauthenticatedUser('Django user object associated with the request is not authenticated.')
