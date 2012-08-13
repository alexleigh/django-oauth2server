import logging
from hashlib import sha256
from urlparse import parse_qsl

from . import constants
from . import settings
from .models import Token
from .utils import TimestampGenerator
from .exceptions import OAuth2Exception, InvalidRequest, InvalidToken, InsufficientScope

log = logging.getLogger(__name__)

class OAuth2Backend(object):
    '''
    Request authentication. Checks a request for valid credentials and
    scope.

    **Kwargs:**
    * *authentication_method:* Accepted authentication methods. Possible
      values are: oauth2.constants.BEARER, oauth2.constants.MAC, 
      oauth2.constants.BEARER_AND_MAC
      *Default oauth2.constants.BEARER*
    * *allowed_scopes:* An iterable of oauth2.models.Scope objects representing
      the scopes the authenticator will check against. None means no limit, an
      empty list means only requests with no scopes will be authenticated.
      *Default None*
    '''
    authentication_method = settings.AUTHENTICATION_METHOD
    allowed_scopes = None

    def __init__(self, **kwargs):
        for key, value in kwargs.iteritems():
            setattr(self, key, value)
            
        if self.authentication_method not in [
            constants.BEARER,
            constants.MAC,
            constants.BEARER_AND_MAC
        ]:
            raise OAuth2Exception(
                'Possible values for authentication_method are'
                'oauth2.constants.BEARER, oauth2.constants.MAC, '
                'oauth2.constants.BEARER_AND_MAC')
    
    def authenticate(self, **credentials):
        token = None
        error = None
        
        if credentials['auth_type'] in ['bearer', 'mac']:
            if credentials['auth_type'] == 'bearer':
                if self.authentication_method & constants.BEARER == 0:
                    raise InvalidToken('Bearer authentication is not supported.')
        
                try:
                    token = Token.objects.get(access_token=credentials['access_token'])
                
                except Token.DoesNotExist:
                    error = InvalidToken('Token doesn\'t exist')
            
            elif credentials['auth_type'] == 'mac':
                if self.authentication_method & constants.MAC == 0:
                    raise InvalidToken('MAC authentication is not supported.')
                request_hostname = credentials['request_hostname']
                request_port = credentials['request_port']
                request_method = credentials['request_method']
                mac_header = parse_qsl(credentials['mac_header'].replace(',', '&').replace('"', ''))
                mac_header = dict([(x[0].strip(), x[1].strip()) for x in mac_header])
                for parameter in ['id', 'nonce', 'mac']:
                    if 'parameter' not in mac_header:
                        raise InvalidToken('MAC Authorization header does not contain required parameter "%s"' % parameter)
                if 'bodyhash' in mac_header:
                    bodyhash = mac_header['bodyhash']
                else:
                    bodyhash = ''
                if 'ext' in mac_header:
                    ext = mac_header['ext']
                else:
                    ext = ''
                if request_hostname is None:
                    raise InvalidRequest('Request does not contain a hostname.')
                if request_port is None:
                    raise InvalidRequest('Request does not contain a port.')
                nonce_timestamp, nonce_string = mac_header['nonce'].split(':')
                mac = sha256('\n'.join([
                    mac_header['nonce'], # The nonce value generated for the request
                    request_method, # The HTTP request method 
                    'XXX', # The HTTP request-URI
                    request_hostname, # The hostname included in the HTTP request
                    request_port, # The port as included in the HTTP request
                    bodyhash,
                    ext
                ])).hexdigest()
                log.debug('%s %s %s' % (nonce_timestamp, nonce_string, mac))
                raise NotImplementedError()
                # TODO:
                # 1. Recalculate the request body hash (if included in the request) as
                # described in Section 3.2 and request MAC as described in
                # Section 3.3 and compare the request MAC to the value received
                # from the client via the "mac" attribute.
                # 2. Ensure that the combination of nonce and MAC key identifier
                # received from the client has not been used before in a previous
                # request (the server MAY reject requests with stale timestamps;
                # the determination of staleness is left up to the server to
                # define).
                # 3. Verify the scope and validity of the MAC credentials.

        else:
            error = InvalidRequest('Request authentication failed, no authentication credentials provided.')
        
        now = TimestampGenerator()()
        if token.expire < now:
            raise InvalidToken('Token is expired')
        
        return (token.user, token.client, token.scopes.all(), error)
    
    def authorize(self, scopes, required_scopes):
        scope_names = set([ scope.name for scope in scopes ])
        required_scope_names = set([ scope.name for scope in required_scopes ])
        missing_scope_names = required_scope_names - scope_names
            
        if len(missing_scope_names) > 0:
            raise InsufficientScope(('Access token has insufficient scope: %s') % ','.join(missing_scope_names))
