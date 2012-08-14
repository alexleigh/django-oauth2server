import logging

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
        if 'auth_type' in credentials and credentials['auth_type'] in ['bearer', 'mac']:
            token = None
            error = None
            now = TimestampGenerator()()
            
            if credentials['auth_type'] == 'bearer':
                if self.authentication_method & constants.BEARER:
                    try:
                        token = Token.objects.get(access_token=credentials['access_token'])
                        scope_names = set([ scope.name for scope in credentials['scopes'] ])
                        required_scope_names = set([ scope.name for scope in credentials['required_scopes'] ])
                        missing_scope_names = required_scope_names - scope_names
                    
                        if len(missing_scope_names) > 0:
                            error = InsufficientScope(('Access token has insufficient scope: %s') % ','.join(missing_scope_names))
        
                        elif token.expire < now:
                            error = InvalidToken('Token is expired')
                        
                        else:
                            user = token.user
                            error = NotImplementedError()
                    
                    except Token.DoesNotExist:
                        error = InvalidToken('Token doesn\'t exist')
                
                else:
                    error = InvalidToken('Bearer authentication is not supported.')
            
            elif credentials['auth_type'] == 'mac':
                error = NotImplementedError()
            
        else:
            error = InvalidRequest('Request authentication failed, no authentication credentials provided.')
            
        return error
