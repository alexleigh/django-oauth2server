from . import has_scope_name
from . import constants
from . import settings
from .models import Token
from .utils import TimestampGenerator
from .exceptions import OAuth2Exception

class OAuth2Backend(object):
    '''
    Authentication backend using OAuth2 access tokens. Currently supports
    bearer tokens only.
    '''
    def authenticate(self, **credentials):
        if 'authentication_method' in credentials:
            authentication_method = credentials['authentication_method']
            
            if authentication_method == 'bearer':
                if settings.AUTHENTICATION_METHOD & constants.BEARER:
                    if 'access_token' in credentials:
                        access_token = credentials['access_token']
                        
                        try:
                            token = Token.objects.get(
                                access_token=access_token
                            )
                            
                            now = TimestampGenerator()()
                            if token.expire >= now:
                                if has_scope_name(
                                    settings.AUTHENTICATION_SCOPE,
                                    token.scopes.all()
                                ):
                                    return token.user
                                
                        except OAuth2Exception:
                            pass
                    
        return None
