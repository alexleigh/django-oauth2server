from django.conf import settings as _settings

from .constants import CODE, TOKEN, CODE_AND_TOKEN, BEARER, MAC
from .exceptions import OAuth2Exception

# Length of the client key.
CLIENT_ID_LENGTH = getattr(_settings, 'OAUTH2_CLIENT_ID_LENGTH', 30)

# Length of the client secret.
CLIENT_SECRET_LENGTH = getattr(_settings, 'OAUTH2_CLIENT_SECRET_LENGTH', 30)

# Length of the scope.
SCOPE_LENGTH = getattr(_settings, 'OAUTH2_SCOPE_LENGTH', 255)

# Length of the authorization code.
CODE_LENGTH = getattr(_settings, 'OAUTH2_CODE_LENGTH', 30)

# Number of seconds in which an authorization code should expire.
CODE_EXPIRATION = getattr(_settings, 'OAUTH2_CODE_EXPIRATION', 120)

# Length of the access token.
ACCESS_TOKEN_LENGTH = getattr(_settings, 'OAUTH2_ACCESS_TOKEN_LENGTH', 20)

# Number of seconds in which an access token should expire.
ACCESS_TOKEN_EXPIRATION = getattr(_settings, 'OAUTH2_ACCESS_TOKEN_EXPIRATION', 3600)

# Length of the refresh token.
REFRESH_TOKEN_LENGTH = getattr(_settings, 'OAUTH2_REFRESH_TOKEN_LENGTH', 20)

# Issue refreshable tokens.
REFRESHABLE = getattr(_settings, 'OAUTH2_REFRESHABLE', True)

# Length of the MAC authentication key.
MAC_KEY_LENGTH = getattr(_settings, 'OAUTH2_MAC_KEY_LENGTH', 20)

# Authentication realm
REALM = getattr(_settings, 'OAUTH2_REALM', '')

# Whether client authentication is required for the token endpoint
REQUIRES_CLIENT_AUTHENTICATION = getattr(_settings, 'OAUTH2_REQUIRES_CLIENT_AUTHENTICATION', False)

# Type of response to generate
ALLOWED_RESPONSE_TYPE = getattr(_settings, 'OAUTH2_ALLOWED_RESPONSE_TYPE', CODE)
if ALLOWED_RESPONSE_TYPE not in [CODE, TOKEN, CODE_AND_TOKEN]:
    raise OAuth2Exception('Possible values for OAUTH2_ALLOWED_RESPONSE_TYPE '
        'are oauth2.constants.CODE, oauth2.constants.TOKEN, '
        'and oauth2.constants.CODE_AND_TOKEN.')

# Type of authentication to use
AUTHENTICATION_METHOD = getattr(_settings, 'OAUTH2_AUTHENTICATION_METHOD', BEARER)
if AUTHENTICATION_METHOD not in [BEARER, MAC]:
    raise OAuth2Exception('Possible values for OAUTH2_AUTHENTICATION_METHOD '
        'are oauth2.constants.MAC and oauth2.constants.BEARER.')
