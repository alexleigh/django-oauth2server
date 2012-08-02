from django.conf import settings as _settings

from .constants import BEARER, MAC
from .exceptions import OAuth2Exception

# Length of the client key.
CLIENT_KEY_LENGTH = getattr(_settings, 'OAUTH2_CLIENT_KEY_LENGTH', 30)

# Length of the client secret.
CLIENT_SECRET_LENGTH = getattr(_settings, 'OAUTH2_CLIENT_SECRET_LENGTH', 30)

# Length of the code key.
CODE_KEY_LENGTH = getattr(_settings, 'OAUTH2_CODE_KEY_LENGTH', 30)

# Length of the MAC authentication key.
MAC_KEY_LENGTH = getattr(_settings, 'OAUTH2_MAC_KEY_LENGTH', 20)

# Length of the access token.
ACCESS_TOKEN_LENGTH = getattr(_settings, 'OAUTH2_ACCESS_TOKEN_LENGTH', 20)

# Length of the refresh token.
REFRESH_TOKEN_LENGTH = getattr(_settings, 'OAUTH2_REFRESH_TOKEN_LENGTH', 20)

# Issue refreshable tokens.
REFRESHABLE = getattr(_settings, 'OAUTH2_REFRESHABLE', True)

# Number of seconds in which an authorization code should expire.
CODE_EXPIRATION = getattr(_settings, 'OAUTH2_CODE_EXPIRATION', 120)

# Number of seconds in which an access token should expire.
ACCESS_TOKEN_EXPIRATION = getattr(_settings, 'OAUTH2_ACCESS_TOKEN_EXPIRATION', 3600)

# Type of authentication to use. Bearer or MAC.
AUTHENTICATION_METHOD = getattr(_settings, 'OAUTH2_AUTHENTICATION_METHOD', BEARER)

if AUTHENTICATION_METHOD not in [BEARER, MAC]:
    raise OAuth2Exception('Possible values for OAUTH2_AUTHENTICATION_METHOD '
        'are oauth2.constants.MAC and oauth2.constants.BEARER')

# Authentication realm
REALM = getattr(_settings, 'OAUTH2_REALM', '')
