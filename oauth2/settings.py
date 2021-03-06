from django.conf import settings as _settings

from .constants import CODE, TOKEN, SECURE_TOKEN, BEARER, MAC
from .exceptions import OAuth2Exception

# URL prefix for OAuth2 endpoints
URL = getattr(_settings, 'OAUTH2_URL', '/oauth2/')

# Tuple of (scope_name, description) tuples
SCOPES = getattr(_settings, 'OAUTH2_SCOPES', ())

# Length of the scope name
SCOPE_LENGTH = getattr(_settings, 'OAUTH2_SCOPE_LENGTH', 255)

# Length of the client ID
CLIENT_ID_LENGTH = getattr(_settings, 'OAUTH2_CLIENT_ID_LENGTH', 32)

# Length of the client secret, must be at least 32
CLIENT_SECRET_LENGTH = getattr(_settings, 'OAUTH2_CLIENT_SECRET_LENGTH', 32)

# Length of the authorization code
CODE_LENGTH = getattr(_settings, 'OAUTH2_CODE_LENGTH', 32)

# Number of seconds in which an authorization code should expire
CODE_EXPIRATION = getattr(_settings, 'OAUTH2_CODE_EXPIRATION', 120)

# Length of the access token
ACCESS_TOKEN_LENGTH = getattr(_settings, 'OAUTH2_ACCESS_TOKEN_LENGTH', 24)

# Number of seconds in which an access token should expire
ACCESS_TOKEN_EXPIRATION = getattr(_settings, 'OAUTH2_ACCESS_TOKEN_EXPIRATION', 3600)

# Length of the refresh token
REFRESH_TOKEN_LENGTH = getattr(_settings, 'OAUTH2_REFRESH_TOKEN_LENGTH', 24)

# Issue refreshable tokens
REFRESHABLE = getattr(_settings, 'OAUTH2_REFRESHABLE', True)

# Length of the MAC authentication key
MAC_KEY_LENGTH = getattr(_settings, 'OAUTH2_MAC_KEY_LENGTH', 24)

# Authentication realm
REALM = getattr(_settings, 'OAUTH2_REALM', '')

# Type of response to generate
ALLOWED_RESPONSE_TYPE = getattr(_settings, 'OAUTH2_ALLOWED_RESPONSE_TYPE', CODE | TOKEN | SECURE_TOKEN)
if ALLOWED_RESPONSE_TYPE not in [
    CODE,
    TOKEN,
    SECURE_TOKEN,
    CODE | TOKEN,
    CODE | SECURE_TOKEN,
    TOKEN | SECURE_TOKEN,
    CODE | TOKEN | SECURE_TOKEN
]:
    raise OAuth2Exception('Possible values for OAUTH2_ALLOWED_RESPONSE_TYPE '
        'are oauth2.constants.CODE, oauth2.constants.TOKEN, '
        'oauth2.constants.SECURE_TOKEN, and their unions thereof.'
    )

# Type of authentication to use
AUTHENTICATION_METHOD = getattr(_settings, 'OAUTH2_AUTHENTICATION_METHOD', BEARER)
if AUTHENTICATION_METHOD not in [BEARER, MAC, BEARER | MAC]:
    raise OAuth2Exception('Possible values for OAUTH2_AUTHENTICATION_METHOD '
        'are oauth2.constants.BEARER, oauth2.constants.MAC, and their unions '
        'thereof.'
    )

# scope needed for authentication using the OAuth2 backend
AUTHENTICATION_SCOPE = getattr(_settings, 'OAUTH2_AUTHENTICATION_SCOPE', 'user_info')