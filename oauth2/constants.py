# authentication types
# Sends and accepts bearer style authentication parameters 
# See http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-04
# and http://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-03
BEARER = 1
# Sends and accepts MAC style authentication parameters 
# See http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01
MAC = 2
BEARER_AND_MAC = BEARER | MAC

# response types
CODE = 1
TOKEN = 2
SECURE_TOKEN = 4
CODE_AND_TOKEN = CODE | TOKEN
