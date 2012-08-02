# Sends and accepts Bearer style authentication parameters 
# See http://tools.ietf.org/html/draft-ietf-oauth-saml2-bearer-03
# and http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-04
BEARER = 1

# Sends and accepts MAC style authentication parameters 
# See http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-00
MAC = 2 

# Grants token style fragments.
TOKEN = 1

# Grants code style parameters.
CODE = 2

# Grants both style parameters.
CODE_AND_TOKEN = CODE | TOKEN
