class OAuth2Exception(Exception):
    '''
    OAuth2 exception base class.
    '''
    pass

# TODO: remove
class UnvalidatedRequest(OAuth2Exception):
    '''
    The method requested requires a validated request to continue.
    '''
    pass

class MissingClientId(OAuth2Exception):
    error = 'invalid_request'
    
class InvalidClient(OAuth2Exception):
    '''
    Client authentication failed (e.g. unknown client, no client credentials
    included, multiple client credentials included, or unsupported credentials
    type).
    '''
    error = 'invalid_client'

class MissingRedirectURI(OAuth2Exception):
    error = 'missing_redirect_uri'

class RedirectURIMismatch(OAuth2Exception):
    error = 'redirect_uri_mismatch'

class AccessDenied(OAuth2Exception):
    '''
    The resource owner or authorization server denied the request.
    '''
    error = 'access_denied'

class InvalidScope(OAuth2Exception):
    '''
    The requested scope is invalid, unknown, or malformed.
    '''
    error = 'invalid_scope'

class UnauthorizedScope(OAuth2Exception):
    '''
    The requested scope exceeds the scope allowed by the authorization server
    or the resource owner.
    '''
    error = 'unauthorized_scope'

class InsufficientScope(OAuth2Exception):
    '''
    The request requires more scopes than those provided by the access token.
    '''
    error = 'insufficient_scope'

class InvalidAuthorizationRequest(OAuth2Exception):
    '''
    The request is missing a required parameter, includes an unsupported
    parameter or parameter value, or is otherwise malformed.
    '''
    error = 'invalid_request'

class InvalidTokenRequest(OAuth2Exception):
    '''
    The request is missing a required parameter, includes an
    unsupported parameter or parameter value, repeats a
    parameter, includes multiple credentials, utilizes more
    than one mechanism for authenticating the client, or is
    otherwise malformed.
    '''
    error = 'invalid_request'

class InvalidAccessRequest(OAuth2Exception):
    '''
    The request is missing a required parameter, includes an
    unsupported parameter or parameter value, repeats the same
    parameter, uses more than one method for including an access
    token, or is otherwise malformed.
    '''
    error = 'invalid_request'

class InvalidGrant(OAuth2Exception):
    '''
    The provided authorization grant is invalid, expired, revoked, does not
    match the redirection URI used in the authorization request, or was issued
    to another client.
    '''
    error = 'invalid_grant'

class InvalidToken(OAuth2Exception):
    '''
    The access token provided is expired, revoked, malformed, or otherwise
    invalid.
    '''
    error = 'invalid_token'

class UnsupportedResponseType(OAuth2Exception):
    '''
    The authorization response type is not supported by the authorization server.
    '''
    error = 'unsupported_response_type'

class UnauthorizedResponseType(OAuth2Exception):
    '''
    The client is not authorized to request an authorization code using this
    method.
    '''
    error = 'unauthorized_response_type'

class UnsupportedGrantType(OAuth2Exception):
    '''
    The authorization grant type is not supported by the authorization server.
    '''
    error = 'unsupported_grant_type'
