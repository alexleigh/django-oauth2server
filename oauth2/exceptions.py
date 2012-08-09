class OAuth2Exception(Exception):
    '''
    OAuth2 exception base class.
    '''
    pass

class InvalidClient(OAuth2Exception):
    '''
    Client authentication failed (e.g. unknown client, no client credentials
    included, multiple client credentials included, or unsupported credentials
    type).
    '''
    error = 'invalid_client'

class MissingRedirectURI(OAuth2Exception):
    '''
    Neither the request nor the client specify a redirect_uri.
    '''
    pass

class UnauthenticatedUser(OAuth2Exception):
    '''
    The provided user is not internally authenticated, via user.is_authenticated().
    '''
    pass

class UnvalidatedRequest(OAuth2Exception):
    '''
    The method requested requires a validated request to continue.
    '''
    pass

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

# authorization exceptions ----------
class AuthorizationException(OAuth2Exception):
    '''
    Authorization exception base class.
    '''
    pass

class InvalidAuthorizationRequest(AuthorizationException):
    '''
    The request is missing a required parameter, includes an unsupported
    parameter or parameter value, or is otherwise malformed.
    '''
    error = 'invalid_request'

class UnsupportedResponseType(AuthorizationException):
    '''
    The authorization response type is not supported by the authorization server.
    '''
    error = 'unsupported_response_type'

class UnauthorizedResponseType(AuthorizationException):
    '''
    The client is not authorized to request an authorization code using this
    method.
    '''
    error = 'unauthorized_response_type'

class AccessDenied(AuthorizationException):
    '''
    The resource owner or authorization server denied the request.
    '''
    error = 'access_denied'
    
# token exceptions ----------
class TokenException(OAuth2Exception):
    '''
    Access Token exception base class.
    '''
    pass

class InvalidTokenRequest(TokenException):
    '''
    The request is missing a required parameter, includes an
    unsupported parameter or parameter value, repeats a
    parameter, includes multiple credentials, utilizes more
    than one mechanism for authenticating the client, or is
    otherwise malformed.
    '''
    error = 'invalid_request'

class UnsupportedGrantType(TokenException):
    '''
    The authorization grant type is not supported by the authorization server.
    '''
    error = 'unsupported_grant_type'

class InvalidGrant(TokenException):
    '''
    The provided authorization grant is invalid, expired, revoked, does not
    match the redirection URI used in the authorization request, or was issued
    to another client.
    '''
    error = 'invalid_grant'

# validation exceptions ----------
class ValidationException(OAuth2Exception):
    '''
    Validation exception base class.
    '''
    pass

class InvalidRequest(ValidationException):
    '''
    The request is missing a required parameter, includes an
    unsupported parameter or parameter value, repeats the same
    parameter, uses more than one method for including an access
    token, or is otherwise malformed.
    '''
    error = 'invalid_request'

class InvalidToken(ValidationException):
    '''
    The access token provided is expired, revoked, malformed, or otherwise
    invalid.
    '''
    error = 'invalid_token'

class InsufficientScope(ValidationException):
    '''
    The request requires more scopes than those provided by the access token.
    '''
    error = 'insufficient_scope'
