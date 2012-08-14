class OAuth2Exception(Exception):
    '''
    OAuth2 exception base class.
    '''
    error = 'oauth2_error'

class OAuth2ClientException(OAuth2Exception):
    '''
    Exceptions related to client authentication. These exceptions should result
    in an error page being displayed, rather than a redirect to the requesting
    client.
    '''
    pass

class OAuth2RedirectURIException(OAuth2Exception):
    '''
    Exceptions related to redirect URIs. These exceptions should result in an
    error page being displayed, rather than a redirect to the requesting
    client.
    '''
    pass

class AccessDenied(OAuth2Exception):
    '''
    The user denied authorization.
    '''
    error = 'access_denied'

class AuthenticationFailed(OAuth2Exception):
    '''
    User authentication failed.
    '''
    error = 'authentication_failed'

class InvalidRequest(OAuth2Exception):
    '''
    The request is missing a required parameter, includes an
    unsupported parameter or parameter value, repeats the same
    parameter, uses more than one method for including an access
    token, or is otherwise malformed.
    '''
    error = 'invalid_request'

class InvalidClientId(OAuth2ClientException, InvalidRequest):
    '''
    No client_id supplied, or the supplied client_id is malformed.
    '''
    pass

class InvalidRedirectURI(OAuth2RedirectURIException, InvalidRequest):
    '''
    No redirect_uri supplied, or the supplied redirect_uri is malformed.
    '''
    pass

class InvalidResponseType(InvalidRequest):
    '''
    No response_type supplied, or the supplied response_type is invalid,
    unknown, malformed, or not authorized.
    '''
    pass

class InvalidGrantType(InvalidRequest):
    '''
    No grant type supplied, or the grant type is not supported by the server.
    '''
    pass

class RedirectURIMismatch(OAuth2RedirectURIException):
    '''
    The supplied redirect_uri does not match the registered redirect_uri
    for the client.
    '''
    error = 'redirect_uri_mismatch'

class InvalidClient(OAuth2ClientException):
    '''
    The supplied client_id does not identify a valid client.
    '''
    error = 'invalid_client'

class InvalidScope(OAuth2Exception):
    '''
    The requested scope is invalid, unknown, or malformed.
    '''
    error = 'invalid_scope'
    
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

class InsufficientScope(OAuth2Exception):
    '''
    The request requires more scopes than those provided by the access token.
    
    **Attributes:**
    * *required_scope:* A space-separated list of the required scopes. *Default ''*
    '''
    error = 'insufficient_scope'
    required_scope = ''
    
    def __init__(self, required_scope):
        self.required_scope = required_scope
        self.message = 'Access token has insufficient scope: %s' % self.required_scope
