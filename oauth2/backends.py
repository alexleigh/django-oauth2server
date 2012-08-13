import logging
from hashlib import sha256
from urlparse import parse_qsl

from django.http import HttpResponse
from django.utils import simplejson
from django.conf import settings as django_settings

from . import constants
from . import settings
from .models import Scope, Token
from .utils import TimestampGenerator
from .exceptions import OAuth2Exception, InvalidAccessRequest, InvalidToken, InsufficientScope

log = logging.getLogger(__name__)

class OAuth2Backend(object):
    '''
    Request authentication. Checks a request for valid credentials and
    scope.

    **Kwargs:**
    * *authentication_method:* Accepted authentication methods. Possible
      values are: oauth2.constants.BEARER, oauth2.constants.MAC, 
      oauth2.constants.BEARER_AND_MAC
      *Default oauth2.constants.BEARER*
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

    def response(self, data):
        '''
        Returns a HttpResponse object of JSON serialized data.

        **Args:**

        * *data:* Object to be JSON serialized and returned.
        '''
        
        json_data = simplejson.dumps(data)
        if self.callback is not None:
            json_data = "%s(%s);" % (self.callback, json_data)
        
        return HttpResponse(
            content=json_data,
            content_type='application/json'
        )
    
    def error_response(self,
            content='',
            mimetype=None,
            content_type=django_settings.DEFAULT_CONTENT_TYPE
        ):
        '''
        Error response generator. Returns a Django HttpResponse with status
        401 and the appropriate headers set. See Django documentation for details.

        **Kwargs:**

        * *content:* See Django docs. *Default ''*
        * *mimetype:* See Django docs. *Default None*
        * *content_type:* See Django docs. *Default DEFAULT_CONTENT_TYPE*
        '''
        response = HttpResponse(
            content=content,
            mimetype=mimetype,
            content_type=content_type
        )
        
        if not self.attempted_validation:
            response['WWW-Authenticate'] = 'Bearer realm="%s"' % settings.REALM
            response.status_code = 401
            return response

        else:
            if self.error is not None:
                error = getattr(self.error, "error", "invalid_request")
                error_description = self.error.message
            else:
                error = "invalid_request"
                error_description = "Invalid Request."
            header = [
                'Bearer realm="%s"' % settings.REALM,
                'error="%s"' % error,
                'error_description="%s"' % error_description]
            if isinstance(self.error, InsufficientScope):
                header.append('scope=%s' % ' '.join(self.authorized_scope))
                response.status_code = 403
            elif isinstance(self.error, InvalidToken):
                response.status_code = 401
            elif isinstance(self.error, InvalidAccessRequest):
                response.status_code = 400
            else:
                response.status_code = 401
            response['WWW-Authenticate'] = ', '.join(header)
            return response
    
    def json_error_response(self):
        '''
        Returns a HttpResponse object of JSON error data.
        '''
        if self.error is not None:
            content = simplejson.dumps({
                "error":getattr(self.error, "error", "invalid_request"),
                "error_description":self.error.message})
        
        else:
            content = ({
                "error":"invalid_request",
                "error_description":"Invalid Request."})
        
        if self.callback is not None:
            content = "%s(%s);" % (self.callback, content)
            
        response = self.error_response(
            self,
            content=content,
            content_type='application/json')
        if self.callback is not None:
            response.status_code = 200
        return response
    
    def authenticate(self, request):
        valid = False
        token = None
        error = None
        attempted_validation = False
        
        callback = request.REQUEST.get('callback')
        
        request_hostname = request.META.get('REMOTE_HOST')
        request_port = request.META.get('SERVER_PORT')
        
        if 'HTTP_AUTHORIZATION' in request.META:
            auth = request.META['HTTP_AUTHORIZATION'].split()
            auth_type = auth[0].lower()
            auth_value = ' '.join(auth[1:]).strip()
            
        if auth_type not in ['bearer', 'mac']:
            access_token = request.REQUEST.get('access_token')
            if access_token is not None:
                self.auth_type = 'bearer'
                self.auth_value = access_token
        
        try:
            if auth_type in ['bearer', 'mac']:
                self.attempted_validation = True
                
                if self.auth_type == 'bearer':
                    if self.authentication_method & constants.BEARER == 0:
                        raise InvalidToken('Bearer authentication is not supported.')
            
                    try:
                        token = Token.objects.get(token=auth_type)
                    
                    except Token.DoesNotExist:
                        raise InvalidToken('Token doesn\'t exist')
                
                elif self.auth_type == 'mac':
                    self.validate_mac(self.auth_value)
                
                self.valid = True
    
            else:
                raise InvalidAccessRequest('Request authentication failed, no authentication credentials provided.')
            
            if self.allowed_scope is not None:
                token_scope = set([x.key for x in self.access_token.scope.all()])
                new_scope = self.allowed_scope - token_scope
                
                if len(new_scope) > 0:
                    raise InsufficientScope(('Access token has insufficient '
                        'scope: %s') % ','.join(self.allowed_scope))
            
            now = TimestampGenerator()()
            if self.access_token.expire < now:
                raise InvalidToken('Token is expired')
        
        except (InvalidAccessRequest, InvalidToken, InsufficientScope) as e:
            self.error = e
            raise e
        
        self.valid = True
        
        return (token.user, token.client, token.scopes.all())

    def validate_mac(self, mac_header):
        '''
        Validate MAC authentication. Not implemented.
        '''
        if self.authentication_method & constants.MAC == 0:
            raise InvalidToken("MAC authentication is not supported.")
        
        mac_header = parse_qsl(mac_header.replace(",","&").replace('"', ''))
        mac_header = dict([(x[0].strip(), x[1].strip()) for x in mac_header])
        for parameter in ["id", "nonce", "mac"]:
            if "parameter" not in mac_header:
                raise InvalidToken("MAC Authorization header does not contain"
                    " required parameter '%s'" % parameter)
        if "bodyhash" in mac_header:
            bodyhash = mac_header["bodyhash"]
        else:
            bodyhash = ""
        if "ext" in mac_header:
            ext = mac_header["ext"]
        else:
            ext = ""
        if self.request_hostname is None:
            raise InvalidAccessRequest("Request does not contain a hostname.")
        if self.request_port is None:
            raise InvalidAccessRequest("Request does not contain a port.")
        nonce_timestamp, nonce_string = mac_header["nonce"].split(":")
        mac = sha256("\n".join([
            mac_header["nonce"], # The nonce value generated for the request
            self.request.method.upper(), # The HTTP request method 
            "XXX", # The HTTP request-URI
            self.request_hostname, # The hostname included in the HTTP request
            self.request_port, # The port as included in the HTTP request
            bodyhash,
            ext
        ])).hexdigest()
        log.debug('%s %s %s' % (nonce_timestamp, nonce_string, mac))
        raise NotImplementedError()

        # Todo:
        # 1.  Recalculate the request body hash (if included in the request) as
        # described in Section 3.2 and request MAC as described in
        # Section 3.3 and compare the request MAC to the value received
        # from the client via the "mac" attribute.
        # 2.  Ensure that the combination of nonce and MAC key identifier
        # received from the client has not been used before in a previous
        # request (the server MAY reject requests with stale timestamps;
        # the determination of staleness is left up to the server to
        # define).
        # 3.  Verify the scope and validity of the MAC credentials.
