import logging
from hashlib import sha256
from urlparse import parse_qsl

from django.http import HttpResponse
from django.utils import simplejson

from . import settings
from . import constants
from .models import Token
from .utils import TimestampGenerator
from .exceptions import InvalidRequest, InvalidToken, InsufficientScope

log = logging.getLogger(__name__)

def authenticate(request):
    authentication_method = None
    
    if 'HTTP_AUTHORIZATION' in request.META:
        auth = request.META['HTTP_AUTHORIZATION'].split()
        authentication_method = auth[0].lower()
    
    if authentication_method == 'bearer':
        access_token = ' '.join(auth[1:]).strip()
        
    elif authentication_method == 'mac':
        mac_header = ' '.join(auth[1:]).strip()
        
    else:
        access_token = request.REQUEST.get('access_token')
        if access_token is not None:
            authentication_method = 'bearer'
    
    if authentication_method is None:
        raise InvalidRequest('No authentication credentials provided.')
    
    if authentication_method not in ['bearer', 'mac']:
        raise InvalidRequest('Authentication method "%s" is not supported.' % authentication_method)
    
    token = None
    now = TimestampGenerator()()
    
    if authentication_method == 'bearer':
        if settings.AUTHENTICATION_METHOD & constants.BEARER == 0:
            raise InvalidToken('Bearer authentication is not supported.')
            
        try:
            token = Token.objects.get(access_token=access_token)
            
        except Token.DoesNotExist:
            raise InvalidToken('Token doesn\'t exist')
    
    elif authentication_method == 'mac':
        if settings.AUTHENTICATION_METHOD & constants.MAC == 0:
            raise InvalidToken('MAC authentication is not supported.')
        
        request_hostname = request.META.get('REMOTE_HOST')
        if request_hostname is None:
            raise InvalidRequest('Request does not contain a hostname.')
        
        request_port = request.META.get('SERVER_PORT')
        if request_port is None:
            raise InvalidRequest('Request does not contain a port.')
        
        request_method = request.method.upper()
        
        mac_header = parse_qsl(mac_header.replace(',', '&').replace('"', ''))
        mac_header = dict([(x[0].strip(), x[1].strip()) for x in mac_header])
        for parameter in ['id', 'nonce', 'mac']:
            if 'parameter' not in mac_header:
                raise InvalidToken('MAC Authorization header does not contain required parameter "%s"' % parameter)
        if 'bodyhash' in mac_header:
            bodyhash = mac_header['bodyhash']
        else:
            bodyhash = ''
        if 'ext' in mac_header:
            ext = mac_header['ext']
        else:
            ext = ''
        
        nonce_timestamp, nonce_string = mac_header['nonce'].split(':')
        mac = sha256('\n'.join([
            mac_header['nonce'], # The nonce value generated for the request
            request_method, # The HTTP request method 
            'XXX', # The HTTP request-URI
            request_hostname, # The hostname included in the HTTP request
            request_port, # The port as included in the HTTP request
            bodyhash,
            ext
        ])).hexdigest()
        
        log.debug('%s %s %s' % (nonce_timestamp, nonce_string, mac))
        raise NotImplementedError()
        
        # TODO:
        # 1. Recalculate the request body hash (if included in the request) as
        # described in Section 3.2 and request MAC as described in
        # Section 3.3 and compare the request MAC to the value received
        # from the client via the "mac" attribute.
        # 2. Ensure that the combination of nonce and MAC key identifier
        # received from the client has not been used before in a previous
        # request (the server MAY reject requests with stale timestamps;
        # the determination of staleness is left up to the server to
        # define).
        # 3. Verify the scope and validity of the MAC credentials.

    if token.expire < now:
        raise InvalidToken('Token is expired')
    
    return (token.user, token.scopes.all())

def has_scope_name(scope_name, scopes):
    scope_names = set([ scope.name for scope in scopes ])
    return scope_name in scope_names

def error_response(exception, content='', content_type=None):
    '''
    Error response generator. Returns an HttpResponse object with status code
    400/401/403 and the appropriate headers set.

    **Kwargs:**
    * *content:* See Django docs. *Default ''*
    * *content_type:* See Django docs. *Default DEFAULT_CONTENT_TYPE*
    '''
    if content_type:
        response = HttpResponse(content, content_type=content_type)
    else:
        response = HttpResponse(content)
    
    if exception is None:
        response['WWW-Authenticate'] = 'Bearer realm="%s"' % settings.REALM
        response.status_code = 401
        return response

    else:
        error = getattr(exception, 'error', 'invalid_request')
        error_description = exception.message
        
        header = [
            'Bearer realm="%s"' % settings.REALM,
            'error="%s"' % error,
            'error_description="%s"' % error_description
        ]
        
        if isinstance(exception, InsufficientScope):
            header.append('scope=%s' % exception.required_scope)
            response.status_code = 403
        
        elif isinstance(exception, InvalidToken):
            response.status_code = 401
        
        elif isinstance(exception, InvalidRequest):
            response.status_code = 400
        
        else:
            response.status_code = 401
        
        response['WWW-Authenticate'] = ', '.join(header)
        
        return response

def json_error_response(exception):
    '''
    Returns an HttpResponse object of JSON error data.
    '''
    if exception is None:
        content = ({
            'error': 'invalid_request',
            'error_description': 'Invalid request.'
        })
    
    else:
        content = ({
            'error': getattr(exception, 'error', 'invalid_request'),
            'error_description': exception.message
        })
    
    return error_response(
        exception,
        content=simplejson.dumps(content),
        content_type='application/json'
    )
