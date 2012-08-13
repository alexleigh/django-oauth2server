import logging

from django.http import HttpResponse
from django.utils import simplejson
from django.conf import settings as django_settings

from . import settings
from .exceptions import InvalidRequest, InvalidToken, InsufficientScope

log = logging.getLogger(__name__)

class OAuth2Middleware(object):
    callback = None
    
    def process_request(self, request):
        self.callback = request.REQUEST.get('callback')
        request_hostname = request.META.get('REMOTE_HOST')
        request_port = request.META.get('SERVER_PORT')
        request_method = request.method.upper()
        if 'HTTP_AUTHORIZATION' in request.META:
            auth = request.META['HTTP_AUTHORIZATION'].split()
            auth_type = auth[0].lower()
        
        if auth_type == 'bearer':
            access_token = ' '.join(auth[1:]).strip()
            
        elif auth_type == 'mac':
            mac_header = ' '.join(auth[1:]).strip()
            
        else:
            access_token = request.REQUEST.get('access_token')
            if access_token is not None:
                auth_type = 'bearer'
        
        return (auth_type, access_token, mac_header, request_hostname, request_port, request_method)

    def process_response(self, request, response):
        '''
        Returns a HttpResponse object of JSON serialized data.

        **Args:**
        * *response:* Object to be JSON serialized and returned.
        '''
        json_context = simplejson.dumps(response)
        if self.callback is not None:
            json_context = "%s(%s);" % (self.callback, json_context)
        return HttpResponse(json_context, content_type='application/json')
    
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
                'error_description="%s"' % error_description
            ]
            
            if isinstance(self.error, InsufficientScope):
                header.append('scope=%s' % ' '.join(self.authorized_scope))
                response.status_code = 403
            
            elif isinstance(self.error, InvalidToken):
                response.status_code = 401
            
            elif isinstance(self.error, InvalidRequest):
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
                'error': getattr(self.error, 'error', 'invalid_request'),
                'error_description': self.error.message
            })
        
        else:
            content = ({
                'error': 'invalid_request',
                'error_description': 'Invalid request.'
            })
        
        if self.callback is not None:
            content = '%s(%s);' % (self.callback, content)
            
        response = self.error_response(
            self,
            content=content,
            content_type='application/json'
        )
        
        if self.callback is not None:
            response.status_code = 200
        
        return response
