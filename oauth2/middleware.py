import logging

from django.utils import simplejson
from django.http import HttpResponse

log = logging.getLogger(__name__)

class OAuth2Middleware(object):
    def process_request(self, request):
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