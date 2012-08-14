class OAuth2Middleware(object):
    def process_request(self, request):
        request_hostname = request.META.get('REMOTE_HOST')
        request_port = request.META.get('SERVER_PORT')
        request_method = request.method.upper()
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
        
        raise NotImplementedError()
        return (authentication_method, access_token, mac_header, request_hostname, request_port, request_method)