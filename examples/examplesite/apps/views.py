from base64 import b64encode

from django.shortcuts import render_to_response
from django.template import RequestContext

from oauth2.models import Client, Scope, Token, Code

def index(request):
    context = {
        'apps': Client.objects.all()
    }
    
    return render_to_response(
        'apps/index.html', 
        context, 
        RequestContext(request))

def app(request, app_name):
    app = Client.objects.get(name=app_name)
    
    resources = [
        {
            'name': 'User info',
            'endpoint': '/api/v2/user/',
        },
        {
            'name': 'User info for user 1',
            'endpoint': '/api/v2/user/1/',
        },
        {
            'name': 'User info for user 2',
            'endpoint': '/api/v2/user/2/',
        },
    ]
    
    context = {
        'app': app,
        'basic_auth': 'Basic %s' % b64encode(app.client_id + ':' + app.client_secret),
        'codes': Code.objects.filter(client=app).select_related(),
        'tokens': Token.objects.filter(client=app).select_related(),
        'scopes': Scope.objects.all(),
        'resources': resources,
    }
    
    context['error_description'] = request.GET.get('error_description')
    
    return render_to_response(
        'apps/app.html', 
        context, 
        RequestContext(request))
