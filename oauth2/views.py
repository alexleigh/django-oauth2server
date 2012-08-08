import logging

from django.http import HttpResponseRedirect
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

from .authorizer import Authorizer, MissingRedirectURI, AuthorizationException
from .token_generator import TokenGenerator
from .forms import AuthorizationForm

log = logging.getLogger(__name__)

@login_required
def authorize(request):
    authorizer = Authorizer()
    
    try:
        authorizer.validate(request)
    
    except MissingRedirectURI, e:
        log.info('Authorization error %s' % e)
        return HttpResponseRedirect('/oauth2/missing_redirect_uri/')
    
    except AuthorizationException, e:
        # The request is malformed or invalid. Automatically redirect to the provided redirect URL.
        log.info('Authorization error %s' % e)
        return authorizer.error_redirect()
    
    if request.method == 'GET':
        # Make sure the authorizer has validated before requesting the client or access_ranges as otherwise they will be None.
        form = AuthorizationForm()
        
        context = {
            'client': authorizer.client, 
            'access_ranges': authorizer.access_ranges,
            'form': form,
        }
        return render_to_response('oauth2/authorize.html', context, RequestContext(request))
    
    elif request.method == 'POST':
        form = AuthorizationForm(request.POST)
        if form.is_valid():
            if request.POST.get('authorize') == 'Allow access':
                return authorizer.grant_redirect()
            else:
                return authorizer.error_redirect()
    
    return HttpResponseRedirect('/')

@login_required
def missing_redirect_uri(request):
    return render_to_response('oauth2/missing_redirect_uri.html', context_instance=RequestContext(request))

@csrf_exempt
def token(request):
    token_generator = TokenGenerator()
    return token_generator.validate(request)
