from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

from oauth2.models import Client
from .forms import SignupForm, LoginForm, ClientCreationForm, ClientDeletionForm

@login_required
def index(request):
    if request.method == 'POST':
        form = ClientCreationForm(request.POST)
        remove_form = ClientDeletionForm(request.POST)
        
        if form.is_valid():
            Client.objects.create(
                name=form.cleaned_data['name'],
                description=form.cleaned_data['description'],
                redirect_uri=form.cleaned_data['redirect_uri'],
                client_profile=form.cleaned_data['client_profile'],
                owner=request.user
            )
        
        elif remove_form.is_valid():
            # TODO: make sure client belongs to user
            Client.objects.filter(client_id=remove_form.cleaned_data['client_id']).delete()
            form = ClientCreationForm()

    else:
        form = ClientCreationForm()

    context = {
        'form': form, 
        'clients': Client.objects.filter(owner=request.user)
    }

    return render_to_response(
        'accounts/index.html', 
        context, 
        RequestContext(request)
    )

def login(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            user = auth.authenticate(
                username=form.cleaned_data["username"],
                password=form.cleaned_data["password"])
            auth.login(request, user)
            return HttpResponseRedirect("/")
    
    else:
        form = LoginForm()
    
    template = {"form":form}
    
    return render_to_response('accounts/login.html', template, RequestContext(request))

@login_required    
def logout(request):
    auth.logout(request)
    return render_to_response('accounts/logout.html', {}, RequestContext(request))

def signup(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            user = User.objects.create_user(
                    form.cleaned_data["username"],
                    form.cleaned_data["email"],
                    form.cleaned_data["password1"],)
            user = auth.authenticate(
                    username=form.cleaned_data["username"],
                    password=form.cleaned_data["password1"])
            auth.login(request, user)
            return HttpResponseRedirect("/")
    else:
        form = SignupForm()
    template = {"form":form}
    return render_to_response(
        'accounts/signup.html', 
        template, 
        RequestContext(request))

