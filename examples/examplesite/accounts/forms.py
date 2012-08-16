from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import UserCreationForm

from crispy_forms.helpers import FormHelper, Submit, Reset
from oauth2.models import Client
from oauth2.settings import CLIENT_ID_LENGTH

class ClientCreationForm(forms.Form):
    name = forms.CharField(label='Name', max_length=255)
    description = forms.CharField(label='Description', max_length=255)
    redirect_uri = forms.URLField(label='Redirect URI', max_length=255)
    client_type = forms.ChoiceField(label='Client type', choices=Client.CLIENT_TYPE)

class ClientDeletionForm(forms.Form):
    client_id = forms.CharField(max_length=CLIENT_ID_LENGTH)

class SignupForm(UserCreationForm):
    email = forms.EmailField(label="Email")
    
    @property
    def helper(self):
        form = SignupForm()
        helper = FormHelper()
        reset = Reset('','Reset')
        helper.add_input(reset)
        submit = Submit('','Sign Up')
        helper.add_input(submit)
        helper.form_action = '/accounts/signup/'
        helper.form_method = 'POST'
        return helper


class LoginForm(forms.Form):
    username = forms.CharField(label="Username", max_length=30)
    password = forms.CharField(label="Password", widget=forms.PasswordInput)
    
    @property
    def helper(self):
        form = LoginForm()
        helper = FormHelper()
        reset = Reset('','Reset')
        helper.add_input(reset)
        submit = Submit('','Log In')
        helper.add_input(submit)
        helper.form_action = '/accounts/login/'
        helper.form_method = 'POST'
        return helper

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if username and password:
            self.user_cache = authenticate(username=username, password=password)
            if self.user_cache is None:
                raise forms.ValidationError("Please enter a correct username and password. Note that both fields are case-sensitive.")
            elif not self.user_cache.is_active:
                raise forms.ValidationError("This account is inactive.")
        return self.cleaned_data