from django.db import models
from django.contrib.auth.models import User
from model_utils import Choices

from .utils import KeyGenerator, TimestampGenerator
from .settings import CLIENT_ID_LENGTH, CLIENT_SECRET_LENGTH, SCOPE_LENGTH
from .settings import CODE_LENGTH, CODE_EXPIRATION
from .settings import ACCESS_TOKEN_LENGTH, ACCESS_TOKEN_EXPIRATION
from .settings import REFRESH_TOKEN_LENGTH, REFRESHABLE
from .settings import MAC_KEY_LENGTH

class Client(models.Model):
    '''
    Stores client data.

    **Args:**

    * *name:* A string representing the client name.
    * *owner:* A django.contrib.auth.models.User object representing the client
       owner.

    **Kwargs:**

    * *description:* A string representing the client description.
      *Default None*
    * *key:* A string representing the client key. *Default 30 character
      random string*
    * *secret:* A string representing the client secret. *Default 30 character
      random string*
    * *redirect_uri:* A string representing the client redirect_uri.
      *Default None*
    '''
    name = models.CharField(max_length=256)
    description = models.TextField(blank=True)
    redirect_uri = models.URLField(null=True)
    
    CLIENT_TYPE = Choices(
        ('web', 'Web application'),
        ('installed', 'Installed application'),
        ('service', 'Service account'),
    )
    client_type = models.CharField(max_length=20, choices=CLIENT_TYPE)
    
    client_id = models.CharField(
        unique=True,
        max_length=CLIENT_ID_LENGTH,
        default=KeyGenerator(CLIENT_ID_LENGTH),
        db_index=True
    )
    
    secret = models.CharField(
        unique=True,
        max_length=CLIENT_SECRET_LENGTH,
        default=KeyGenerator(CLIENT_SECRET_LENGTH)
    )
    
    owner = models.ForeignKey(User, null=True, blank=True)

class Scope(models.Model):
    '''
    Stores scope data.

    **Args:**

    * *name:* A string representing the OAuth2 scope needed to access the
       resource. Used in access token requests and validation

    **Kwargs:**

    * *description:* A string representing the scope description.
      *Default None*
    '''
    name = models.CharField(unique=True, db_index=True, max_length=SCOPE_LENGTH)
    description = models.TextField(blank=True)

class Code(models.Model):
    '''
    Stores authorization code data.

    **Args:**

    * *client:* An oauth2.models.Client object
    * *user:* A django.contrib.auth.models.User object

    **Kwargs:**

    * *key:* A string representing the authorization code. *Default 30
      character random string*
    * *expire:* A positive integer timestamp representing the access token's
      expiration time.
    * *redirect_uri:* A string representing the redirect_uri provided by the
      requesting client when the code was issued. *Default None*
    * *scope:* A list of oauth2.models.Scope objects. *Default None*
    '''
    client = models.ForeignKey(Client)
    redirect_uri = models.URLField(null=True)
    user = models.ForeignKey(User)
    
    code = models.CharField(
        unique=True,
        max_length=CODE_LENGTH,
        default=KeyGenerator(CODE_LENGTH),
        db_index=True)
    
    issue = models.PositiveIntegerField(
        editable=False,
        default=TimestampGenerator())
    
    expire = models.PositiveIntegerField(
        default=TimestampGenerator(CODE_EXPIRATION))
    
    scopes = models.ManyToManyField(Scope)

class Token(models.Model):
    '''
    Stores token data.

    **Args:**

    * *client:* An oauth2.models.Client object
    * *user:* A django.contrib.auth.models.User object

    **Kwargs:**

    * *access_token:* A string representing the access token. *Default 20
      character random string*
    * *refresh_token:* A string representing the refresh token. *Default 20
      character random string*
    * *mac_key:* A string representing the MAC key. *Default None*
    * *expire:* A positive integer timestamp representing the access token's
      expiration time.
    * *scope:* A list of oauth2.models.Scope objects. *Default None*
    * *refreshable:* A boolean that indicates whether this access token is
      refreshable. *Default True*
    '''
    client = models.ForeignKey(Client)
    user = models.ForeignKey(User)
    
    access_token = models.CharField(
        unique=True,
        max_length=ACCESS_TOKEN_LENGTH,
        default=KeyGenerator(ACCESS_TOKEN_LENGTH),
        db_index=True)
    
    refresh_token = models.CharField(
        unique=True,
        blank=True,
        null=True,
        max_length=REFRESH_TOKEN_LENGTH,
        default=KeyGenerator(REFRESH_TOKEN_LENGTH),
        db_index=True)
    
    mac_key = models.CharField(
        unique=True,
        blank=True,
        null=True,
        max_length=MAC_KEY_LENGTH,
        default=None)
    
    issue = models.PositiveIntegerField(
        editable=False,
        default=TimestampGenerator())
    
    expire = models.PositiveIntegerField(
        default=TimestampGenerator(ACCESS_TOKEN_EXPIRATION))
    
    refreshable = models.BooleanField(default=REFRESHABLE)
    
    scopes = models.ManyToManyField(Scope)

class Nonce(models.Model):
    '''
    Stores nonce strings for use with MAC Authentication.

    **Args:**

    * *token:* An oauth2.models.Token object
    * *nonce:* A unique nonce string.
    '''
    token = models.ForeignKey(Token)
    nonce = models.CharField(max_length=30, db_index=True)
