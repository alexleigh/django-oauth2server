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

    **Kwargs:**
    * *client_id:* A string representing the client id. *Default 30 character
      random string*
    * *client_secret:* A string representing the client secret. *Default 30 character
      random string*
    * *redirect_uri:* A string representing the client redirect_uri.
      *Default None*
    * *client_type:* A string representing the client type. *Default web*
    * *name:* A string representing the client name.
    * *description:* A string representing the client description.
      *Default None*
    * *owner:* A django.contrib.auth.models.User object representing the client
       owner.
    '''
    client_id = models.CharField(
        max_length=CLIENT_ID_LENGTH,
        default=KeyGenerator(CLIENT_ID_LENGTH),
        primary_key=True,
        unique=True,
        db_index=True
    )
    
    client_secret = models.CharField(
        max_length=CLIENT_SECRET_LENGTH,
        default=KeyGenerator(CLIENT_SECRET_LENGTH),
        unique=True,
        blank=True
    )
    
    CLIENT_TYPE = Choices(
        ('web', 'Web application'),
        ('installed', 'Installed application'),
        ('service', 'Service account'),
    )
    client_type = models.CharField(
        max_length=20,
        choices=CLIENT_TYPE,
        default=CLIENT_TYPE.web
    )
    
    redirect_uri = models.URLField(null=True)
    
    name = models.CharField(max_length=255, unique=True)
    
    description = models.TextField(blank=True)
    
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
    name = models.CharField(
        max_length=SCOPE_LENGTH,
        unique=True,
        db_index=True
    )
    
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
    code = models.CharField(
        max_length=CODE_LENGTH,
        default=KeyGenerator(CODE_LENGTH),
        unique=True,
        db_index=True
    )
    
    issue = models.PositiveIntegerField(
        default=TimestampGenerator(),
        editable=False
    )
    
    expire = models.PositiveIntegerField(
        default=TimestampGenerator(CODE_EXPIRATION)
    )
    
    redirect_uri = models.URLField(null=True)
    
    scopes = models.ManyToManyField(Scope)
    
    client = models.ForeignKey(Client)
    
    user = models.ForeignKey(User)

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
    access_token = models.CharField(
        max_length=ACCESS_TOKEN_LENGTH,
        default=KeyGenerator(ACCESS_TOKEN_LENGTH),
        unique=True,
        db_index=True
    )
    
    refresh_token = models.CharField(
        max_length=REFRESH_TOKEN_LENGTH,
        default=KeyGenerator(REFRESH_TOKEN_LENGTH),
        unique=True,
        db_index=True,
        blank=True
    )
    
    mac_key = models.CharField(
        max_length=MAC_KEY_LENGTH,
        default=None,
        unique=True,
        db_index=True,
        blank=True
    )
    
    issue = models.PositiveIntegerField(
        default=TimestampGenerator(),
        editable=False
    )
    
    expire = models.PositiveIntegerField(
        default=TimestampGenerator(ACCESS_TOKEN_EXPIRATION)
    )
    
    refreshable = models.BooleanField(default=REFRESHABLE)
    
    scopes = models.ManyToManyField(Scope)
    
    client = models.ForeignKey(Client)
    
    user = models.ForeignKey(User)
    
class Nonce(models.Model):
    '''
    Stores nonce strings for use with MAC Authentication.

    **Args:**

    * *token:* An oauth2.models.Token object
    * *nonce:* A unique nonce string.
    '''
    nonce = models.CharField(max_length=30, db_index=True)
    
    token = models.ForeignKey(Token)
