from django.db import models
from django.contrib.auth.models import User
from django.contrib.contenttypes import generic
from django.contrib.contenttypes.models import ContentType
from model_utils import Choices

from .utils import KeyGenerator, TimestampGenerator
from .settings import CLIENT_KEY_LENGTH, CLIENT_SECRET_LENGTH, SCOPE_LENGTH
from .settings import ACCESS_TOKEN_LENGTH, REFRESH_TOKEN_LENGTH
from .settings import ACCESS_TOKEN_EXPIRATION, MAC_KEY_LENGTH, REFRESHABLE
from .settings import CODE_KEY_LENGTH, CODE_EXPIRATION

class Client(models.Model):
    '''
    Stores client authentication data.

    **Args:**

    * *name:* A string representing the client name.
    * *user:* A django.contrib.auth.models.User object representing the client
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
    description = models.TextField(null=True, blank=True)
    
    CLIENT_TYPE = Choices(
        ('web', 'Web application'),
        ('installed', 'Installed application'),
        ('service', 'Service account'),
    )
    client_type = models.CharField(max_length=20, choices=CLIENT_TYPE)
    
    key = models.CharField(
        unique=True,
        max_length=CLIENT_KEY_LENGTH,
        default=KeyGenerator(CLIENT_KEY_LENGTH),
        db_index=True
    )
    
    secret = models.CharField(
        unique=True,
        max_length=CLIENT_SECRET_LENGTH,
        default=KeyGenerator(CLIENT_SECRET_LENGTH)
    )
    
    redirect_uri = models.URLField(null=True)
    
    user = models.ForeignKey(User, null=True, blank=True)

class ProtectedResource(models.Model):
    '''
    Stores information about resources protected by OAuth2 and the scopes
    needed to access the resources.

    **Args:**

    * *scope:* A string representing the OAuth2 scope needed to access the
       resource. Used in access token requests and validation

    **Kwargs:**

    * *description:* A string representing the access range description.
      *Default None*
    '''
    
    content_type = models.ForeignKey(ContentType)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    object = generic.GenericForeignKey('content_type', 'object_id')
    
    scope = models.CharField(unique=True, max_length=SCOPE_LENGTH, db_index=True)
    description = models.TextField(blank=True)
    requires_user = models.BooleanField(default=False)

class Scope(models.Model):
    '''
    Stores OAuth 2 scopes.

    **Args:**

    * *name:* A string representing the OAuth2 scope needed to access the
       resource. Used in access token requests and validation

    **Kwargs:**

    * *description:* A string representing the scope description.
      *Default None*
    '''
    
    name = models.CharField(unique=True, max_length=SCOPE_LENGTH, db_index=True)
    description = models.TextField(blank=True)

class AccessToken(models.Model):
    '''
    Stores access token data.

    **Args:**

    * *client:* A oauth2app.models.Client object
    * *user:* A django.contrib.auth.models.User object

    **Kwargs:**

    * *token:* A string representing the access key token. *Default 10
      character random string*
    * *refresh_token:* A string representing the access key token. *Default 10
      character random string*
    * *mac_key:* A string representing the MAC key. *Default None*
    * *expire:* A positive integer timestamp representing the access token's
      expiration time.
    * *scope:* A list of oauth2app.models.AccessRange objects. *Default None*
    * *refreshable:* A boolean that indicates whether this access token is
      refreshable. *Default False*
    '''
    client = models.ForeignKey(Client)
    user = models.ForeignKey(User)
    token = models.CharField(
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
    scope = models.ManyToManyField(Scope)
    refreshable = models.BooleanField(default=REFRESHABLE)

class Code(models.Model):
    '''
    Stores authorization code data.

    **Args:**

    * *client:* A oauth2app.models.Client object
    * *user:* A django.contrib.auth.models.User object

    **Kwargs:**

    * *key:* A string representing the authorization code. *Default 30
      character random string*
    * *expire:* A positive integer timestamp representing the access token's
      expiration time.
    * *redirect_uri:* A string representing the redirect_uri provided by the
      requesting client when the code was issued. *Default None*
    * *scope:* A list of oauth2app.models.AccessRange objects. *Default None*
    '''
    client = models.ForeignKey(Client)
    user = models.ForeignKey(User)
    key = models.CharField(
        unique=True,
        max_length=CODE_KEY_LENGTH,
        default=KeyGenerator(CODE_KEY_LENGTH),
        db_index=True)
    issue = models.PositiveIntegerField(
        editable=False,
        default=TimestampGenerator())
    expire = models.PositiveIntegerField(
        default=TimestampGenerator(CODE_EXPIRATION))
    redirect_uri = models.URLField(null=True)
    scope = models.ManyToManyField(Scope)

class MACNonce(models.Model):
    '''
    Stores nonce strings for use with MAC Authentication.

    **Args:**

    * *access_token:* A oauth2app.models.AccessToken object
    * *nonce:* A unique nonce string.
    '''
    access_token = models.ForeignKey(AccessToken)
    nonce = models.CharField(max_length=30, db_index=True)
