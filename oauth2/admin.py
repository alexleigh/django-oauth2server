from django.contrib import admin

from .models import Client, Scope, AccessToken, Code, MACNonce

admin.site.register(Client)
admin.site.register(Scope)
admin.site.register(AccessToken)
admin.site.register(Code)
admin.site.register(MACNonce)