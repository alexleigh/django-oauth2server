from django.contrib import admin

from .models import Client, ProtectedResource, AccessToken, Code, MACNonce

admin.site.register(Client)
admin.site.register(ProtectedResource)
admin.site.register(AccessToken)
admin.site.register(Code)
admin.site.register(MACNonce)