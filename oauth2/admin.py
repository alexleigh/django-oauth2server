from django.contrib import admin

from .models import Client, AccessRange, AccessToken, Code, MACNonce

admin.site.register(Client)
admin.site.register(AccessRange)
admin.site.register(AccessToken)
admin.site.register(Code)
admin.site.register(MACNonce)