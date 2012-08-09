from django.contrib import admin

from .models import Client, Scope, Code, Token, Nonce

admin.site.register(Client)
admin.site.register(Scope)
admin.site.register(Code)
admin.site.register(Token)
admin.site.register(Nonce)
