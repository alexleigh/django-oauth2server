from django.conf.urls.defaults import patterns, include

urlpatterns = patterns('',
    (r'^oauth2/', include('oauth2.urls')),
    (r'^api/', include('api.urls')),
    (r'^accounts/', include('accounts.urls')),
)
