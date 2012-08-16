from django.conf.urls.defaults import patterns, include

urlpatterns = patterns('',
    (r'^oauth2/', include('oauth2.urls')),
    (r'^accounts/', include('accounts.urls')),
    (r'^apps/', include('apps.urls')),
)
