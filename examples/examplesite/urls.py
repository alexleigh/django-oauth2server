from django.conf.urls.defaults import patterns, include
from django.views.generic import RedirectView

urlpatterns = patterns('',
    (r'^$', RedirectView.as_view(url='/apps/')),
    (r'^oauth2/', include('oauth2.urls')),
    (r'^accounts/', include('accounts.urls')),
    (r'^apps/', include('apps.urls')),
)
