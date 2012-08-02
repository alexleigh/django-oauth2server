from django.conf.urls.defaults import patterns

from . import views

urlpatterns = patterns('',
    (r'^authorize/$', views.authorize),
    (r'^missing_redirect_uri/$', views.missing_redirect_uri),
    (r'^token/$', views.token),
)
