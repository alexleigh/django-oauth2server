from django.conf.urls.defaults import patterns

from . import views, constants

urlpatterns = patterns('',
    (r'^missing_redirect_uri/$', views.missing_redirect_uri),
    (r'^authorize/$', views.ClientAuthorizationView.as_view(authentication_method=constants.MAC)),
    (r'^token/$', views.TokenView.as_view()),
)
