from django.conf.urls.defaults import patterns

from . import views

urlpatterns = patterns('',
    (r'^authorize/$', views.ClientAuthorizationView.as_view()),
    (r'^token/$', views.TokenView.as_view()),
)
