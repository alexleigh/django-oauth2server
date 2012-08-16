from django.conf.urls.defaults import patterns

from . import views

urlpatterns = patterns('',
    (r'^$', views.index),
    (r'^(?P<app_name>\w+)/$', views.app),
)
