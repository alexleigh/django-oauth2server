from django.conf.urls.defaults import patterns

from . import views
from . import api

urlpatterns = patterns('',
    (r'^$', views.index),
    (r'^apps/$', views.apps),
    
    (r'^login/?$', views.login),
    (r'^logout/?$', views.logout),
    (r'^signup/?$', views.signup),
    
    (r'^date_joined/?$', api.date_joined),
    (r'^last_login/?$', api.last_login),
    (r'^email/?$', api.email)
)
