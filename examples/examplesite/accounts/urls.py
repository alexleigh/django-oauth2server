from django.conf.urls.defaults import patterns

from . import views
from . import api

urlpatterns = patterns('',
    (r'^$', views.index),
    
    (r'^login/$', views.login),
    (r'^logout/$', views.logout),
    (r'^signup/$', views.signup),
    
    (r'^email/(\d+)/$', api.email),
    (r'^date_joined/(\d+)/$', api.date_joined),
    (r'^last_login/(\d+)/$', api.last_login)
)
