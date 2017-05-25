from django.conf.urls import url

from . import views

from django.conf import settings


urlpatterns = [
    url(r'^ajax_get', views.ajax_get),
    url(r'^trace_form', views.trace_form),
    url(r'', views.index),
]
