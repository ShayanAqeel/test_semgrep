from django.urls import path
from . import views
import debug_toolbar
from django.conf import settings
from django.contrib import admin
from django.urls import path, include

import blog.views

import blog
urlpatterns = [
    path('', views.index),
    path("ip/", blog.views.get_ip),
    path("post/<slug>/", views.post_detail, name="blog-post-detail"),
]
if settings.DEBUG:
    urlpatterns += [
        path("__debug__/", include(debug_toolbar.urls)),
    ]
