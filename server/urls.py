"""
URL configuration for server project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, re_path
from . import views

from django.contrib import admin
from django.urls import path, include
from . import views

# Create a router and register the PostViewSet

urlpatterns = [
    path("admin/", admin.site.urls),
    
    path("login/", views.login, name='login'),
    path("register/", views.register, name='register'),
    path("profile/", views.profile, name='profile'),

    path("password_reset/", views.password_reset, name='password_reset'),
    path("password_reset_confirm/", views.password_reset_confirm, name='password_reset_confirm'),

    path("inscripcion/", views.upload_files, name='upload_files'),
    path("descarga/", views.download_docx, name='download_docx'),

    path('pagemaster/login/', views.pagemaster_login, name='pagemaster_login'),
    
    path('post/', views.post_list, name='post_list'),  # Changed to point to post_list
    path('post/create/', views.post_create, name='post_create'),  # New endpoint for creating a post
    path('post/<int:post_id>/', views.post_detail, name='post_detail'),

]
