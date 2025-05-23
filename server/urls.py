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
    path('user/loans/', views.user_loans, name='user_loans'),
    path('user/haberes/', views.haberes, name='haberes'),
    path('user/dividendos/', views.dividendos, name='dividendos'),
    path('user/solicitudes/', views.solicitudes, name='solicitudes'),
    path('user/create_loan_request/', views.create_loan_request, name='loadRequest'),
    path('user/verify_loan/', views.verify_loan, name='verify_loan'),
    path('user/get_loan_options/', views.get_loan_options, name='get_loan_options'),
     path('user/loan_preset/', views.loan_preset, name='loan_preset'),

    path('user/fianzas/', views.fianza, name='fianza'),
    path('profile/edit/', views.update_own_profile, name='update_own_profile'),


    path("password_reset/", views.password_reset, name='password_reset'),
    path("password_reset_confirm/", views.password_reset_confirm, name='password_reset_confirm'),

    path("inscripcion/", views.upload_files, name='upload_files'),
    path("descarga/", views.download_docx, name='download_docx'),

    path('pagemaster/login/', views.pagemaster_login, name='pagemaster_login'),
    path('pagemaster/search-custom-users/', views.search_custom_users, name='search_custom_users'),
    path('pagemaster/update-custom-user/<int:custom_user_id>/', views.update_custom_user, name='update_custom_user'),
    path('pagemaster/import-users/', views.import_users_from_excel, name='import_users_from_excel'),
    path('pagemaster/import_prestamos/', views.import_prestamos, name='import_prestamos'),
    path('pagemaster/search_inner_prestamos/', views.search_inner_prestamos, name='search_inner_prestamos'),
    path('pagemaster/update_inner_prestamo/', views.update_inner_prestamo, name='update_inner_prestamo'),
    path('pagemaster/file_upload/', views.upload_files, name='upload_files'),
    path('pagemaster/search_file_uploads/', views.search_file_uploads, name='search_file_uploads'),
    path('pagemaster/delete_file_upload/<str:serial>/', views.delete_file_upload, name='delete_file_upload'),



    
    path('post/', views.post_list, name='post_list'),
    path('post/create/', views.post_create, name='post_create'),  
    path('post/<int:post_id>/', views.post_detail_get, name='post_detail_get'),  # GET without authentication
    path('post/<int:post_id>/modify/', views.post_detail_modify, name='post_detail_modify'),  # PUT, PATCH, DELETE with authentication
    
    path('ping/', views.ping, name='ping')

]
