from django.contrib import admin
from django.urls import path
from security import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.home, name='home'),  

    path('check-ip/', views.check_ip, name='check_ip'),
    path('check-hash/', views.check_hash, name='check_hash'),
    path('check-domain/', views.check_domain, name='check_domain'),


]
