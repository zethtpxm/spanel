"""
URL configuration for spanel project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
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
from django.urls import path
from django.shortcuts import redirect
from . import views

# Add a root URL view function that redirects to signIn
def redirect_to_signin(request):
    return redirect('signIn')

urlpatterns = [
    # Root URL will now redirect to signIn
    path('', redirect_to_signin, name='home'),

    path('admin/', admin.site.urls),
    path('signIn/', views.signIn, name='signIn'),
    path('welcome/', views.welcome, name='welcome'),
    path('logout/', views.logout, name='logout'),
    path('signUp/', views.signUp, name='signUp'),
    path('postSignUp/', views.postSignUp, name='postSignUp'),
    # API endpoints for mobile app
    path('api/login/', views.api_login, name='api_login'),
    path('api/register/', views.api_register, name='api_register')
]