"""FileSystem URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
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
from django.conf.urls import url
from django.conf import settings
from django.urls import path
from files.views import SignUp, Logout, Login, VerifyEmail, UploadFile, ListDirectory, DownloadFile

from django.contrib import admin
from django.conf.urls import *
urlpatterns = [
    path('admin/', admin.site.urls),
    url('signup/', SignUp.as_view()),
    url('login/', Login.as_view()),
    url('logout/', Logout.as_view()),
    url('verifyEmail/', VerifyEmail.as_view()),
    url('uploadFile/', UploadFile.as_view()),
    url('listDir/', ListDirectory.as_view()),
    url('downloadFile/', DownloadFile.as_view()),
    
    
]
