from .views import *

from django.urls import path
from . import views


urlpatterns = [
    path('', views.home, name='home'),
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('dash/(?P<user>.*)/$', views.dash, name='dash'),

     ]