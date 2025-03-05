from django.contrib import admin
from django.urls import path
from .views import *

urlpatterns = [
    path("", home, name='home'),
    path("studentlogin/", studentlogin, name="studentlogin"),
    path("facultylogin/", facultylogin, name="facultylogin"),
    path("studentpage/", studentpage, name="studentpage"),
    path("facultypage/", facultypage, name="facultypage"),
    path("logout/", logoutpage, name="logoutpage"),
    path("deletefile/<int:file_id>/", deletefile, name="deletefile"),
    path("addstudent/", addstudent, name="addstudent"),
    
    # Password Reset URLs
    path('reset_password/', password_reset_request, name="reset_password"),
    path('reset_password_confirm/<uidb64>/<token>/', password_reset_confirm, name="password_reset_confirm"),
    path('password-reset/', password_reset_request, name='password_reset_request'),
]
