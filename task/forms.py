from django import forms
from django.forms import ModelForm
from .models import *
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
class Taskform(forms.ModelForm):
    class Meta:
        model=Student
        fields=['companyname','files']
class Createuserform(UserCreationForm):
    class Meta:
        model=User
        fields=['username','email','password1','password2']
    