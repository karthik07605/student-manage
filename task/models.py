from django.db import models
from django.contrib.auth.models import User
# Create your models here.
def user_directory_path(instance, filename):

    return f'uploads/user_{instance.user.id}/{filename}'

class Student(models.Model):
    companyname=models.CharField(max_length=30)
    files=models.FileField(upload_to='uploads/')
    user=models.ForeignKey(User,null=True,on_delete=models.CASCADE)
    def __str__(self):
        return self.companyname

class Profile(models.Model):
    USER_TYPES=[
        ('student','Student'),
        ('teacher','Teacher'),
    ]
    user=models.OneToOneField(User,on_delete=models.CASCADE)
    user_type=models.CharField(max_length=10,choices=USER_TYPES,default='student')
    def __str__(self):
        return f"{self.user.username} - {self.user_type}"
    
class Teacher(models.Model):
    user=models.OneToOneField(User,on_delete=models.CASCADE)
    
    def __str__(self):
        return self.user.username
