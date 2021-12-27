from django.db import models

# Create your models here.
from django.utils import timezone as tz
from django.db import migrations
class UserTable(models.Model):
    id = models.AutoField(primary_key=True)
    firstName = models.CharField(max_length=200)
    lastName = models.CharField(max_length=200)
    contactNumber = models.CharField(max_length=200)
    email = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    isActive = models.IntegerField(default=True)
    createdOn = models.DateTimeField(default=tz.now)
    userType = models.IntegerField(default=0)
    class Meta:
        db_table = "userTable"
        
class UserOtp(models.Model):
    id = models.AutoField(primary_key=True)
    email = models.CharField(max_length=200)
    otp = models.CharField(max_length=200)
    isActive = models.BooleanField(default=True)
    createdOn = models.DateTimeField(default=tz.now)
    class Meta:
        db_table = "userOtp"

class UserTokens(models.Model):
    id = models.AutoField(primary_key=True)
    userId = models.CharField(max_length=500)
    accessToken = models.CharField(max_length=500)
    isActive = models.IntegerField()
    createdOn = models.DateTimeField(default=tz.now)
    class Meta:
        db_table = "userTokens"
