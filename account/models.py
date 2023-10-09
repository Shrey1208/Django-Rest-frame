from django.db import models
from django.contrib.auth.models import User


# Create your models here.
class user_details(models.Model):
    # username = models.CharField(max_length=50)
    FirstName = models.CharField(max_length=30)
    LastName = models.CharField(max_length=30)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=120)
    # User = models.CharField(max_length=100,default='')
    # is_active = models.BooleanField(default=True)
    # favorite_items = models.ManyToManyField('Item', blank=True)

class Item(models.Model):
    name = models.CharField(max_length=100)
    price = models.IntegerField()
    image = models.CharField( max_length=50)
    description = models.TextField()
    is_archived = models.BooleanField(default=False)


    def __str__(self):
        return self.name

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE) 
