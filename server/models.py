from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.core.validators import RegexValidator
from django.conf import settings
from rest_framework.authtoken.models import Token as DefaultToken



class CustomUser(AbstractUser):
    cedula = models.CharField(
        max_length=15,
        unique=True,
        null=True,  
        validators=[RegexValidator(regex='^[0-9]*$', message='Cedula must be numeric')]
    )
    phone_number = models.CharField(
        max_length=15,
        unique=False,
        null=True  
    )
    email = models.EmailField(unique=True)
    
    full_name = models.CharField(max_length=255, blank=True, null=False)


    def save(self, *args, **kwargs):
        if not self.email:
            raise ValueError("Email is required.")
        if not self.username:  # Set username to cedula if not provided
            self.username = self.cedula
        super().save(*args, **kwargs)

    def __str__(self):
        return self.cedula or self.username

 # Caja

class UserCaja(models.Model):
    CE_TRABAJADOR = models.CharField(max_length=100)
    CO_UBICACION = models.CharField(max_length=100)
    TIPOPERSONAL = models.CharField(max_length=100)
    EMAIL = models.EmailField(max_length=255)
    TELEFONOS = models.CharField(max_length=50)
    CTABANCO = models.CharField(max_length=50)
    DESCRIPCION = models.TextField(blank=True)

    def __str__(self):
        return self.CE_TRABAJADOR
    
class PageMaster(AbstractUser):
    full_name = models.CharField(max_length=255, blank=True, null=False)

    # Set unique related names to avoid clashes
    groups = models.ManyToManyField(
        Group,
        related_name='pagemaster_set',  
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='pagemaster_permissions_set',  
        blank=True,
    )

    def save(self, *args, **kwargs):
        if not self.username:
            raise ValueError("Username is required.")
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username
    

class CustomToken(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, related_name='custom_auth_token', on_delete=models.CASCADE)
    key = models.CharField(max_length=40, primary_key=True)
    created = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()  # Implement this method to generate a token
        super().save(*args, **kwargs)

    @staticmethod
    def generate_key():
        import binascii
        import os
        return binascii.hexlify(os.urandom(20)).decode()
