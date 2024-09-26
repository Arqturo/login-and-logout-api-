from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import RegexValidator

class CustomUser(AbstractUser):
    cedula = models.CharField(
        max_length=15,
        unique=True,
        null=True,  
        validators=[RegexValidator(regex='^[0-9]*$', message='Cedula must be numeric')]
    )
    phone_number = models.CharField(
        max_length=15,
        unique=True,
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