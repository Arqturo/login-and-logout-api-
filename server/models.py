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

    def save(self, *args, **kwargs):
        if not self.email:
            raise ValueError("Email is required.")
        super().save(*args, **kwargs)

    def __str__(self):
        return self.cedula or self.username 
