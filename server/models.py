from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.core.validators import RegexValidator
from django.conf import settings
from rest_framework.authtoken.models import Token as DefaultToken
from django.contrib.auth import get_user_model
from django.utils import timezone
import os
import uuid
from django.core.exceptions import ValidationError

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
    
    # Birth date is now mandatory and defaults to today
    birth_date = models.DateField(default=timezone.now)  # Use today's date as default
    
    # Room address is optional, but with a larger max length
    room_address = models.CharField(max_length=500, null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.email:
            raise ValueError("Email is required.")
        if not self.username:  # Set username to cedula if not provided
            self.username = self.cedula
        super().save(*args, **kwargs)

    def __str__(self):
        return self.cedula or self.username

    def get_roles(self):
        roles = []
        # Check if user is in any groups
        if self.groups.exists():
            roles.extend([group.name for group in self.groups.all()])
        # Optionally check for specific permissions and add corresponding roles
        if self.has_perm('server.add_customuser'):
            roles.append('CustomUser')
        return roles
    
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


class Post(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()  
    content = models.TextField()
    image = models.TextField() 
    author = models.CharField(max_length=255)  
    created_at = models.DateTimeField(auto_now_add=True)  
    updated_at = models.DateTimeField(auto_now=True) 


class InnerPrestamo(models.Model):
    prestamo_id = models.IntegerField(unique=True)  # Renamed field, representing 'CODPTMO'
    name = models.CharField(max_length=255)  # 'name' will store 'DESCRIP' from SQL
    description = models.TextField(blank=True)
    enable = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class FileUpload(models.Model):
    # Unique serial for the file upload record
    serial = models.CharField(max_length=255, unique=True)
    # Directory where files will be saved
    directory = models.CharField(max_length=255, unique=True)

    def save(self, *args, **kwargs):
        # If no serial is provided, generate a unique one
        if not self.serial:
            self.serial = uuid.uuid4().hex  # Generate a unique serial if not set
        
        # If no directory is provided, generate one using the serial
        if not self.directory:
            self.directory = os.path.join('uploads', self.serial)
        
        # Save the model instance
        super(FileUpload, self).save(*args, **kwargs)

    def create_files(self, files):
        # Ensure the total size of the files does not exceed 50MB
        total_size = sum(file.size for file in files)
        if total_size > 50 * 1024 * 1024:  # 50MB
            raise ValidationError("Total file size exceeds 50MB.")

        # Create a unique directory to store the files in MEDIA_ROOT
        upload_dir = os.path.join(settings.MEDIA_ROOT, self.directory)
        os.makedirs(upload_dir, exist_ok=True)  # Create the directory if it doesn't exist

        # Iterate through the files and save each one
        for file in files:
            # Generate the full file path
            file_path = os.path.join(upload_dir, file.name)
            # Save the file to the disk
            with open(file_path, 'wb') as f:
                for chunk in file.chunks():
                    f.write(chunk)

        return self

    def clean_directory(self):
        # Ensure no double slashes in the directory path
        self.directory = self.directory.replace("\\", "/")  # Replace backslashes with forward slashes
        return self.directory