from rest_framework import serializers
from .models import CustomUser, PageMaster, Post,InnerPrestamo,FileUpload  
from rest_framework import serializers
from django.utils import timezone

class InnerPrestamoSerializer(serializers.ModelSerializer):
    class Meta:
        model = InnerPrestamo
        fields = ['id', 'name', 'description', 'enable']  # Include the fields you want to expose in the API

class CustomUserSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'cedula', 'email', 'phone_number', 'full_name', 'birth_date', 'room_address', 'roles']  # Added birth_date and room_address
        extra_kwargs = {
            'cedula': {'required': True},
            'email': {'required': True},
            'phone_number': {'required': True},
            'birth_date': {'required': True},
            'room_address': {'required': False},
        }

    def get_roles(self, obj):
        roles = []
        if obj.groups.exists():
            roles.extend([group.name for group in obj.groups.all()])
        if obj.has_perm('server.add_post'):
            roles.append('PageMaster') 
        return roles

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, write_only=True)


# PageMaster

class PageMasterSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()

    class Meta:
        model = PageMaster
        fields = ['id', 'username', 'full_name', 'roles']
        extra_kwargs = {
            'username': {'required': True},
            'full_name': {'required': False},
        }

    def get_roles(self, obj):
        roles = []
        # Check if PageMaster is in any groups
        if obj.groups.exists():
            roles.extend([group.name for group in obj.groups.all()])
        # Add specific permissions checks if needed
        if obj.has_perm('server.add_post'):
            roles.append('PageMaster')  # Adjust based on your permission logic
        return roles


class PageMasterPasswordResetSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)  

class PageMasterPasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, write_only=True)




class PostSerializer(serializers.ModelSerializer):
    created_at = serializers.DateTimeField(format="%d/%m/%Y", read_only=True)
    updated_at = serializers.DateTimeField(format="%d/%m/%Y", read_only=True)

    class Meta:
        model = Post
        fields = ['id', 'title', 'description', 'content', 'image', 'author', 'created_at', 'updated_at']  # Added 'content'

    def create(self, validated_data):
        # Set created_at and updated_at to the current date and time
        validated_data['created_at'] = timezone.now()
        validated_data['updated_at'] = timezone.now()
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Update only the updated_at timestamp on update
        validated_data['updated_at'] = timezone.now()
        return super().update(instance, validated_data)

class FileUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileUpload
        fields = ['id', 'serial', 'directory']  # Add any other fields you want to expose

class FileUploadSerializer(serializers.ModelSerializer):
    # This method will clean the directory value before returning it in the serialized data
    directory = serializers.SerializerMethodField()

    class Meta:
        model = FileUpload
        fields = ['id', 'serial', 'directory']  # Add any other fields you want to expose

    def get_directory(self, obj):
        # Clean the directory to remove any extra slashes
        return obj.clean_directory()  # Assuming clean_directory method is in your model