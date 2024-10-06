from rest_framework import serializers
from .models import CustomUser, PageMaster, Post

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'cedula', 'email', 'phone_number', 'full_name']
        extra_kwargs = {
            'cedula': {'required': True},
            'email': {'required': True},
            'phone_number': {'required': True}
        }

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, write_only=True)


# pageMaster

class PageMasterSerializer(serializers.ModelSerializer):
    class Meta:
        model = PageMaster
        fields = ['id', 'username', 'full_name']  
        extra_kwargs = {
            'username': {'required': True},
            'full_name': {'required': False},
        }

class PageMasterPasswordResetSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)  

class PageMasterPasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, write_only=True)

class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = ['id', 'title', 'description', 'image', 'author']