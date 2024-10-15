from rest_framework import serializers
from .models import CustomUser, PageMaster, Post

class CustomUserSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'cedula', 'email', 'phone_number', 'full_name', 'roles']
        extra_kwargs = {
            'cedula': {'required': True},
            'email': {'required': True},
            'phone_number': {'required': True}
        }

    def get_roles(self, obj):
        roles = []
        # Check if user is in any groups
        if obj.groups.exists():
            roles.extend([group.name for group in obj.groups.all()])
        # You can also check specific permissions here if needed
        if obj.has_perm('server.add_post'):
            roles.append('PageMaster')  # Adjust based on your permission logic
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
    class Meta:
        model = Post
        fields = ['id', 'title', 'description', 'image', 'author', 'created_at', 'updated_at']

