from rest_framework import serializers
from .models import CustomUser

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'cedula', 'email', 'phone_number']
        extra_kwargs = {
            'cedula': {'required': True},
            'email': {'required': True},
            'phone_number': {'required': True}
        }
