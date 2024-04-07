# users/serializers.py
from rest_framework import serializers
from django.contrib.auth.hashers import check_password
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'password']
        extra_kwargs = {'password': {'write_only': True}}

class SigninSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class GoogleSignupSerializer(serializers.Serializer):
    token = serializers.CharField()

class FacebookSignupSerializer(serializers.Serializer):
    token = serializers.CharField()

class GoogleSigninSerializer(serializers.Serializer):
    token = serializers.CharField()

class FacebookSigninSerializer(serializers.Serializer):
    token = serializers.CharField()
    
class PasswordChangeSerializer(serializers.Serializer):
    email = serializers.EmailField()
    current_password = serializers.CharField()
    new_password = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError("User with this email does not exist")

        user = User.objects.get(email=email)

        if not check_password(current_password, user.password):
            raise serializers.ValidationError("Current password is incorrect")

        if current_password == new_password:
            raise serializers.ValidationError("New password cannot be the same as the current password")

        return data