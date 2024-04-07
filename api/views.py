from google.oauth2 import id_token
from google.auth.transport import requests
from decouple import config
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.contrib.auth import authenticate
from drf_yasg.utils import swagger_auto_schema
from .serializers import GoogleSigninSerializer, GoogleSignupSerializer, PasswordChangeSerializer, SigninSerializer, UserSerializer, FacebookSignupSerializer, FacebookSigninSerializer
from django.contrib.auth.hashers import make_password
from rest_framework.permissions import IsAuthenticated
from allauth.socialaccount.models import SocialAccount
from django.db import IntegrityError
from django.contrib.auth import get_user_model

User = get_user_model()

class Signup(APIView):
    @swagger_auto_schema(request_body=UserSerializer)
    def post(self, request):
        request.data['password'] = make_password(request.data['password'])

        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token, _ = Token.objects.get_or_create(user=user)
            return Response({'token': token.key}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Signin(APIView):
    @swagger_auto_schema(request_body=SigninSerializer)
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)
        if user:
            token, _ = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

class Signout(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_200_OK, data={'message': 'User signed out successfully'})

class GoogleSignup(APIView):
    @swagger_auto_schema(request_body=GoogleSignupSerializer)
    def post(self, request, *args, **kwargs):
        token = request.data.get('token')
        CLIENT_ID = config("GOOGLE_CLIENT_ID")

        if not token:
            return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)
            userid = idinfo['sub'] 
            email = idinfo['email']
            user = User.objects.filter(email=email).first()
            if user:
                try:
                    SocialAccount.objects.create(user=user, provider='google', uid=userid)
                    return Response({'message': 'Google account linked successfully'}, status=status.HTTP_200_OK)
                except IntegrityError:
                    return Response({'error': 'This Google account is already linked to another user'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                user = User.objects.create(email=email)
                SocialAccount.objects.create(user=user, provider='google', uid=userid)
                return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)

        except ValueError:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        
class GoogleSignin(APIView):
    @swagger_auto_schema(request_body=GoogleSigninSerializer)
    def post(self, request, *args, **kwargs):
        token = request.data.get('token')
        CLIENT_ID = config("GOOGLE_CLIENT_ID")

        if not token:
            return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)
            email = idinfo['email']
            user = User.objects.filter(email=email).first()
            if user:
                token, _ = Token.objects.get_or_create(user=user)
                return Response({'token': token.key})
            else:
                return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        except ValueError:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        
class FacebookSignup(APIView):
    @swagger_auto_schema(request_body=FacebookSignupSerializer)
    def post(self, request, *args, **kwargs):
        token = request.data.get('token')
        FACEBOOK_CLIENT_ID = config("FACEBOOK_CLIENT_ID")
        FACEBOOK_CLIENT_SECRET = config("FACEBOOK_CLIENT_SECRET")

        if not token:
            return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            resp = requests.get(
                'https://graph.facebook.com/me',
                params={'access_token': token, 'fields': 'id,name,email',
                        'client_id': FACEBOOK_CLIENT_ID, 'client_secret': FACEBOOK_CLIENT_SECRET}
            )
            resp.raise_for_status()
            data = resp.json()

            userid = data.get('id')
            email = data.get('email')
            if not email:
                return Response({'error': 'Email not provided by Facebook'}, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.filter(email=email).first()
            if user:
                try:
                    SocialAccount.objects.create(user=user, provider='facebook', uid=userid)
                    return Response({'message': 'Facebook account linked successfully'}, status=status.HTTP_200_OK)
                except IntegrityError:
                    return Response({'error': 'This Facebook account is already linked to another user'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                user = User.objects.create(email=email)
                SocialAccount.objects.create(user=user, provider='facebook', uid=userid)
                return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)

        except requests.exceptions.HTTPError:
            return Response({'error': 'Error communicating with Facebook'}, status=status.HTTP_400_BAD_REQUEST)

class FacebookSignin(APIView):
    @swagger_auto_schema(request_body=FacebookSigninSerializer)
    def post(self, request, *args, **kwargs):
        token = request.data.get('token')
        FACEBOOK_APP_ID = config("FACEBOOK_APP_ID")
        FACEBOOK_APP_SECRET = config("FACEBOOK_APP_SECRET")

        if not token:
            return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            resp = requests.get(
                'https://graph.facebook.com/me',
                params={'access_token': token, 'fields': 'id,name,email',
                        'client_id': FACEBOOK_APP_ID, 'client_secret': FACEBOOK_APP_SECRET}
            )
            resp.raise_for_status()
            data = resp.json()

            email = data.get('email')
            if not email:
                return Response({'error': 'Email not provided by Facebook'}, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.filter(email=email).first()
            if user:
                token, _ = Token.objects.get_or_create(user=user)
                return Response({'token': token.key})
            else:
                return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        except requests.exceptions.HTTPError:
            return Response({'error': 'Error communicating with Facebook'}, status=status.HTTP_400_BAD_REQUEST)
        
class PasswordChange(APIView):
    @swagger_auto_schema(request_body=PasswordChangeSerializer)
    def post(self, request, *args, **kwargs):
        serializer = PasswordChangeSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            new_password = serializer.validated_data['new_password']
            user = User.objects.get(email=email)
            user.password = make_password(new_password)
            user.save()
            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)