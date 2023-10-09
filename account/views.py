from django.shortcuts import render
from rest_framework import decorators
from rest_framework.decorators import api_view,permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework import status,viewsets
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken,api_settings

from django.db.models import Q
from django.contrib.auth.hashers import make_password, check_password
from django.conf import settings
from django.core.mail import EmailMessage

from django.core.mail import send_mail
from .models import *
from .serializers import *
import datetime
import jwt

# Create your views here.
class CustomTokenObtainPairView(TokenObtainPairView):
   
    pass

class UserRegisterViewAPIView(APIView):
    def post(self, request):
        # username = request.data.get('Username')
        FirstName = request.data.get('FirstName', '')
        LastName = request.data.get('LastName', '')
        email = request.data.get('email')
        password =request.data.get('password')

        # if not username:
        #     return Response({'status': 400, 'message': 'Username field is required.'}, status=400)
        if not email:
            return Response({'status': 400, 'message': 'Email field is required.'}, status=400)
        if not password:
            return Response({'status': 400, 'message': 'Password field is required.'}, status=400)
        
        email = user_details.objects.filter(email=email).first()
        if email:
            if email == email:
                return Response({'status': 400, 'message': 'Users with this Email is already exist.'}, status=400)


        serializer = UserSerializer(data=request.data , partial= True)
        if not serializer.is_valid():
            # serializer = UserSerializer(data= request.data)
            return Response({'status': 403,'error':serializer.errors, 'message':'Somthing Went wrong please check again.....'})
        else:
            serializer.save()
            print(request.data)
            return Response({'status': 200, 'message':'Rigistertion succesful.'}) 
        return Response(serializer.errors, status=status.HTTP_200_OK)




class LoginView(APIView):
    def post(self, request):
        authentication_classes= [ JWTAuthentication ]
        permission_classes = [IsAuthenticated]
        email = request.data.get('email')
        password = request.data.get('password')
        Email = user_details.objects.filter(email = email).exists()

        try:
            if Email:
                user = user_details.objects.get(email=email)
                passs = user.password
                if password == passs:
                    try:
                        token_obj , _ = Token.objects.get_or_create(user=user)
                        print(token_obj)
                    except Exception as e:
                        token_obj = ''
                        print(e)

                    abc =  UserProfileSerializer(user,data=request.data , partial= True)
                    if abc.is_valid():
                        return Response({'data': abc.data,'message': 'Login successful!'}, status=status.HTTP_200_OK)
                    else:
                        print("somthing went wrong//")
                else:
                    return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                print("Invalid Email...")
        except user_details.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            user = request.user
            print(user)
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']
            print(old_password)
            passs = user.password
            print(passs)
            if user is not None and user.check_password(old_password):
                user.set_password(new_password)
                user.save()
                return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid old password.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



from django.core.mail import send_mail
from django.conf import settings
class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email', '')
        try:
            user = user_details.objects.get(email=email)
        except user_details.DoesNotExist:
            return Response({'message': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)
        payload = {
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expiration time
        }
        reset_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
        email_subject = 'Password Reset Request'
        email_body = f'Click the following link to reset your password: {settings.FRONTEND_URL}/reset_password/{reset_token}/'
        print(reset_token)
        email = EmailMessage(
                email_subject,
                email_body,
                settings.EMAIL_HOST_USER,
                [user.email],
            )
        email.content_subtype = "html"
        email.send(fail_silently=False)
        return Response({'message': 'Password reset email sent successfully.'}, status=status.HTTP_200_OK)



class ResetPasswordView(APIView):
    def post(self, request, reset_token):
        email = request.data.get('email', '')
        new_password = request.data.get('new_password')
        print(new_password,'jnfdsj')
        try:
            payload = jwt.decode(reset_token, settings.SECRET_KEY, algorithms=['HS256'])
            email = payload['email']
            user = user_details.objects.get(email=email)

            Email = user_details.objects.filter(email = email).exists()
            print(Email)
            if Email:
                print("hey")
                User = user_details.objects.get(email = email)
                print(User)
                user_details.objects.filter(email=email).update(password = new_password)

            
            return Response({'message': 'Password reset successfully.'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'message': 'Token has expired.'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError:
            return Response({'message': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)
        except user_details.DoesNotExist:
            return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)


class ChnagePasswordAPIView(APIView):

    def post(self, request):
        email = request.data.get('email')
        old_password = request.data.get('old_password', '')
        new_password = request.data.get('new_password', '')
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            Email = user_details.objects.filter(Q(email=email) & Q(password=old_password)).exists()
            if Email:
                user_details.objects.filter(email=email).update(password = new_password)    
                return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid old password.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ItemViewSet(viewsets.ModelViewSet):
    queryset = Item.objects.filter(is_archived=False) 
    serializer_class = ItemSerializer

    @decorators.action(detail=True, methods=['post'])
    def archive(self, request, pk=None):
        item = self.get_object()
        item.is_archived = True
        item.save()
        return Response({'status': 'Item archived'})

    @decorators.action(detail=True, methods=['post'])
    def unarchive(self, request, pk=None):
        item = self.get_object()
        item.is_archived = False
        item.save()
        return Response({'status': 'Item unarchived'})


from django.contrib.auth import authenticate, login
class AdminLoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            return Response({"message": "admin login sucssfully.", 'user_id': user.id}, status=status.HTTP_200_OK)  ##"""'token': token.key""" 
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)



class AdminTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        try:
            user = User.objects.get(username=username, is_staff=True)
        except User.DoesNotExist:
            return Response({'error': 'Invalid credentials or not an admin.'}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.check_password(password):
            return Response({'error': 'Invalid password.'}, status=status.HTTP_401_UNAUTHORIZED)

        response = super().post(request, *args, **kwargs)
        return response

@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def admin_profile(request):
    user = request.user

    if request.method == 'GET':
        serializer = AdminProfileSerializer(user)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = AdminProfileSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_admin_password(request):
    user = request.user
    serializer = AdminChangePasswordSerializer(data=request.data)

    if serializer.is_valid():
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']

        if not user.check_password(old_password):
            return Response({'error': 'Incorrect old password.'}, status=status.HTTP_400_BAD_REQUEST)

        user.password = make_password(new_password)
        user.save()

        return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def forgot_password(request):
    username_or_email = request.data.get('username_or_email')
    try:
        user = User.objects.get(Q(username=username_or_email) | Q(email=username_or_email))
        print(user)
    except User.DoesNotExist:
        return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    refresh = RefreshToken.for_user(user)
    reset_link = f'{settings.FRONTEND_URL}/reset-password/{refresh.access_token}'  # Replace with your actual reset link
    email_subject = 'Password Reset Request'
    message = f'Click the following link to reset your password: {reset_link}'
    from_email = 'shreyashpathak755@gmail.com' 
    recipient_list = [user.email]
    email = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                [user.email],
            )
    email.content_subtype = "html"
    email.send(fail_silently=False)
    return Response({'message': 'Password reset link sent to your email.'}, status=status.HTTP_200_OK)





