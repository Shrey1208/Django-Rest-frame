from rest_framework import serializers
from .models import *
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = user_details

        # fields = ['name' , 'age']  ## wich we wanna need
        # exclude = ['id']          ## wich we want to skip
        fields = '__all__'         ## that will take all record's from Db...

    def validate(self, data):
        if '@' not in data['email']:
            raise serializers.ValidationError({'error' : "Invalid Email"})

        if data['FirstName']:
            for n in data['FirstName']:
                if n.isdigit():
                    raise serializers.ValidationError({'error' : "FirstName can not be digit.."})

        if data['LastName']:
            for n in data['LastName']:
                if n.isdigit():
                    raise serializers.ValidationError({'error' : "LirstName can not be digit.."})
        return data


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = user_details
        fields = '__all__'

class ChangePasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

class UpdaePasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = user_details
        fields = ['password'] 

class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class ItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = Item
        fields = '__all__'

class AdminProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # fields = ('id', 'username', 'email', 'first_name', 'last_name')
        fields = '__all__'

class AdminLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

class AdminChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()