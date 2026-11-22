from django.contrib.auth import authenticate
from rest_framework import serializers

from user_auth_app.models import User


class RegistrationSerializer(serializers.ModelSerializer):
    """Validate registration data and create a new user."""

    password = serializers.CharField(write_only=True)
    confirmed_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "confirmed_password"]

        extra_kwargs = {
            "email": {"required": True, "allow_blank": False},
        }

    def validate_email(self, value):
        """Ensure the email is not already used (case insensitive)."""
        email = value.strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise serializers.ValidationError("Email already exists")
        return email

    def validate(self, data):
        """Ensure that password and confirmed_password match."""

        if data["password"] != data["confirmed_password"]:
            raise serializers.ValidationError(
                {"confirmed_password": "Passwords do not match"}
            )

        return data

    def create(self, validated_data):
        """Create the user with a hashed password."""

        validated_data.pop("confirmed_password")
        user_email = validated_data.pop("email")
        user = User.objects.create_user(
            username=user_email, email=user_email, is_active=False, **validated_data
        )

        return user


class UserLoginSerializer(serializers.Serializer):
    """Validate login credentials."""

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        """Authenticate the user and add it to the validated data as "user"."""
        email = data.get("email").lower()
        password = data.get("password")
        user = authenticate(username=email, password=password)

        if user is None:
            raise serializers.ValidationError("Invalid email or password")

        data["user"] = user
        return data
