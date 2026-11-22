from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import DjangoUnicodeDecodeError, force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from user_auth_app.models import User
from user_auth_app.signals import pre_password_reset

from .serializers import RegistrationSerializer, UserLoginSerializer


class RegistrationView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        """Create the user and return a message.

        Returns 400 with the validation errors if the registration fails.
        """
        serializer = RegistrationSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"detail": "User created successfully!"}, status=status.HTTP_201_CREATED
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """Log in a user and return and set auth token cookies."""

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        """Validate the credentials and return user data and set auth cookies.

        Returns 401 with the validation errors if the login fails.
        """

        serializer = UserLoginSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data["user"]
            refresh = RefreshToken.for_user(user)
            user = {
                "id": user.id,
                "username": user.email,
            }
            response = Response({"detail": "Login successful", "user": user})

            response.set_cookie(
                key="access_token",
                value=str(refresh.access_token),
                httponly=True,
                secure=True,
                samesite="Lax",
            )

            response.set_cookie(
                key="refresh_token",
                value=str(refresh),
                httponly=True,
                secure=True,
                samesite="Lax",
            )

            return response

        return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Blacklist the refresh token and delete the auth cookies.

        Args:
            request: The incoming request containing the auth cookies.

        Returns:
            Response: 200 with a success message, or 401 if no refresh token
            cookie is set.
        """
        refresh_token = request.COOKIES.get("refresh_token")
        if refresh_token is None:
            return Response(
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()

        except TokenError:
            pass

        response = Response(
            {
                "detail": "Logout successful! All Tokens will be deleted. Refresh token is now invalid."
            },
            status=status.HTTP_200_OK,
        )

        response.delete_cookie(
            key="refresh_token",
            samesite="Lax",
        )

        response.delete_cookie(
            key="access_token",
            samesite="Lax",
        )

        return response


class CookieTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        """Create a new access token from the refresh token cookie.

        Args:
            request: The incoming request containing the refresh token cookie.

        Returns:
            Response: 200 and sets a new "access_token" cookie, or 401 if the
            refresh token is missing or invalid.
        """
        refresh_token = request.COOKIES.get("refresh_token")
        if refresh_token is None:
            return Response(
                status=status.HTTP_401_UNAUTHORIZED,
            )

        serializer = self.get_serializer(data={"refresh": refresh_token})

        try:
            serializer.is_valid(raise_exception=True)

        except TokenError:
            return Response(
                status=status.HTTP_401_UNAUTHORIZED,
            )

        access_token = serializer.validated_data.get("access")
        response = Response({"detail": "Token refreshed"})
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=True,
            samesite="Lax",
        )

        return response


class ActivateUserView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request, uidb64, token):

        try:
            decoded_id = urlsafe_base64_decode(uidb64)
            userid = force_str(decoded_id)
            user = User.objects.get(id=userid)
        except (ValueError, DjangoUnicodeDecodeError, User.DoesNotExist):
            return Response(status=status.HTTP_400_BAD_REQUEST)

        if default_token_generator.check_token(user, token) is False:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        if user.is_active:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        user.is_active = True
        user.save(update_fields=["is_active"])
        return Response(
            {"message": "Account successfully activated."}, status=status.HTTP_200_OK
        )


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        raw_email = request.data.get("email")
        if raw_email is None:
            return Response(
                {"detail": "An email has been sent to reset your password."},
                status=status.HTTP_200_OK,
            )
        try:
            email = raw_email.lower()
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"detail": "An email has been sent to reset your password."},
                status=status.HTTP_200_OK,
            )

        pre_password_reset.send(User, instance=user)
        return Response(
            {"detail": "An email has been sent to reset your password."},
            status=status.HTTP_200_OK,
        )


class ConfirmPasswordView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, uidb64, token):
        password = request.data.get("new_password")
        confirm_password = request.data.get("confirm_password")

        try:
            decoded_id = urlsafe_base64_decode(uidb64)
            userid = force_str(decoded_id)
            user = User.objects.get(id=userid)
        except (ValueError, DjangoUnicodeDecodeError, User.DoesNotExist):
            return Response(
                {"detail": "Your Password has been successfully reset."},
                status=status.HTTP_200_OK,
            )

        if (
            not user.is_active
            or not password
            or not confirm_password
            or password != confirm_password
            or not default_token_generator.check_token(user, token)
        ):
            return Response(
                {"detail": "Your Password has been successfully reset."},
                status=status.HTTP_200_OK,
            )
        user.set_password(password)
        user.save(update_fields=["password"])
        return Response(
            {"detail": "Your Password has been successfully reset."},
            status=status.HTTP_200_OK,
        )
