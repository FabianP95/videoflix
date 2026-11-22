from unittest.mock import patch

from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import status
from rest_framework.test import APITestCase

from user_auth_app.models import User

EMAIL = "test@example.com"
PASSWORD = "Secret123!"


class BaseAuthTestCase(APITestCase):
    """Base class that mocks the RQ queue, so no Redis server is needed."""

    def setUp(self):
        """Patch django_rq.enqueue used in the post_save signal."""
        patcher = patch("user_auth_app.signals.django_rq.enqueue")
        self.mock_enqueue = patcher.start()
        self.addCleanup(patcher.stop)

    def create_user(self, email=EMAIL, password=PASSWORD, is_active=True):
        """Create a user the same way the registration does (username = email)."""
        return User.objects.create_user(
            username=email, email=email, password=password, is_active=is_active
        )

    def login(self, email=EMAIL, password=PASSWORD):
        """Log in with the given credentials and return the response."""
        return self.client.post(
            reverse("login"), {"email": email, "password": password}, format="json"
        )


class RegistrationTests(BaseAuthTestCase):
    def setUp(self):
        """Set the registration url and valid registration data."""
        super().setUp()
        self.url = reverse("registration")
        self.valid_data = {
            "email": EMAIL,
            "password": PASSWORD,
            "confirmed_password": PASSWORD,
        }

    def test_register_success(self):
        """Test that a valid registration returns 201 and creates the user."""
        response = self.client.post(self.url, self.valid_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data, {"detail": "User created successfully!"})
        self.assertTrue(User.objects.filter(email=EMAIL).exists())

    def test_username_is_email(self):
        """Test that the email is used as username."""
        self.client.post(self.url, self.valid_data, format="json")
        user = User.objects.get(email=EMAIL)
        self.assertEqual(user.username, EMAIL)

    def test_email_is_lowercased(self):
        """Test that the email is stored in lower case."""
        self.valid_data["email"] = "TEST@Example.com"
        self.client.post(self.url, self.valid_data, format="json")
        self.assertTrue(User.objects.filter(email=EMAIL).exists())

    def test_user_is_inactive_after_registration(self):
        """Test that a new user is inactive until the email is confirmed."""
        self.client.post(self.url, self.valid_data, format="json")
        user = User.objects.get(email=EMAIL)
        self.assertFalse(user.is_active)

    def test_activation_mail_is_enqueued(self):
        """Test that the registration enqueues exactly one activation mail job."""
        self.client.post(self.url, self.valid_data, format="json")
        self.mock_enqueue.assert_called_once()
        args = self.mock_enqueue.call_args.args
        self.assertEqual(args[-1], EMAIL)

    def test_password_is_hashed(self):
        """Test that the password is stored hashed and not in plain text."""
        self.client.post(self.url, self.valid_data, format="json")
        user = User.objects.get(email=EMAIL)
        self.assertNotEqual(user.password, PASSWORD)
        self.assertTrue(user.check_password(PASSWORD))

    def test_register_passwords_do_not_match(self):
        """Test that different passwords return 400 with a confirmed_password error."""
        self.valid_data["confirmed_password"] = "Other123!"
        response = self.client.post(self.url, self.valid_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("confirmed_password", response.data)
        self.assertFalse(User.objects.filter(email=EMAIL).exists())

    def test_register_duplicate_email_case_insensitive(self):
        """Test that an already used email (case insensitive) returns 400."""
        self.create_user(email="TEST@example.com")
        response = self.client.post(self.url, self.valid_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

    def test_register_invalid_email(self):
        """Test that an invalid email format returns 400."""
        self.valid_data["email"] = "no-email"
        response = self.client.post(self.url, self.valid_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

    def test_register_missing_fields(self):
        """Test that a missing required field returns 400."""
        for field in ["email", "password", "confirmed_password"]:
            data = self.valid_data.copy()
            data.pop(field)
            response = self.client.post(self.url, data, format="json")
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, field)
            self.assertIn(field, response.data)

    def test_password_not_in_response(self):
        """Test that the password is not returned in the response."""
        response = self.client.post(self.url, self.valid_data, format="json")
        self.assertNotIn("password", response.data)
        self.assertNotIn("confirmed_password", response.data)


class ActivationTests(BaseAuthTestCase):
    def setUp(self):
        """Create an inactive user and build a valid activation url."""
        super().setUp()
        self.user = self.create_user(is_active=False)
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.token = default_token_generator.make_token(self.user)

    def get_url(self, uidb64=None, token=None):
        """Return the activation url, optionally with other uid or token."""
        return reverse(
            "activate",
            kwargs={"uidb64": uidb64 or self.uidb64, "token": token or self.token},
        )

    def test_activation_success(self):
        """Test that a valid link returns 200 and activates the user."""
        response = self.client.get(self.get_url())
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)

    def test_activation_invalid_token(self):
        """Test that an invalid token returns 400 and the user stays inactive."""
        response = self.client.get(self.get_url(token="invalid-token"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)

    def test_activation_invalid_uid(self):
        """Test that an invalid uid returns 400."""
        response = self.client.get(self.get_url(uidb64="invalid"))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_activation_unknown_user(self):
        """Test that a uid of a not existing user returns 400."""
        unknown_uid = urlsafe_base64_encode(force_bytes(99999))
        response = self.client.get(self.get_url(uidb64=unknown_uid))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_activation_link_only_works_once(self):
        """Test that the token is invalid after the user was activated."""
        self.client.get(self.get_url())
        response = self.client.get(self.get_url())
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class LoginTests(BaseAuthTestCase):
    def setUp(self):
        """Set the login url and create an active test user."""
        super().setUp()
        self.url = reverse("login")
        self.user = self.create_user()

    def test_login_success_sets_cookies(self):
        """Test that a valid login returns the user data and sets httponly auth cookies."""
        response = self.login()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "Login successful")
        self.assertEqual(response.data["user"], {"id": self.user.id, "username": EMAIL})
        for cookie in ["access_token", "refresh_token"]:
            self.assertIn(cookie, response.cookies)
            self.assertTrue(response.cookies[cookie]["httponly"])
            self.assertTrue(response.cookies[cookie]["secure"])
            self.assertEqual(response.cookies[cookie]["samesite"], "Lax")

    def test_login_email_case_insensitive(self):
        """Test that the login works with an upper case email."""
        response = self.login(email="TEST@Example.com")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_tokens_not_in_body(self):
        """Test that the tokens are not returned in the response body."""
        response = self.login()
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)

    def test_login_inactive_user(self):
        """Test that a not activated user can not log in."""
        self.user.is_active = False
        self.user.save()
        response = self.login()
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIn("access_token", response.cookies)

    def test_login_wrong_password(self):
        """Test that a wrong password returns 401 and sets no cookie."""
        response = self.login(password="wrong")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIn("access_token", response.cookies)

    def test_login_unknown_user(self):
        """Test that an unknown email returns 401."""
        response = self.login(email="nobody@example.com")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_missing_fields(self):
        """Test that a login without credentials returns 401."""
        response = self.client.post(self.url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class AuthenticatedTestCase(BaseAuthTestCase):
    """Base class that logs in a user, so the test client holds the auth cookies."""

    def setUp(self):
        """Create an active test user and log in to set the auth cookies."""
        super().setUp()
        self.user = self.create_user()
        self.login()


class LogoutTests(AuthenticatedTestCase):
    def setUp(self):
        """Log in the test user and set the logout url."""
        super().setUp()
        self.url = reverse("logout")

    def test_logout_success_deletes_cookies(self):
        """Test that a logout returns 200 and empties both auth cookies."""
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data["detail"],
            "Logout successful! All Tokens will be deleted. Refresh token is now invalid.",
        )
        self.assertEqual(response.cookies["access_token"].value, "")
        self.assertEqual(response.cookies["refresh_token"].value, "")

    def test_refresh_token_blacklisted_after_logout(self):
        """Test that the refresh token can not be used anymore after logout."""
        refresh_token = self.client.cookies["refresh_token"].value
        self.client.post(self.url)
        self.client.cookies["refresh_token"] = refresh_token
        response = self.client.post(reverse("token_refresh"))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_without_auth(self):
        """Test that a logout without auth cookies returns 401."""
        self.client.cookies.clear()
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_without_refresh_token(self):
        """Test that a logout with access but without refresh cookie returns 401."""
        del self.client.cookies["refresh_token"]
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_with_invalid_access_token(self):
        """Test that a logout with an invalid access token returns 401."""
        self.client.cookies["access_token"] = "invalid"
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TokenRefreshTests(AuthenticatedTestCase):
    def setUp(self):
        """Log in the test user and set the token refresh url."""
        super().setUp()
        self.url = reverse("token_refresh")

    def test_refresh_success(self):
        """Test that a valid refresh returns 200 and sets a new httponly access cookie."""
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"detail": "Token refreshed"})
        self.assertIn("access_token", response.cookies)
        self.assertNotEqual(response.cookies["access_token"].value, "")
        self.assertTrue(response.cookies["access_token"]["httponly"])

    def test_refresh_without_cookie(self):
        """Test that a refresh without refresh token cookie returns 401."""
        self.client.cookies.clear()
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_with_invalid_cookie(self):
        """Test that a refresh with an invalid refresh token returns 401."""
        self.client.cookies["refresh_token"] = "invalid"
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PasswordResetTests(BaseAuthTestCase):
    RESET_MESSAGE = "An email has been sent to reset your password."

    def setUp(self):
        """Create an active test user and set the password reset url."""
        super().setUp()
        self.url = reverse("password_reset")
        self.user = self.create_user()
        self.mock_enqueue.reset_mock()

    def request_reset(self, email=EMAIL):
        """Request a password reset for the given email and return the response."""
        return self.client.post(self.url, {"email": email}, format="json")

    def test_reset_success(self):
        """Test that a valid email returns 200 with the documented message."""
        response = self.request_reset()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data, {"detail": "An email has been sent to reset your password."}
        )

    def test_reset_mail_is_enqueued(self):
        """Test that exactly one reset mail job is enqueued for the user's email."""
        self.request_reset()
        self.mock_enqueue.assert_called_once()
        args = self.mock_enqueue.call_args.args
        self.assertEqual(args[-1], EMAIL)

    def test_reset_email_case_insensitive(self):
        """Test that the reset works with an upper case email."""
        response = self.request_reset(email="TEST@Example.com")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.mock_enqueue.assert_called_once()

    def test_reset_unknown_email(self):
        """Test that an unknown email returns 200 but enqueues no mail job."""
        response = self.request_reset(email="nobody@example.com")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.mock_enqueue.assert_not_called()

    def test_reset_invalid_email(self):
        """Test that an invalid email format returns 200 but enqueues no mail job."""
        response = self.request_reset(email="no-email")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"detail": self.RESET_MESSAGE})
        self.mock_enqueue.assert_not_called()

    def test_reset_missing_email(self):
        """Test that a request without email returns 200 but enqueues no mail job."""
        response = self.client.post(self.url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"detail": self.RESET_MESSAGE})
        self.mock_enqueue.assert_not_called()


class PasswordConfirmTests(BaseAuthTestCase):
    NEW_PASSWORD = "NewSecret456!"
    CONFIRM_MESSAGE = "Your Password has been successfully reset."

    def setUp(self):
        """Create an active user and build a valid password confirm url."""
        super().setUp()
        self.user = self.create_user()
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.token = default_token_generator.make_token(self.user)
        self.valid_data = {
            "new_password": self.NEW_PASSWORD,
            "confirm_password": self.NEW_PASSWORD,
        }

    def get_url(self, uidb64=None, token=None):
        """Return the password confirm url, optionally with other uid or token."""
        return reverse(
            "password_confirm",
            kwargs={"uidb64": uidb64 or self.uidb64, "token": token or self.token},
        )

    def confirm(self, data=None, **url_kwargs):
        """Send the new password to the confirm url and return the response."""
        return self.client.post(
            self.get_url(**url_kwargs),
            self.valid_data if data is None else data,
            format="json",
        )

    def assert_password_unchanged(self):
        """Assert that the user still has the old password."""
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(PASSWORD))

    def test_confirm_success(self):
        """Test that a valid link returns 200 with the documented message."""
        response = self.confirm()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            response.data, {"detail": "Your Password has been successfully reset."}
        )

    def test_password_is_changed(self):
        """Test that the new password is set and the old one is invalid."""
        self.confirm()
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.NEW_PASSWORD))
        self.assertFalse(self.user.check_password(PASSWORD))

    def test_login_with_new_password(self):
        """Test that the login works with the new and fails with the old password."""
        self.confirm()
        self.assertEqual(
            self.login(password=PASSWORD).status_code, status.HTTP_401_UNAUTHORIZED
        )
        self.assertEqual(
            self.login(password=self.NEW_PASSWORD).status_code, status.HTTP_200_OK
        )

    def assert_generic_response(self, response):
        """Assert the generic 200 response that is returned in every case."""
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"detail": self.CONFIRM_MESSAGE})

    def test_confirm_passwords_do_not_match(self):
        """Test that different passwords return 200 but keep the old password."""
        self.valid_data["confirm_password"] = "Other123!"
        response = self.confirm()
        self.assert_generic_response(response)
        self.assert_password_unchanged()

    def test_confirm_missing_fields(self):
        """Test that a missing required field returns 200 but keeps the old password."""
        for field in ["new_password", "confirm_password"]:
            data = self.valid_data.copy()
            data.pop(field)
            response = self.confirm(data=data)
            self.assertEqual(response.status_code, status.HTTP_200_OK, field)
        self.assert_password_unchanged()

    def test_confirm_invalid_token(self):
        """Test that an invalid token returns 200 but keeps the old password."""
        response = self.confirm(token="invalid-token")
        self.assert_generic_response(response)
        self.assert_password_unchanged()

    def test_confirm_invalid_uid(self):
        """Test that an invalid uid returns 200 but keeps the old password."""
        response = self.confirm(uidb64="invalid")
        self.assert_generic_response(response)
        self.assert_password_unchanged()

    def test_confirm_unknown_user(self):
        """Test that a uid of a not existing user returns 200 and changes nothing."""
        unknown_uid = urlsafe_base64_encode(force_bytes(99999))
        response = self.confirm(uidb64=unknown_uid)
        self.assert_generic_response(response)
        self.assert_password_unchanged()

    def test_confirm_inactive_user(self):
        """Test that an inactive user can not reset the password."""
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        response = self.confirm()
        self.assert_generic_response(response)
        self.assert_password_unchanged()

    def test_confirm_link_only_works_once(self):
        """Test that the token is invalid after the password was changed."""
        self.confirm()
        data = {"new_password": "Third789!", "confirm_password": "Third789!"}
        response = self.confirm(data=data)
        self.assert_generic_response(response)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.NEW_PASSWORD))


class FullAuthFlowTests(BaseAuthTestCase):
    def test_register_activate_login_refresh_logout(self):
        """Test the whole flow from registration to logout."""
        register_data = {
            "email": EMAIL,
            "password": PASSWORD,
            "confirmed_password": PASSWORD,
        }
        response = self.client.post(
            reverse("registration"), register_data, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

       
        self.assertEqual(self.login().status_code, status.HTTP_401_UNAUTHORIZED)

        
        uidb64, token = self.mock_enqueue.call_args.args[1:3]
        response = self.client.get(
            reverse("activate", kwargs={"uidb64": uidb64, "token": token})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(self.login().status_code, status.HTTP_200_OK)
        self.assertEqual(
            self.client.post(reverse("token_refresh")).status_code, status.HTTP_200_OK
        )
        self.assertEqual(
            self.client.post(reverse("logout")).status_code, status.HTTP_200_OK
        )

    def test_password_reset_flow(self):
        """Test the whole flow from password reset request to login with new password."""
        new_password = "NewSecret456!"
        self.create_user()
        self.mock_enqueue.reset_mock()

        response = self.client.post(
            reverse("password_reset"), {"email": EMAIL}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        uidb64, token = self.mock_enqueue.call_args.args[1:3]
        response = self.client.post(
            reverse("password_confirm", kwargs={"uidb64": uidb64, "token": token}),
            {"new_password": new_password, "confirm_password": new_password},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(self.login().status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(
            self.login(password=new_password).status_code, status.HTTP_200_OK
        )
