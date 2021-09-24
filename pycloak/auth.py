from typing import List

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


class JWTBackend(ModelBackend):
    def authenticate(self, request, jwt_data: dict = None):
        # 1. get/create/update user
        username = self.get_username(request, jwt_data)
        defaults = {
            "email": self.get_email(request, jwt_data),
            "first_name": self.get_firstname(request, jwt_data),
            "last_name": self.get_lastname(request, jwt_data),
            "is_staff": self.get_is_staff(request, jwt_data),
            "is_superuser": self.get_is_superuser(request, jwt_data),
        }
        UserModel = get_user_model()
        user, _ = UserModel.objects.update_or_create(**{UserModel.USERNAME_FIELD: username}, defaults=defaults)
        user.set_unusable_password()
        user.save()
        user.backend = "pycloak.auth.JWTBackend"
        return user

    def get_username(self, request, jwt_data: dict) -> str:
        return jwt_data[getattr(settings, "PYCLOAK_USERNAME_CLAIM", "sub")]

    def get_email(self, request, jwt_data: dict) -> str:
        return jwt_data[getattr(settings, "PYCLOAK_EMAIL_CLAIM", "email")]

    def get_firstname(self, request, jwt_data: dict) -> str:
        return jwt_data[getattr(settings, "PYCLOAK_FIRSTNAME_CLAIM", "given_name")]

    def get_lastname(self, request, jwt_data: dict) -> str:
        return jwt_data[getattr(settings, "PYCLOAK_LASTNAME_CLAIM", "family_name")]

    def get_is_staff(self, request, jwt_data: dict) -> bool:
        token_roles = self.get_roles(request, jwt_data)
        return bool(set(getattr(settings, "PYCLOAK_STAFF_ROLES", [])).intersection(token_roles))

    def get_is_superuser(self, request, jwt_data: dict) -> bool:
        token_roles = self.get_roles(request, jwt_data)
        return bool(
            set(getattr(settings, "PYCLOAK_SUPERUSER_ROLES", [])).intersection(token_roles))

    def get_roles(self, request, jwt_data: dict) -> List[str]:
        return jwt_data.get("realm_access", {}).get("roles", []) + [role for v in
                                                                    jwt_data.get("resource_access", {}).values() for
                                                                    role in v.get("roles", [])]
