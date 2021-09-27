from typing import List

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group


class JWTBackend(ModelBackend):
    def authenticate(self, request, jwt_data: dict = None):
        # 1. get/create/update user
        username = self.get_username(request, jwt_data)
        is_staff = self.get_is_staff(request, jwt_data)
        is_superuser = self.get_is_superuser(request, jwt_data)
        defaults = {
            "email": self.get_email(request, jwt_data),
            "first_name": self.get_firstname(request, jwt_data),
            "last_name": self.get_lastname(request, jwt_data),
            "is_staff": is_staff or is_superuser,
            "is_superuser": is_superuser,
        }
        UserModel = get_user_model()
        user, _ = UserModel.objects.update_or_create(**{UserModel.USERNAME_FIELD: username}, defaults=defaults)
        user.backend = "pycloak.auth.JWTBackend"
        self.add_groups(request, jwt_data, user)
        return user

    def add_groups(self, request, jwt_data, user):
        token_roles = self.get_roles(request, jwt_data)
        existing = set(Group.objects.filter(name__in=token_roles).values_list("name", flat=True))
        non_existing = [tr for tr in token_roles if tr not in existing]
        Group.objects.bulk_create([Group(name=ne) for ne in non_existing])
        user.groups.set(Group.objects.filter(name__in=token_roles))

    def get_username(self, request, jwt_data: dict) -> str:
        return jwt_data[getattr(settings, "PYCLOAK_USERNAME_CLAIM", "preferred_username")]

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
        return self.get_realm_roles(request, jwt_data) + self.get_client_roles(request, jwt_data)

    def get_realm_roles(self, request, jwt_data: dict):
        return jwt_data.get("realm_access", {}).get("roles", [])

    def get_client_roles(self, request, jwt_data: dict):
        client_id = getattr(settings, "PYCLOAK_CLIENT_ID", None)
        return jwt_data.get("resource_access", {}).get(client_id, {}).get("roles", [])
