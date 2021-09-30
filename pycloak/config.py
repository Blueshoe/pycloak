from django.conf import settings


class _PycloakConfiguration:
    ALGORITHM = getattr(settings, "PYCLOAK_ALGORITHM", None)
    AUDIENCE = getattr(settings, "PYCLOAK_AUDIENCE", None)
    TOKEN_HEADER = getattr(settings, "PYCLOAK_TOKEN_HEADER", "HTTP_AUTHORIZATION")
    CLIENT_ID = getattr(settings, "PYCLOAK_CLIENT_ID", "account")
    ALLOW_DEFAULT_LOGIN = getattr(settings, "PYCLOAK_ALLOW_DEFAULT_LOGIN", False)
    USERNAME_CLAIM = getattr(settings, "PYCLOAK_USERNAME_CLAIM", "preferred_username")
    FIRSTNAME_CLAIM = getattr(settings, "PYCLOAK_FIRSTNAME_CLAIM", "given_name")
    LASTNAME_CLAIM = getattr(settings, "PYCLOAK_LASTNAME_CLAIM", "family_name")
    EMAIL_CLAIM = getattr(settings, "PYCLOAK_EMAIL_CLAIM", "email")
    STAFF_ROLES = getattr(settings, "PYCLOAK_STAFF_ROLES", [])
    SUPERUSER_ROLES = getattr(settings, "PYCLOAK_SUPERUSER_ROLES", [])
    TOKENID_CLAIM = getattr(settings, "PYCLOAK_TOKENID_CLAIM", "jti")
    SESSION_KEY = getattr(settings, "PYCLOAK_SESSION_KEY", "_pycloak_token_id")


conf = _PycloakConfiguration()
