from django.conf import settings


class _PycloakConfiguration:
    def __init__(self):
        self.ALGORITHM = getattr(settings, "PYCLOAK_ALGORITHM", None)
        self.AUDIENCE = getattr(settings, "PYCLOAK_AUDIENCE", None)
        self.TOKEN_HEADER = getattr(settings, "PYCLOAK_TOKEN_HEADER", "HTTP_X_FORWARDED_ACCESS_TOKEN")
        self.CLIENT_ID = getattr(settings, "PYCLOAK_CLIENT_ID", "account")
        self.ALLOW_DEFAULT_LOGIN = getattr(settings, "PYCLOAK_ALLOW_DEFAULT_LOGIN", False)
        self.USERNAME_CLAIM = getattr(settings, "PYCLOAK_USERNAME_CLAIM", "preferred_username")
        self.FIRSTNAME_CLAIM = getattr(settings, "PYCLOAK_FIRSTNAME_CLAIM", "given_name")
        self.LASTNAME_CLAIM = getattr(settings, "PYCLOAK_LASTNAME_CLAIM", "family_name")
        self.EMAIL_CLAIM = getattr(settings, "PYCLOAK_EMAIL_CLAIM", "email")
        self.STAFF_ROLES = getattr(settings, "PYCLOAK_STAFF_ROLES", [])
        self.SUPERUSER_ROLES = getattr(settings, "PYCLOAK_SUPERUSER_ROLES", [])
        self.TOKENID_CLAIM = getattr(settings, "PYCLOAK_TOKENID_CLAIM", "jti")
        self.SESSION_KEY = getattr(settings, "PYCLOAK_SESSION_KEY", "_pycloak_token_id")

    def to_dict(self):
        return {
            k: v for k, v in self.__dict__.items() if k.isupper()
        }

    def __str__(self):
        return str(self.to_dict())


conf = _PycloakConfiguration()
