from django.conf import settings


class _PycloakConfiguration:
    DEFAULTS: dict = {
        "ALGORITHM": None,
        "AUDIENCE": None,
        "PUBLIC_KEY": None,  # can be exported from keyclaok realm
        "TOKEN_HEADER": "HTTP_X_FORWARDED_ACCESS_TOKEN",
        "CLIENT_ID": "account",
        "ALLOW_DEFAULT_LOGIN": False,
        "USERNAME_CLAIM": "preferred_username",
        "FIRSTNAME_CLAIM": "given_name",
        "LASTNAME_CLAIM": "family_name",
        "EMAIL_CLAIM": "email",
        "STAFF_ROLES": [],
        "SUPERUSER_ROLES": [],
        "TOKENID_CLAIM": "jti",
        "SESSION_KEY": "_pycloak_token_id",
        "ISSUER": None,
        "CLAIM_TO_USER_MAPPING": {},
        "CLAIM_SKIP_MISSING": False,
        "CLAIM_IGNORE_VALIDATION_ERROR": False,
    }

    def __getattr__(self, item):
        if item in self.DEFAULTS:
            return getattr(settings, f"PYCLOAK_{item}", self.DEFAULTS[item])
        raise AttributeError

    def to_dict(self):
        return {k: getattr(self, k) for k in self.DEFAULTS}

    def __str__(self):
        return str(self.to_dict())


conf = _PycloakConfiguration()
