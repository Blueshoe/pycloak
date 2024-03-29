import time

from base64 import b64decode
from http.client import UNAUTHORIZED
from typing import List

from cryptography.hazmat.primitives import serialization
from django.contrib.auth import authenticate, login, logout
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin
from jwt import ExpiredSignatureError, InvalidTokenError, decode

from .config import conf


try:
    import structlog

    logger = structlog.get_logger(__name__)
except ImportError:
    import logging

    logger = logging.getLogger(__name__)


class JWTMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if not self.process_token(request):
            request.session.pop(conf.SESSION_KEY, None)
            if not self.allow_default_login(request):
                return HttpResponse(status=UNAUTHORIZED)

    def process_token(self, request) -> bool:
        """
        Return True if there is a logged in and authenticated user when this function returns
        """

        # if a token is present, make sure that token is or has been used for authentication
        # if not, let an existing login persist

        logger.debug(
            "start process_token",
            headers=request.headers.keys(),
            config=conf.to_dict(),
        )

        # 1. get token from request
        try:
            jwt = self.get_jwt_from_request(request)
        except (ValueError, KeyError):
            # no token, but accept other options of authentication
            logger.warning("No jwt retrieved")
            request.session.pop(conf.SESSION_KEY, None)
            return request.user.is_authenticated

        # 2. get payload from jwt
        try:
            jwt_data = self.get_data_from_jwt(request, jwt)
        except (InvalidTokenError, ValueError) as e:
            logger.exception("Token decoding failed", error=str(e))
            return False
        except ExpiredSignatureError:
            # this can be raised, when the token is decoded with verify_signature=True
            logger.warning("Token has expired")
            return False

        # 3. check if the token is expired
        # this is implicitly done, when the token is decoded with verify_signature=True
        if jwt_data.get("exp", 0) < time.time():
            logger.warning("Token has expired")
            return False

        # 4. check if the token is issued by the configured issuer
        iss = jwt_data.get("iss", "")
        if iss and conf.ISSUER and (iss != conf.ISSUER):
            logger.warning("Token issuer mismatch")
            return False

        # 5. if the user is authenticated, check the token id is the one from the session
        id_from_token = self.get_token_id(request, jwt_data)
        logger.debug("Token id read", request_token_id=id_from_token)
        if request.user.is_authenticated:
            id_from_session = request.session.get(conf.SESSION_KEY, None)
            logger.debug("Session token id read", session_token_id=id_from_session)
            if id_from_token == id_from_session:
                logger.debug("Id match, session still valid")
                return True

        # 6. authenticate user with jwt data
        try:
            user = authenticate(request, jwt_data=jwt_data)
        except Exception as e:
            logger.exception("Token authentication failed", error=str(e))
            return False

        # 7. login user
        if user:
            request.session[conf.SESSION_KEY] = id_from_token
            if request.user != user:
                logger.debug("Different user, logging out")
                logout(request)
            if not request.user.is_authenticated:
                logger.debug("Logging user in", user=str(user))
                login(request, user)
            else:  # the same user with a new token
                request.user = (
                    user  # be sure this is the updated object as per the new token
                )
            self.store_claim_on_user(request, user)
            return True
        else:
            logger.warning("No user found, no login")
            return False

    def get_verify(self, request) -> bool:
        return bool(
            self.get_algorithms(request)
            and self.get_audience(request)
            and self.get_public_key(request)
        )

    def get_public_key(self, request):
        key = conf.PUBLIC_KEY
        if key:
            key_der = b64decode(key.encode())
            public_key = serialization.load_der_public_key(key_der)
            return public_key

    def get_audience(self, request) -> str:
        return conf.AUDIENCE

    def get_algorithms(self, request) -> List[str]:
        return [conf.ALGORITHM]

    def get_bearer_token(self, request) -> str:
        """
        Get the token from the Authorization header
        depending on the configuration of the oauth2 proxy, this might be the jwt access_token or the id_token
        """
        try:
            header_value = request.META["HTTP_AUTHORIZATION"]
            auth_type, token = header_value.split(" ")
            if auth_type != "Bearer":
                return None
        except (KeyError, ValueError, TypeError):
            return None
        return token

    def get_jwt_from_request(self, request) -> str:
        token_header = conf.TOKEN_HEADER
        header_value = request.META[token_header]
        bearer_token = self.get_bearer_token(request)
        if token_header == "HTTP_AUTHORIZATION":
            logger.debug("Bearer token")
            if bearer_token is None:
                raise ValueError("No Bearer token")
            jwt = bearer_token
            id_token = None
        else:
            logger.debug("Header token")
            jwt = header_value
            id_token = bearer_token  # might be None
        logger.debug("Raw token retrieved", raw_token=jwt)
        request.jwt = jwt
        request.id_token = id_token
        return jwt

    def get_data_from_jwt(self, request, jwt) -> dict:
        options = {
            "verify_signature": self.get_verify(request),
        }
        data = decode(
            jwt,
            algorithms=self.get_algorithms(request),
            key=self.get_public_key(request),
            audience=self.get_audience(request),
            options=options,
        )
        logger.debug("jwt decoded", jwt_data=data)
        request.jwt_data = data
        return data

    def allow_default_login(self, request) -> bool:
        return conf.ALLOW_DEFAULT_LOGIN

    def get_token_id(self, request, jwt_data) -> str:
        return jwt_data[conf.TOKENID_CLAIM]

    def store_claim_on_user(self, request, user):
        # store objects to save (user or related objects)
        obj_to_save = set()

        for claim, attr in conf.CLAIM_TO_USER_MAPPING.items():
            if not attr.get("field"):
                raise ImproperlyConfigured(
                    f"PYCLOAK_CLAIM_TO_USER_MAPPING: {claim} has no field specified"
                )

            # check for related fields on the user model
            rel_fields = attr["field"].split(".")
            obj = user
            field = rel_fields.pop()
            for rel_obj in rel_fields:
                obj = getattr(obj, rel_obj)
                if obj is None or not (hasattr(obj, "_meta") and hasattr(obj._meta, "fields")):
                    raise ImproperlyConfigured(
                        f"Related object {rel_obj} not found on user object or is not a model instance."
                    )
            obj_to_save.add(obj)

            # check for value
            value = request.jwt_data.get(claim)
            if value is None:
                logger.warning(f"Claim {claim} not found in jwt")
                if conf.CLAIM_SKIP_MISSING:
                    continue
                else:
                    raise ImproperlyConfigured(f"Claim {claim} not found in jwt")

            # check for callback method
            if callback_fun := attr.get("callback"):
                try:
                    value = callback_fun(value)
                except Exception as e:
                    logger.exception(
                        f"Callback {callback_fun} failed for claim {claim}",
                        error=str(e),
                    )
                    raise ValueError(
                        f"Callback {callback_fun} failed for claim {claim}"
                    )

            # explicitly validate value on field
            # we do this, as we want to save all fields that we can if PYCLOAK_IGNORE_VALIDATION_ERROR is True
            for obj_field in obj._meta.fields:
                if field == obj_field.name:
                    try:
                        obj_field.get_prep_value(value)
                        setattr(obj, field, value)
                    except ValidationError as e:
                        logger.warning(
                            f"Validation error for claim {claim} on field {field}",
                            error=str(e),
                        )
                        if not conf.CLAIM_IGNORE_VALIDATION_ERROR:
                            raise e

        # save the object(s) (user or related object)
        for obj in obj_to_save:
            obj.save()
