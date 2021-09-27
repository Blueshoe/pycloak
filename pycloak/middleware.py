import logging
from http.client import UNAUTHORIZED
from typing import List

from django.conf import settings
from django.contrib.auth import authenticate, login
from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin
from jwt import decode


logger = logging.getLogger(__name__)


class JWTMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if not request.user.is_authenticated:
            try:
                # 1. get token from request
                jwt = self.get_jwt_from_request(request)

                # 2. get payload from jwt
                jwt_data = self.get_data_from_jwt(request, jwt)

                # 3. authenticate user with jwt data
                user = authenticate(request, jwt_data=jwt_data)
            except Exception as e:
                logger.exception(f"Token auth failed: {e}")
                logger.debug(f"{request.META}")
                if not self.allow_default_login(request):
                    return HttpResponse(status=UNAUTHORIZED)
            else:
                if user:
                    login(request, user)

    def get_verify(self, request) -> bool:
        return bool(self.get_algorithms(request) and self.get_audience(request))

    def get_audience(self, request) -> str:
        return getattr(settings, "PYCLOAK_AUDIENCE", None)

    def get_algorithms(self, request) -> List[str]:
        return [getattr(settings, "PYCLOAK_ALGORITHM", None)]

    def get_jwt_from_request(self, request) -> str:
        token_header = getattr(settings, "PYCLOAK_TOKEN_HEADER", "HTTP_X_FORWARDED_ACCESS_TOKEN")
        header_value = request.META[token_header]
        if token_header == "HTTP_AUTHORIZATION":
            auth_type, jwt = header_value.split(" ")
            if auth_type != "Bearer":
                raise ValueError("No Bearer token")
        else:
            jwt = header_value
        return jwt

    def get_data_from_jwt(self, request, jwt) -> dict:
        options = {
            "verify_signature": self.get_verify(request),
            "audience": self.get_audience(request),
        }
        return decode(
            jwt,
            algorithms=self.get_algorithms(request),
            options=options
        )

    def allow_default_login(self, request) -> bool:
        return getattr(settings, "PYCLOAK_ALLOW_DEFAULT_LOGIN", True)
