import logging
from http.client import UNAUTHORIZED
from typing import List

from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin
from jwt import decode, InvalidTokenError

from .config import conf

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

        # 1. get token from request
        try:
            jwt = self.get_jwt_from_request(request)
        except (ValueError, KeyError) as e:
            # no token, but accept other options of authentication
            request.session.pop(conf.SESSION_KEY, None)
            return request.user.is_authenticated

        # 2. get payload from jwt
        try:
            jwt_data = self.get_data_from_jwt(request, jwt)
        except InvalidTokenError as e:
            logger.exception(f"Token decoding failed: {e}")
            return False

        # 3. if the user is authenticated, check the token id is the one from the session
        id_from_token = self.get_token_id(request, jwt_data)
        if request.user.is_authenticated:
            id_from_session = request.session.get(conf.SESSION_KEY, None)
            if id_from_token == id_from_session:
                return True
            else:
                logout(request)
                # no further action, let the authentication go on with the new token

        # 4. authenticate user with jwt data
        try:
            user = authenticate(request, jwt_data=jwt_data)
        except Exception as e:
            logger.exception(f"Token authentication failed: {e}")
            return False

        # 5. login user
        if user:
            login(request, user)
            request.session[conf.SESSION_KEY] = id_from_token
            return True
        else:
            return False

    def get_verify(self, request) -> bool:
        return bool(self.get_algorithms(request) and self.get_audience(request))

    def get_audience(self, request) -> str:
        return conf.AUDIENCE

    def get_algorithms(self, request) -> List[str]:
        return [conf.ALGORITHM]

    def get_jwt_from_request(self, request) -> str:
        token_header = conf.TOKEN_HEADER
        header_value = request.META[token_header]
        if token_header == "HTTP_AUTHORIZATION":
            auth_type, jwt = header_value.split(" ")
            if auth_type != "Bearer":
                raise ValueError("No Bearer token")
        else:
            jwt = header_value
        logger.debug(f"{jwt}")
        return jwt

    def get_data_from_jwt(self, request, jwt) -> dict:
        options = {
            "verify_signature": self.get_verify(request),
            "audience": self.get_audience(request),
        }
        data = decode(
            jwt,
            algorithms=self.get_algorithms(request),
            options=options
        )
        logger.debug(f"{data}")
        return data

    def allow_default_login(self, request) -> bool:
        return conf.ALLOW_DEFAULT_LOGIN

    def get_token_id(self, request, jwt_data) -> str:
        return jwt_data[conf.TOKENID_CLAIM]
