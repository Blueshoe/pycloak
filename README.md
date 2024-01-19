# pycloak

## Abstract
When creating service-oriented platforms with django, the redundant user management becomes an unneeded overhead.
Hence, a central user and permission management with secure authorization is required. We'd like to use standard
components all over and only use django for the domain specific implementations. That is following the trend to
push implementation details to the infrastructure.

This project contains utilities for django to support the following architecture. In this usecase django is not required
to authorize or validate the token as this is already done. Django can extract the user's information (i.e. profile and
group memberships) and other claims and work with it right away.

![Pycloak Architecture](docs/static/img/pycloak-arch.png?raw=true "Architecture")

This setup contains a couple of standard components, such as the JWT issuer, for instance 
[Keycloak](https://www.keycloak.com) or any social login provider. The token validation and authorization 
(like e-mail domain, profile information, group membership) is done by a specialized reverse proxy, such as the
[OAuth2 Proxy](https://oauth2-proxy.github.io/oauth2-proxy/). Of course there are plenty of other OpenID Connect/OAuth2
products available on the market.



## Auth backend
Add `pycloak.auth.JWTBackend` to your `AUTHENTICATION_BACKENDS` setting, e.g.:

```python
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "pycloak.auth.JWTBackend",
]
```

The auth backend can be subclassed and provides a couple of hooks to customize its behaviour beyond the flexibility given by the settings:

```
get_username(self, request, jwt_data: dict) -> str
get_email(self, request, jwt_data: dict) -> str:
get_firstname(self, request, jwt_data: dict) -> str
get_lastname(self, request, jwt_data: dict) -> str
get_is_staff(self, request, jwt_data: dict) -> bool
get_is_superuser(self, request, jwt_data: dict) -> bool
get_roles(self, request, jwt_data: dict) -> List[str]
```

## Middleware
Add `pycloak.middleware.JWTMiddleware` to your `MIDDLEWARE`setting, e.g.:

```python
MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    # ...
    'pycloak.middleware.JWTMiddleware',  # after the above!
]
```

The middleware can also be subclassed with the following hooks:
```
get_verify(self, request) -> bool
get_audience(self, request) -> str
get_public_key(self, request) -> str
get_algorithms(self, request) -> List[str]
get_jwt_from_request(self, request) -> str  # extract the raw token from the request
get_data_from_jwt(self, request, jwt) -> dict  # decode the raw token
allow_default_login(self, request) -> bool
def get_token_id(self, request, jwt_data) -> str
```

## Other settings
There are a couple of other settings that can be used to modify the behaviour. They are shown with their default values:

```python
# if these three are set, the jwt will be verified
PYCLOAK_ALGORITHM = None  # could be for instance: "RS256"
PYCLOAK_AUDIENCE = None
PYCLOAK_PUBLIC_KEY = None  # public key can be exported from keycloak (realm settings > keys > public keys)

# if set, the issuer will be checked against this value
PYCLOAK_ISSUER = None 

# header that transports the JWT; use HTTP_AUTHORIZATION for Bearer authentication
PYCLOAK_TOKEN_HEADER = "HTTP_X_FORWARDED_ACCESS_TOKEN"

# if token decoding or authentication fails, do nothing
PYCLOAK_ALLOW_DEFAULT_LOGIN = True

# claims to use for populating user model 
PYCLOAK_USERNAME_CLAIM = "preferred_username"
PYCLOAK_FIRSTNAME_CLAIM = "given_name"
PYCLOAK_LASTNAME_CLAIM = "family_name"
PYCLOAK_EMAIL_CLAIM = "email"

# claim used to identify tokens and expire sessions
PYCLOAK_TOKENID_LOGIN = "jti"

# key used to store token id in session
PYCLOAK_SESSION_KEY = "_pycloak_token_id"

# client_id. Only "resource_access" roles of this client will be considered 
PYCLOAK_CLIENT_ID = "account"

# roles that escalate user privileges
# they are read from jwt["realm_access"]["roles"] and 
# any jwt["resource_access"][...]["roles"]
PYCLOAK_STAFF_ROLES = []
PYCLOAK_SUPERUSER_ROLES = []
```
