# pycloak

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
get_algorithms(self, request) -> List[str]
get_jwt_from_request(self, request) -> str  # extract the raw token from the request
get_data_from_jwt(self, request, jwt) -> dict  # decode the raw token
allow_default_login(self, request) -> bool
```

## Other settings
There are a couple of other settings that can be used to modify the behaviour. They are shown with their default values:

```python
# if these two are set, the jwt will be verified
PYCLOAK_ALGORITHM = None  # could be for instance: "RS256"
PYCLOAK_AUDIENCE = None

# if token decoding or authentication fails, do nothing
PYCLOAK_ALLOW_DEFAULT_LOGIN = True

# claims to use for populating user model 
PYCLOAK_USERNAME_CLAIM = "sub"
PYCLOAK_FIRSTNAME_CLAIM = "given_name"
PYCLOAK_LASTNAME_CLAIM = "family_name"
PYCLOAK_EMAIL_CLAIM = "email"

# roles that escalate user privileges
# they are read from jwt["realm_access"]["roles"] and 
# any jwt["resource_access"][...]["roles"]
PYCLOAK_STAFF_ROLES = []
PYCLOAK_SUPERUSER_ROLES = []
```
