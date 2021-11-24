0.0.12 (2021-11-24)
-------------------
* Add simple auth backend for django-rest-framework 

0.0.11 (2021-11-19)
-------------------
* Stores raw token and decoded data as attributes on request 

0.0.10 (2021-11-15)
-------------------
* Bugfixes 

0.0.9 (2021-11-15)
------------------
* Adds structlog support
* Adds more debug logging

* 0.0.8 (2021-09-30)
------------------
* Stores token id in session to verify previous logins against current access token

0.0.7 (2021-09-27)
------------------
* Fixes bug where superusers might not be staff users

0.0.6 (2021-09-27)
------------------
* Adds `PYClOAK_TOKEN_ID` setting
* Adds roles as groups to user
* Adds logging
* Changes defaults
  * `PYCLOAK_TOKEN_HEADER = "HTTP_X_FORWARDED_ACCESS_TOKEN"`
  * `PYCLOAK_USERNMAE_CLAIM = "preferred_username"` 

0.0.2 (2021-09-24)
------------------
* Adds documentation in README.md

0.0.1 (2021-09-21)
------------------
* Initial version
