from builtins import hasattr


try:
    from rest_framework.authentication import SessionAuthentication

    class CsrfExemptSessionAuthentication(SessionAuthentication):
        def enforce_csrf(self, request):
            if hasattr(request, "jwt"):
                return
            return super(CsrfExemptSessionAuthentication, self).enforce_csrf(request)

except ImportError:
    pass
