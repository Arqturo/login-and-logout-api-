from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import PageMaster

class PageMasterTokenAuthentication(TokenAuthentication):
    def authenticate(self, request):
        auth = super().authenticate(request)
        if auth is None:
            return None

        user, token = auth

        # Ensure the user is a PageMaster
        if not isinstance(user, PageMaster):
            raise AuthenticationFailed('This token does not belong to a PageMaster user.')

        return (user, token)