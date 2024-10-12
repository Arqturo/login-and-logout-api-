from datetime import timedelta
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from django.conf import settings
from django.http import JsonResponse

class TokenExpirationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token_expiration_seconds = int(settings.TOKEN_EXPIRATION_SECONDS)

        if 'HTTP_AUTHORIZATION' in request.META:
            auth = request.META['HTTP_AUTHORIZATION'].split()
            if len(auth) == 2 and auth[0] == 'Token':
                try:
                    token = Token.objects.get(key=auth[1])
                    if timezone.now() - token.created > timedelta(seconds=token_expiration_seconds):
                        token.delete()  
                        return JsonResponse({"error": "Token has expired."}, status=401)
                except Token.DoesNotExist:
                    return JsonResponse({"error": "Invalid token."}, status=401)

        response = self.get_response(request)
        return response
