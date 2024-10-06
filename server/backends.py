from django.contrib.auth.backends import ModelBackend
from .models import PageMaster

class PageMasterBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = PageMaster.objects.get(username=username)
            if user.check_password(password):
                return user
        except PageMaster.DoesNotExist:
            return None