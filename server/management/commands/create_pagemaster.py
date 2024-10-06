from django.core.management.base import BaseCommand
from server.models import PageMaster
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

class Command(BaseCommand):
    help = 'Create a new PageMaster user and a superuser'

    def add_arguments(self, parser):
        parser.add_argument('username', type=str, help='Username for the PageMaster and superuser')
        parser.add_argument('password', type=str, help='Password for the PageMaster and superuser')
        parser.add_argument('--full_name', type=str, help='Full name for the PageMaster', default='')

    def handle(self, *args, **kwargs):
        username = kwargs['username']
        password = kwargs['password']
        full_name = kwargs['full_name']

        try:
            # Create the PageMaster user
            pagemaster = PageMaster(username=username, full_name=full_name)
            pagemaster.set_password(password)  # Hash the password
            pagemaster.save()

            # Create a superuser using the createsuperuser command
            User = get_user_model()
            User.objects.create_superuser(username=username, email=username, password=password)

            self.stdout.write(self.style.SUCCESS(f'PageMaster "{username}" and Superuser "{username}" created successfully.'))
        except ValidationError as e:
            self.stderr.write(self.style.ERROR(f'Error: {e}'))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f'Failed to create PageMaster and Superuser: {e}'))
