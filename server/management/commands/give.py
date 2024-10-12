from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group
from server.models import CustomUser  # Replace 'your_app' with your actual app name

class Command(BaseCommand):
    help = 'Assigns the CustomUser group to all existing CustomUser instances'

    def handle(self, *args, **kwargs):
        group, created = Group.objects.get_or_create(name='CustomUser')  # Ensure the group exists
        for user in CustomUser.objects.all():
            user.groups.add(group)
        self.stdout.write(self.style.SUCCESS('Successfully assigned group to all CustomUsers'))