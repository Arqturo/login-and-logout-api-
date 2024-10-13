from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group
from server.models import CustomUser  

class Command(BaseCommand):
    help = 'Assigns the CustomUser group to all existing CustomUser instances, removing it from PageMasters'

    def handle(self, *args, **kwargs):
        # Ensure the groups exist
        custom_user_group, created = Group.objects.get_or_create(name='CustomUser')
        page_master_group, created = Group.objects.get_or_create(name='PageMaster')

        for user in CustomUser.objects.all():
            if page_master_group in user.groups.all():
                # If user is a PageMaster, remove them from CustomUser group
                user.groups.remove(custom_user_group)
            else:
                # Otherwise, add them to CustomUser group
                user.groups.add(custom_user_group)

        self.stdout.write(self.style.SUCCESS('Successfully updated groups for all CustomUsers'))
