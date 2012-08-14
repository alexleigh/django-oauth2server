import logging

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

log = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Initialize the scopes available through OAuth2 by reading the ' \
           'OAUTH2_SCOPES variable in settings.'

    def handle(self, *args, **options):
        users = User.objects.all()
        
        for user in users:
            pass