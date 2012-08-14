import logging

from django.core.management.base import BaseCommand

from ...models import Scope
from ...settings import SCOPES

log = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Initialize the scopes available through OAuth2 by reading the ' \
           'OAUTH2_SCOPES variable in settings.'

    def handle(self, *args, **options):
        Scope.objects.all().delete()
        
        for name, description in SCOPES:
            scope = Scope(name=name, description=description)
            scope.save()
