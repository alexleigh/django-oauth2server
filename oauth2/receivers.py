import logging
from django.dispatch import receiver
from django.db.models.signals import pre_save
from .models import Client

log = logging.getLogger(__name__)

@receiver(pre_save, sender=Client)
def compute_client_type(sender, instance, using, **kwargs):
    if instance.client_type == '':
        if instance.client_profile in (Client.CLIENT_PROFILE.web, Client.CLIENT_PROFILE.service):
            log.info('Setting client %s to be of type confidential' % instance)
            instance.client_type = Client.CLIENT_TYPE.confidential
        else:
            log.info('Setting client %s to be of type public' % instance)
            instance.client_type = Client.CLIENT_TYPE.public
