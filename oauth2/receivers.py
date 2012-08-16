from django.dispatch import receiver
from django.db.models.signals import pre_save
from .models import Client

@receiver(pre_save, sender=Client)
def compute_client_type(sender, instance, using, **kwargs):
    if instance.client_type is None:
        if instance.client_profile in (Client.CLIENT_PROFILE.web, Client.CLIENT_PROFILE.service):
            instance.client_type = Client.CLIENT_TYPE.confidential
        else:
            instance.client_type = Client.CLIENT_TYPE.public
