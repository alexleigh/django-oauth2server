import logging

from tastypie.authorization import Authorization
from .models import Scope
from .validator import JSONValidator, ValidationException

log = logging.getLogger(__name__)

class OAuth2Authorization(Authorization):
    def is_authorized(self, request):
        log.debug(object)
        # get the scope required to access the object
        scope = None
        object_class = self.resource_meta.object_class
        if object_class and getattr(object_class, '_meta', None):
            # TODO: make this work
            permission_codes = {
                #'GET': '%s.get_%s',
                'POST': '%s.add_%s',
                'PUT': '%s.change_%s',
                'DELETE': '%s.delete_%s',
            }
            if request.method in permission_codes:
                permission_code = permission_codes[request.method] % (
                    object_class._meta.app_label,
                    object_class._meta.module_name
                )
                scope = Scope.objects.get(name=permission_code)
            scope = Scope.objects.get(name='date_joined')
        
        # authenticate and authorize
        validator = JSONValidator(scope=scope)
        log.debug(request.user)
        try:
            validator.validate(request)
        except ValidationException:
            return validator.error_response()
        return True