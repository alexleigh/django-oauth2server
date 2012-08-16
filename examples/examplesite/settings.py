import os

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))

SITE_ID = 1

ADMINS = ()

MANAGERS = ADMINS

TIME_ZONE = 'America/New_York'

LANGUAGE_CODE = 'en-us'

USE_I18N = True

USE_L10N = True

STATIC_URL = '/static/'

MEDIA_URL = '/media/'

ADMIN_MEDIA_PREFIX = '/static/admin/'

STATICFILES_DIRS = (
    os.path.join(PROJECT_ROOT, 'static'),
)

TEMPLATE_DIRS = (
    os.path.join(PROJECT_ROOT, 'templates'),
)

STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)

TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.core.context_processors.request',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
)

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.admin',
    'crispy_forms',
    'oauth2',
    'accounts',
    'apps',
)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3', 
        'NAME': 'mysite.sqlite',      
        'USER': '',      
        'PASSWORD': '',  
        'HOST': '',      
        'PORT': '',      
    }
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler'
        }
    },
    'loggers': {
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },
    }
}

DEBUG = True
TEMPLATE_DEBUG = DEBUG

SECRET_KEY = '=hf03e+08xlolbb$!-s01m-n_4xn*5mdsd!pm@$+ms!pe08f-7'

ROOT_URLCONF = 'urls'

LOGIN_URL = '/accounts/login/'

OAUTH2_URL = '/oauth2/'

OAUTH2_SCOPES = (
    ('user_info', 'View basic information about your account'),
    ('user_profile', 'View and edit your account profile'),
)
