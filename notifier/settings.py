###############################################################################
## Imports
###############################################################################
# Python
from importlib import import_module

# Django
from django.core.exceptions import ImproperlyConfigured
from django.conf import settings
import south

SECRET_KEY = 'abc123'

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'south',
    'notifier',
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'notifier_testing.db',
        'USER': 'notifier_user',
        'PASSWORD': '',
    }
}

SKIP_SOUTH_TESTS = True

SITE_ID = 1

###############################################################################
## App Settings
###############################################################################
BACKENDS = getattr(
    settings,
    'NOTIFIER_BACKENDS',
    ('notifier.backends.EmailBackend',)
)

BACKEND_CLASSES = [getattr(import_module(mod), cls)
                   for (mod, cls) in (backend.rsplit(".", 1)
                   for backend in BACKENDS)]

# Whether or not to record SentNotification objects
# Not doing so can improve performance, but also lets you store your
# own
CREATE_SENT_NOTIFICATIONS = getattr(
    settings,
    'NOTIFIER_CREATE_SENT_NOTIFICATIONS',
    True
)
