from .base import *

DEBUG = True

ALLOWED_HOSTS = ['127.0.0.1']
SITE_URL = 'http://127.0.0.1:8001'
INTERNAL_IPS = ['127.0.0.1']

INSTALLED_APPS += [
    'debug_toolbar',
]

MIDDLEWARE += [
    'debug_toolbar.middleware.DebugToolbarMiddleware',
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': get_secret('LOCAL_DB_NAME'),
        'USER': get_secret('LOCAL_DB_USER'),
        'PASSWORD': get_secret('LOCAL_DB_PASSWORD'),
        'HOST': get_secret('LOCAL_DB_HOST'),
        'PORT': get_secret('LOCAL_DB_PORT'),
    }
}

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
