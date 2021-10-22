from .base import *

DEBUG = False

ALLOWED_HOSTS = ['*']  # 이후 고정 아이피 등록시키기

# AWS RDS (PostgreSQL) 연동 필요
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': '',
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': '',
    }
}

# AWS S3 연동 작업 필요
