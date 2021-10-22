from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.utils.translation import ugettext_lazy as _
from time import time
from uuid import uuid4


def get_user_photo_path(instance, filename):
    """회원 프로필 사진 저장 경로"""
    instance_id = instance.pk if instance.pk else int(time())
    uuid = uuid4().hex
    filename = filename.split('.')[-1] if filename.split('.') else 'jpg'

    return f'user/{instance_id}_{uuid}.{filename}'


class UserManager(BaseUserManager):
    def create_user(self, email, password=None):
        if not email:
            # raise : 단일 인자의 예외를 발생
            raise ValueError(_('User must have and phone and email address'))

        user = self.model(
            email=self.normalize_email(email),
        )
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password):
        user = self.create_user(
            email=email,
            password=password,
        )

        user.is_superuser = True
        user.is_active = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    """회원정보"""
    UNCHECKED, MALE, FEMALE, TAILORED_GENDER = (0, 1, 2, 3)
    GENDER_CHOICE = (
        (UNCHECKED, '밝히고 싶지 않음'),
        (MALE, '남성'),
        (FEMALE, '여성'),
        (TAILORED_GENDER, '맞춤 성별')
    )

    email = models.EmailField(verbose_name=_('이메일'), max_length=255, unique=True)
    phone = models.CharField(verbose_name=_('휴대폰 번호'), max_length=20, unique=True, blank=True, null=True)
    username = models.CharField(verbose_name=_('계정 이름'), max_length=30, unique=True)
    fullname = models.CharField(verbose_name=_('사용자 이름'), max_length=30)
    photo = models.ImageField(verbose_name=_('프로필 사진'), upload_to=get_user_photo_path, blank=True)
    gender = models.IntegerField(verbose_name=_('성별'), default=0, choices=GENDER_CHOICE)
    web_site = models.CharField(verbose_name=_('웹 사이트'), max_length=255, null=True, blank=True)
    introduction = models.TextField(verbose_name=_('소개'), null=True, blank=True)

    is_active = models.BooleanField(verbose_name=_('계정활성'), default=False)
    is_superuser = models.BooleanField(verbose_name=_('관리자'), default=False)

    date_joined = models.DateTimeField(verbose_name=_('수정일'), auto_now=True)
    created_at = models.DateTimeField(verbose_name=_('생성일'), auto_now_add=True)

    objects = UserManager()
    USERNAME_FIELD = 'email'

    class Meta:
        db_table = 'auth_user'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.email}({self.fullname})'

    @property
    def is_staff(self):
        return self.is_superuser

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser


class Administrator(models.Model):
    """
    관리자 정보
    - 전체 관리자
    - 비지니스 관리자
    """
    ALL_ADMIN, BUSINESS_ADMIN = (0, 1)
    ADMIN_TYPE = (
        (ALL_ADMIN, '전체 관리자'),
        (BUSINESS_ADMIN, '비지니스 관리자')
    )
    user = models.ForeignKey('User', related_name='administrator', on_delete=models.CASCADE)
    type = models.IntegerField(verbose_name=_('관리자 타입'), default=1, choices=ADMIN_TYPE)
    is_active = models.BooleanField(verbose_name=_('계정활성'), default=False)
    created_at = models.DateTimeField(verbose_name=_('생성일'), auto_now_add=True)
    modified_at = models.DateTimeField(verbose_name=_('수정일'), auto_now=True)

    class Meta:
        db_table = 'administrator'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.user}({self.type})'


class UserEmailAuthentication(models.Model):
    """
    사용자 이메일 인증 확인
    이후 보안 코드쪽도 추가하기
    """
    user = models.ForeignKey('User', related_name='user_email', on_delete=models.CASCADE)
    security_code = models.IntegerField(verbose_name=_('보안코드'))
    verification = models.BooleanField(verbose_name=_('이메일 인증 확인'), default=False)

    created_at = models.DateTimeField(verbose_name=_('생성일'), auto_now_add=True)

    class Meta:
        db_table = 'user_email_authentication'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.user}({self.security_code})'
