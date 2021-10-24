# Generated by Django 3.2.3 on 2021-10-24 22:33

import core.account.models
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(max_length=255, unique=True, verbose_name='이메일')),
                ('phone', models.CharField(blank=True, max_length=20, null=True, unique=True, verbose_name='휴대폰 번호')),
                ('username', models.CharField(max_length=30, unique=True, verbose_name='계정 이름')),
                ('fullname', models.CharField(max_length=30, verbose_name='사용자 이름')),
                ('photo', models.ImageField(blank=True, upload_to=core.account.models.get_user_photo_path, verbose_name='프로필 사진')),
                ('gender', models.IntegerField(choices=[(0, '밝히고 싶지 않음'), (1, '남성'), (2, '여성'), (3, '맞춤 성별')], default=0, verbose_name='성별')),
                ('web_site', models.CharField(blank=True, max_length=255, null=True, verbose_name='웹 사이트')),
                ('introduction', models.TextField(blank=True, null=True, verbose_name='소개')),
                ('is_active', models.BooleanField(default=False, verbose_name='계정활성')),
                ('is_superuser', models.BooleanField(default=False, verbose_name='관리자')),
                ('date_joined', models.DateTimeField(auto_now=True, verbose_name='수정일')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='생성일')),
            ],
            options={
                'db_table': 'auth_user',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='UserEmailAuthentication',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('security_code', models.IntegerField(verbose_name='보안코드')),
                ('verification', models.BooleanField(default=False, verbose_name='이메일 인증 확인')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='생성일')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_email', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'user_email_authentication',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='Administrator',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.IntegerField(choices=[(0, '전체 관리자'), (1, '비지니스 관리자')], default=1, verbose_name='관리자 타입')),
                ('is_active', models.BooleanField(default=False, verbose_name='계정활성')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='생성일')),
                ('modified_at', models.DateTimeField(auto_now=True, verbose_name='수정일')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='administrator', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'administrator',
                'ordering': ['-created_at'],
            },
        ),
    ]
