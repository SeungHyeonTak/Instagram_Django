from django.contrib import admin
from core.account.models import *


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('id', 'email', 'fullname', 'is_active', 'last_login', 'created_at')
    list_display_links = ('email',)
    search_fields = ('fullname', 'username',)
    ordering = ('-created_at',)


@admin.register(Administrator)
class AdministratorAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'type', 'is_active', 'created_at')
    list_display_links = ('id',)
    search_fields = ('user',)
    ordering = ('-created_at',)


@admin.register(UserEmailAuthentication)
class UserEmailAuthentication(admin.ModelAdmin):
    list_display = ('id', 'user', 'security_code', 'verification', 'created_at')
    list_display_links = ('user',)
    search_fields = ('user',)
    ordering = ('-created_at',)
