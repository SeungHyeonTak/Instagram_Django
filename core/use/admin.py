from django.contrib import admin
from core.use.models import *


@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'created_at',)
    list_display_links = ('id',)
    search_fields = ('user',)
    ordering = ('-created_at',)


@admin.register(Comments)
class CommentsAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'post', 'content', 'created_at',)
    list_display_links = ('id',)
    search_fields = ('user',)
    ordering = ('-created_at',)


@admin.register(PostLike)
class PostLikeAdmin(admin.ModelAdmin):
    list_display = ('id', 'post', 'user', 'created_at')
    list_display_links = ('id',)
    search_fields = ('user',)
    ordering = ('-created_at',)


@admin.register(CommentsLike)
class CommentsLikeAdmin(admin.ModelAdmin):
    list_display = ('id', 'comment', 'user', 'created_at',)
    list_display_links = ('id',)
    search_fields = ('user',)
    ordering = ('-created_at',)


@admin.register(Following)
class FollowingAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'following_user', 'created_at',)
    list_display_links = ('id',)
    search_fields = ('user',)
    ordering = ('-created_at',)
