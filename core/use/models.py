from django.db import models
from django.utils.translation import ugettext_lazy as _
from time import time
from uuid import uuid4


def get_post_photo_path(instance, filename):
    instance_id = instance.pk if instance.pk else int(time())
    uuid = uuid4().hex
    filename = filename.split('.')[-1] if filename.split('.') else 'jpg'

    return f'post/{instance_id}_{uuid}.{filename}'


class Post(models.Model):
    """게시물"""
    # todo: 태그 나중에 추가 (& 사용자 이름 태그) & 현재 위치 관련 속성
    user = models.ForeignKey('account.User', related_name='posts', on_delete=models.CASCADE)
    photo = models.ImageField(verbose_name=_('사진'), upload_to=get_post_photo_path)
    content = models.TextField(verbose_name=_('내용'), null=True, blank=True)

    created_at = models.DateTimeField(verbose_name=_('생성일'), auto_now_add=True)
    modified_at = models.DateTimeField(verbose_name=_('수정일'), auto_now=True)

    class Meta:
        db_table = 'posts'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.user}'


class Comments(models.Model):
    """댓글"""
    user = models.ForeignKey('account.User', related_name='user_comments', on_delete=models.CASCADE)
    post = models.ForeignKey('Post', related_name='post_comments', on_delete=models.CASCADE)

    content = models.TextField(verbose_name=_('내용'))

    created_at = models.DateTimeField(verbose_name=_('생성일'), auto_now_add=True)
    modified_at = models.DateTimeField(verbose_name=_('수정일'), auto_now=True)

    class Meta:
        db_table = 'comment'
        ordering = ['-created_at']


class PostLike(models.Model):
    """
    게시물 좋아요
    """
    post = models.ForeignKey('Post', on_delete=models.CASCADE)
    user = models.ForeignKey('account.User', on_delete=models.CASCADE)

    created_at = models.DateTimeField(verbose_name=_('생성일'), auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class CommentsLike(models.Model):
    """
    댓글 좋아요
    좋아요 누른 사용자 속성 추가하기
    """
    comment = models.ForeignKey('Comments', on_delete=models.CASCADE)
    like_count = models.IntegerField(verbose_name=_('댓글 좋아요'), default=0)


class Following(models.Model):
    """팔로우"""
    user = models.ForeignKey('account.User', related_name='following', on_delete=models.CASCADE)
    following_user = models.ForeignKey('account.User', related_name='followers', on_delete=models.CASCADE)

    created_at = models.DateTimeField(verbose_name=_('생성일'), auto_now_add=True)

    class Meta:
        db_table = 'followings'
        ordering = ['-created_at']
