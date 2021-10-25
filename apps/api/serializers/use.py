from rest_framework import serializers
from core.use.models import Post, PostLike


class PostFavSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = '__all__'


class PostSerializer(serializers.HyperlinkedModelSerializer):

    def to_representation(self, post):
        like = PostLike.objects.filter(post=post).count()
        return_dict = {
            "id": post.pk,
            "user": post.user.username,
            "photo": post.photo.url,
            "content": post.content,
            'like_count': like
        }
        return return_dict

    class Meta:
        model = Post
        fields = ('id', 'user', 'photo', 'content')
