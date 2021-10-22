from rest_framework import serializers
from core.use.models import Post


class PostSerializer(serializers.HyperlinkedModelSerializer):

    def to_representation(self, post):
        return_dict = {
            "id": post.pk,
            "user": post.user.username,
            "photo": post.photo.url,
            "content": post.content
        }
        return return_dict

    class Meta:
        model = Post
        fields = ('id', 'user', 'photo', 'content')
