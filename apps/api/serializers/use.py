from rest_framework import serializers
from core.use.models import Post, PostLike, Comments, CommentsLike, Following


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


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comments
        fields = '__all__'


class CommentLikeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommentsLike
        fields = '__all__'


class FollowingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Following
        fields = '__all__'
