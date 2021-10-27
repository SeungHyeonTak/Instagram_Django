from rest_framework import viewsets, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework_jwt.authentication import JSONWebTokenAuthentication

from apps.api.serializers.use import PostSerializer, PostFavSerializer, CommentSerializer, CommentLikeSerializer, \
    FollowingSerializer
from core.use.models import Post, PostLike, Comments, CommentsLike, Following
from core.account.models import User


class PostsViewSet(viewsets.ModelViewSet):
    """
    list: 게시물 목록 조회
    create: 게시물 생성
    """
    serializer_class = PostSerializer
    authentication_classes = [JSONWebTokenAuthentication]
    permission_classes = [IsAuthenticated]

    pagination = PageNumberPagination()

    def get_queryset(self):
        return Post.objects.all().order_by('-id')

    def post_list(self, request):
        is_checked = True
        status_code = status.HTTP_200_OK

        try:
            self.pagination.page_size = 20
            query = self.get_queryset()
            result = self.pagination.paginate_queryset(query, request)
            serializer = PostSerializer(result, many=True)

            return serializer, status_code, is_checked
        except Exception as e:
            print(f'게시물 조회 실패 : {e}')
            response_message = {'400': '게시물을 조회 할 수 없습니다.'}
            status_code = status.HTTP_400_BAD_REQUEST
            is_checked = False

            return response_message, status_code, is_checked

    def list(self, request, *args, **kwargs):
        """
        게시물 목록 조회

        ---
        ## /use/posts/
        """
        try:
            response_message, status_code, is_checked = self.post_list(request)
            if is_checked:
                return self.pagination.get_paginated_response(response_message.data)
            return Response(data=response_message, status=status_code)
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)

    def params_validate(self, request):
        """게시물 생성 파라미터 검사"""
        request_data = request.data
        is_params_checked = True
        response_message = {}
        status_code = status.HTTP_200_OK

        photo = request_data.get('photo', None)  # 게시할 사진

        if photo is None:
            is_params_checked = False
            response_message = {'400 - 1': '필수파라미터(photo)가 없습니다.'}
            status_code = status.HTTP_400_BAD_REQUEST
            return response_message, status_code, is_params_checked

        return response_message, status_code, is_params_checked

    def post_create(self, request):
        """게시물 생성 비지니스 로직"""
        request_data = request.data
        is_checked = False
        status_code = status.HTTP_400_BAD_REQUEST
        try:
            post = Post.objects.create(
                user=self.request.user,
                photo=request_data.get('photo'),
                content=request_data.get('content', None),
            )
            status_code = status.HTTP_201_CREATED
            serializer = PostSerializer(post)
            response_message = serializer.data
            is_checked = True
            return response_message, status_code, is_checked
        except Exception as e:
            print(f'게시물 생성 실패 : {e}')
            response_message = {'400 - 2': '게시물 생성을 실패하였습니다.'}
            return response_message, status_code, is_checked

    def create(self, request, *args, **kwargs):
        """
        게시물 생성

        ---
        ## /use/posts/
        """
        try:
            response_message, status_code, is_checked = self.params_validate(request)
            if is_checked:
                response_message, status_code, is_checked = self.post_create(request)
            return Response(
                data=response_message if is_checked else response_message,
                status=status_code if is_checked else status_code
            )
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)


class PostViewSet(viewsets.ModelViewSet):
    """
    retrieve: 게시물 조회
    partial_update: 게시물 수정
    destroy: 게시물 삭제
    """
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    authentication_classes = [JSONWebTokenAuthentication]

    def get_permissions(self):
        """http method 권한 핸들링"""
        if self.action == 'patch' or self.action == 'delete':
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [AllowAny]

        return [permission() for permission in permission_classes]

    def post_detail(self, pk):
        is_checked = False
        status_code = status.HTTP_400_BAD_REQUEST
        response_message = {}

        try:
            post = self.queryset.get(pk=pk)
            count = PostLike.objects.filter(post=post).count()
            response_message.update({
                'id': post.pk,
                'user': post.user.email,
                'photo': post.photo.url,
                'content': post.content,
                'like_count': count,
                'created_at': post.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })
            status_code = status.HTTP_200_OK
            is_checked = True
        except Post.DoesNotExist:
            response_message = {'400 - 2': '게시물이 없습니다.'}

        return response_message, status_code, is_checked

    def retrieve(self, request, *args, **kwargs):
        """
        게시물 조회

        ---
        ## /use/post/<int:pk>
        """
        try:
            pk = kwargs.get('pk')
            response_message, status_code, is_checked = self.params_check(pk)
            if is_checked:
                response_message, status_code, is_checked = self.post_detail(pk)
            return Response(
                data=response_message if is_checked else response_message,
                status=status_code if is_checked else status_code
            )
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)

    def params_patch_validate(self, request, pk):
        """게시물 수정 파라미터 검사"""
        request_data = request.data
        is_params_checked = True
        response_message = {}
        status_code = status.HTTP_200_OK

        photo = request_data.get('photo', None)
        content = request_data.get('content', None)

        if pk is None:
            is_params_checked = False
            response_message = {'400 - 1': '필수파라미터(pk)가 없습니다.'}
            return response_message, status_code, is_params_checked

        if photo is not None:
            response_message.update({'photo': photo})
        if content is not None:
            response_message.update({'content': content})
        response_message.update({'pk': pk})

        return response_message, status_code, is_params_checked

    def post_patch(self, request, **kwargs):
        """게시물 수정 비지니스 로직"""
        is_checked = False
        response_message = {}
        status_code = status.HTTP_400_BAD_REQUEST
        try:
            post = self.queryset.get(id=kwargs.get('pk'))

            if request.user != post.user:
                response_message = {'400 - 2': '게시물에 접근할 권한이 없습니다.'}
                return response_message, status_code, is_checked
            elif post:
                for key, value in kwargs.items():
                    if 'photo' is key:
                        post.photo = value
                    if 'content' is key:
                        post.content = value
                post.save()
                is_checked = True
                status_code = status.HTTP_200_OK
                response_message = {'message': '게시물이 수정되었습니다.'}
                return response_message, status_code, is_checked

        except Post.DoesNotExist:
            response_message = {'400 - 3': '게시물이 존재하지 않습니다.'}
            return response_message, status_code, is_checked
        except Exception as e:
            print(f'게시물 수정 Error : {e}')
            return response_message, status_code, is_checked

    def partial_update(self, request, *args, **kwargs):
        """
        게시물 수정

        ---
        ## /use/post/<int:pk>
        """
        try:
            response_message, status_code, is_checked = self.params_patch_validate(request, kwargs.get('pk'))
            if is_checked:
                response_message, status_code, is_checked = self.post_patch(request, **response_message)
            return Response(
                data=response_message if is_checked else response_message,
                status=status_code if is_checked else status_code
            )
        except Exception as e:
            print(f'error : {e}')
            response_message = {"500": "서버 에러"}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)

    def params_check(self, pk):
        """게시물 삭제 파라미터 검사 (해당 게시물의 id값)"""
        is_checked = True
        response_message = {}
        status_code = status.HTTP_200_OK

        if pk is None:
            is_checked = False
            response_message = {'400 - 1': '게시물이 존재 하지 않습니다.'}
            status_code = status.HTTP_400_BAD_REQUEST
            return response_message, status_code, is_checked

        return response_message, status_code, is_checked

    def post_delete(self, request, pk):
        """게시물 삭제"""
        response_message = {}
        status_code = status.HTTP_400_BAD_REQUEST
        is_checked = False

        try:
            post = self.queryset.get(pk=pk)
            if request.user != post.user:
                response_message = {'400 - 2': '게시물에 접근할 권한이 없습니다.'}
            else:
                post.delete()
                response_message = {'message': '게시물이 삭제되었습니다.'}
                status_code = status.HTTP_200_OK

            return response_message, status_code, is_checked
        except Post.DoesNotExist:
            response_message = {'400 - 3': '게시물이 존재하지 않습니다.'}
            return response_message, status_code, is_checked
        except Exception as e:
            print(f'게시물 삭제 error : {e}')
            return response_message, status_code, is_checked

    def destroy(self, request, *args, **kwargs):
        """
        게시물 삭제

        ---
        ## /use/post/<int:pk>
        """
        try:
            pk = kwargs.get('pk')
            response_message, status_code, is_checked = self.params_check(pk)
            if is_checked:
                response_message, status_code, is_checked = self.post_delete(request, pk)
            return Response(
                data=response_message if is_checked else response_message,
                status=status_code if is_checked else status_code
            )
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)


class PostFavViewSet(viewsets.ModelViewSet):
    """
    create: 게시물 좋아요
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JSONWebTokenAuthentication]
    serializer_class = PostFavSerializer
    queryset = PostLike.objects.all()

    def params_validate(self, request):
        """파라미터 검사"""
        request_data = request.data
        response_message = {}
        status_code = status.HTTP_200_OK
        is_checked = True

        post_id = request_data.get('post_id')
        if not post_id:
            response_message = {'400': '필수파라미터(post_id)가 없습니다.'}
            status_code = status.HTTP_400_BAD_REQUEST
            is_checked = False
            return response_message, status_code, is_checked

        return response_message, status_code, is_checked

    def post_like(self, request):
        request_data = request.data
        response_message = {}
        status_code = status.HTTP_400_BAD_REQUEST
        is_checked = False

        post_id = request_data.get('post_id')

        try:
            post = Post.objects.get(id=post_id)
            fav = self.queryset.filter(post=post, user=request.user).first()
            if not fav:
                """해당 사용자가 좋아요 누른적 없을때 (좋아요 +1)"""
                self.queryset.create(
                    post=post,
                    user=request.user
                )
                response_message = {'message': f'게시물({post_id}) 좋아요'}
                status_code = status.HTTP_201_CREATED
                is_checked = True
                return response_message, status_code, is_checked
            else:
                fav.delete()
                response_message = {'message': f'게시물({post_id}) 좋아요 취소'}
                status_code = status.HTTP_200_OK
                is_checked = True
                return response_message, status_code, is_checked
        except Post.DoesNotExist:
            response_message = {'400': '게시물이 존재하지 않습니다.'}
        return response_message, status_code, is_checked

    def create(self, request, *args, **kwargs):
        """
        게시물 좋아요

        ---
        ## use/post/favs
        """
        try:
            response_message, status_code, is_checked = self.params_validate(request)
            if is_checked:
                response_message, status_code, is_checked = self.post_like(request)
            return Response(
                data=response_message if is_checked else response_message,
                status=status_code if is_checked else status_code
            )
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)


class CommentViewSet(viewsets.ModelViewSet):
    """
    create: 댓글 작성
    """
    queryset = Comments.objects.all()
    authentication_classes = [JSONWebTokenAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = CommentSerializer

    def params_validate(self, request):
        """댓글 파라미터 검사"""
        request_data = request.data
        is_checked = True
        response_message = {}
        status_code = status.HTTP_200_OK
        loss_params = []

        content = request_data.get('content', None)

        if content is None:
            loss_params.append('content')

        if loss_params:
            response_message = {'400 - 1': f'필수파라미터({",".join(loss_params)})가 없습니다.'}
            status_code = status.HTTP_400_BAD_REQUEST

        return response_message, status_code, is_checked

    def comment_create(self, request, pk):
        """댓글 생성 로직"""
        request_data = request.data
        is_checked = False
        status_code = status.HTTP_400_BAD_REQUEST
        response_message = {}

        try:
            post = Post.objects.get(pk=pk)
            Comments.objects.create(
                user=self.request.user,
                post=post,
                content=request_data.get('content')
            )
            status_code = status.HTTP_201_CREATED
            is_checked = True
        except Post.DoesNotExist:
            response_message = {'message': '게시물이 없습니다.'}
        except Exception as e:
            print(f'댓글 생성 실패 : {e}')
            response_message = {'400 - 2': '댓글 생성을 실패하였습니다.'}

        return response_message, status_code, is_checked

    def create(self, request, *args, **kwargs):
        """
        댓글 작성

        ---
        ## use/post/<int:pk>/comment
        """
        try:
            pk = kwargs.get('pk')
            response_message, status_code, is_checked = self.params_validate(request)
            if is_checked:
                response_message, status_code, is_checked = self.comment_create(request, pk)
            return Response(
                data=response_message if is_checked else response_message,
                status=status_code if is_checked else status_code
            )
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)


class CommentFavViewSet(viewsets.ModelViewSet):
    """
    create: 댓글 좋아요
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JSONWebTokenAuthentication]
    serializer_class = CommentLikeSerializer
    queryset = CommentsLike.objects.all()

    def params_validate(self, request):
        request_data = request.data
        response_message = {}
        status_code = status.HTTP_200_OK
        is_checked = True

        comment_id = request_data.get('comment_id')

        if not comment_id:
            response_message = {'400 - 1': '필수파라미터(comment_id)가 없습니다.'}
            status_code = status.HTTP_400_BAD_REQUEST
            is_checked = False
            return response_message, status_code, is_checked

        return response_message, status_code, is_checked

    def comment_favs_create(self, request):
        request_data = request.data
        response_message = {}
        status_code = status.HTTP_400_BAD_REQUEST
        is_checked = False

        try:
            comment_id = request_data.get('comment_id')
            comment = Comments.objects.get(id=comment_id)
            comment_fav = self.queryset.filter(comment=comment, user=self.request.user).first()
            if not comment_fav:
                """좋아요 +1"""
                self.queryset.create(
                    comment=comment,
                    user=self.request.user
                )
                response_message = {'message': f'댓글({comment_id}) 좋아요'}
                status_code = status.HTTP_201_CREATED
                is_checked = True
            else:
                """좋아요 -1"""
                comment_fav.delete()
                response_message = {'message': f'댓글({comment_id}) 좋아요 취소'}
                status_code = status.HTTP_200_OK
                is_checked = True
        except Comments.DoesNotExist:
            response_message = {'400 - 2': '댓글이 존재하지 않습니다.'}

        return response_message, status_code, is_checked

    def create(self, request, *args, **kwargs):
        """
        댓글 좋아요

        ---
        ## use/comment/favs
        """
        try:
            response_message, status_code, is_checked = self.params_validate(request)
            if is_checked:
                response_message, status_code, is_checked = self.comment_favs_create(request)
            return Response(
                data=response_message if is_checked else response_message,
                status=status_code if is_checked else status_code
            )
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)


class FollowViewSet(viewsets.ModelViewSet):
    """
    create: 팔로우 추가
    """
    permission_classes = [IsAuthenticated]
    authentication_classes = [JSONWebTokenAuthentication]
    serializer_class = FollowingSerializer
    queryset = Following

    def params_validate(self, request):
        request_data = request.data
        response_message = {}
        status_code = status.HTTP_200_OK
        is_checked = True

        follow_id = request_data.get('follow_id')

        if not follow_id:
            response_message = {'400 - 1': '필수파라미터(follow_id)가 없습니다.'}
            status_code = status.HTTP_400_BAD_REQUEST
            is_checked = False
            return response_message, status_code, is_checked

        return response_message, status_code, is_checked

    def follow_create(self, request):
        status_code = status.HTTP_400_BAD_REQUEST
        is_checked = False

        follow_user = User.objects.filter(id=request.data.get('follow_id')).first()

        if not follow_user:
            response_message = {'400 - 2': 'follow 할 상대가 존재하지 않습니다.'}
            return response_message, status_code, is_checked

        follow = Following.objects.filter(following_user=follow_user, user=request.user).first()

        if follow is None:
            if follow_user == request.user:
                response_message = {'message': '자신을 follow할 순 없습니다.'}
                status_code = status.HTTP_200_OK
                is_checked = True
            elif 'Insta-left' in follow_user.email and not follow_user.is_active:
                response_message = {'message': '이미 탈퇴한 회원입니다.'}
                status_code = status.HTTP_200_OK
                is_checked = True
            else:
                Following.objects.create(
                    following_user=follow_user,
                    user=request.user
                )
                response_message = {'message': f'{request.user}님이 {follow_user}님을 follow 하였습니다.'}
                status_code = status.HTTP_201_CREATED
                is_checked = True
            return response_message, status_code, is_checked
        else:
            follow.delete()
            response_message = {'message': f'{request.user}님이 {follow_user}님을 follow 취소 하였습니다.'}
            return response_message, status_code, is_checked

    def create(self, request, *args, **kwargs):
        """
        팔로우 추가

        ---
        ## use/follow
        """
        try:
            response_message, status_code, is_checked = self.params_validate(request)
            if is_checked:
                response_message, status_code, is_checked = self.follow_create(request)
            return Response(
                data=response_message if is_checked else response_message,
                status=status_code if is_checked else status_code
            )
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)
