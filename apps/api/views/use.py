from rest_framework import viewsets, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.api.serializers.use import PostSerializer
from core.use.models import Post


class PostsViewSet(viewsets.ModelViewSet):
    """
    list: 게시물 목록 조회
    """
    serializer_class = PostSerializer
    authentication_classes = [SessionAuthentication]
    permission_classes = ''

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


class PostViewSet(viewsets.ModelViewSet):
    """
    create: 게시물 생성
    update: 게시물 수정
    delete: 게시물 삭제
    """
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    def params_validate(self, request):
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

    def params_patch_validate(self, request):
        request_data = request.data
        is_params_checked = True
        response_message = {}
        status_code = status.HTTP_200_OK

        photo = request_data.get('photo')
        content = request_data.get('content')

        # photo, content 두개뿐임

    def post_patch(self, request):
        request_data = request.data
        is_checked = False
        status_code = status.HTTP_400_BAD_REQUEST
        try:
            pass
        except Exception as e:
            pass

    def create(self, request, *args, **kwargs):
        """
        게시물 생성

        ---
        ## /use/post/
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

    def partial_update(self, request, *args, **kwargs):
        """
        게시물 수정

        ---
        ## /use/post/
        """
        pass

    def destroy(self, request, *args, **kwargs):
        """
        게시물 삭제

        ---
        ## /use/post/
        """
        pass
