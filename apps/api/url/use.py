from django.urls import path

import apps.api.views.use as rest_views

app_name = 'use'

posts = rest_views.PostsViewSet.as_view({'get': 'list', 'post': 'create'})  # 게시물 리스트 조회, 게시물 생성
post = rest_views.PostViewSet.as_view(
    {'get': 'retrieve', 'patch': 'partial_update', 'delete': 'destroy'}
)  # 게시물 조회, 수정, 삭제

urlpatterns = [
    path('posts', posts, name='posts'),
    path('post/<int:pk>', post, name='post'),
]
