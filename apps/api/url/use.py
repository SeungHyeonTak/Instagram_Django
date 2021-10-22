from django.urls import path

import apps.api.views.use as rest_views

app_name = 'use'

posts = rest_views.PostsViewSet.as_view({'get': 'list'})  # 게시물 리스트 조회
post = rest_views.PostViewSet.as_view({'post': 'create', 'patch': 'partial_update', 'delete': 'destroy'})  # 게시물 생성

urlpatterns = [
    path('post/', post, name='post'),
    path('posts/', posts, name='posts'),
]
