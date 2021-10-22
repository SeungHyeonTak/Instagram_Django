from django.urls import path

import apps.api.views.account as rest_views

app_name = 'account'

signup = rest_views.SignupViewSet.as_view({'post': 'create'})  # 회원가입
withdrawal = rest_views.WithdrawalViewSet.as_view({'patch': 'partial_update'})  # 회원탈퇴
signin = rest_views.SigninViewSet.as_view({'post': 'create'})  # 로그인
signout = rest_views.SignoutViewSet.as_view({'post': 'update'})  # 로그아웃
activate = rest_views.ActivateViewSet.as_view({'post': 'update'})  # 계정활성

urlpatterns = [
    path('signup/', signup, name='signup'),
    path('withdrawal/', withdrawal, name='withdrawal'),
    path('signin/', signin, name='signin'),
    path('signout/', signout, name='signout'),
    path('activate/', activate, name='activate'),
]