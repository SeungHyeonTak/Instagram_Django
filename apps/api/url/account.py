from django.urls import path
import apps.api.views.account as rest_views
from rest_framework_jwt.views import verify_jwt_token, refresh_jwt_token

app_name = 'account'

signup = rest_views.SignupViewSet.as_view({'post': 'create'})  # 회원가입
withdrawal = rest_views.WithdrawalViewSet.as_view({'patch': 'partial_update'})  # 회원탈퇴
signin = rest_views.SigninViewSet.as_view({'post': 'create'})  # 로그인
signout = rest_views.SignoutViewSet.as_view({'post': 'update'})  # 로그아웃
activate = rest_views.ActivateViewSet.as_view({'post': 'update'})  # 계정활성
information = rest_views.UserInformationViewSet.as_view({'get': 'list', "patch": "partial_update"})  # 유저 정보

urlpatterns = [
    path('signup', signup, name='signup'),
    path('withdrawal', withdrawal, name='withdrawal'),
    path('signin', signin, name='signin'),
    path('signout', signout, name='signout'),
    path('activate', activate, name='activate'),
    path('information', information, name='information'),
    path('token/verify', verify_jwt_token),  # token 유효성 검증
    path('token/refresh', refresh_jwt_token),  # token 갱신
]
