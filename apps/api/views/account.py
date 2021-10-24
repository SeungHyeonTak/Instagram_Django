import datetime
import random

from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.core.mail import EmailMessage
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone
from rest_framework import viewsets, status, permissions
from rest_framework.response import Response
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.settings import api_settings

from apps.api.serializers.account import UserSerializer
from core.account.models import User, UserEmailAuthentication, Administrator, JWTokens


class SignupViewSet(viewsets.ModelViewSet):
    """
    create : 회원가입
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    authentication_classes = []
    permission_classes = []

    def send_active_mail(self, domain, uidb64, token):
        """회원가입 인증 메일 보내기"""
        return f'아래 링크를 클릭하면 회원가입 인증이 완료됩니다. \n\n ' \
               f'회원가입 링크 : http://{domain}/users/{uidb64}/{token}\n\n' \
               f'감사합니다.'

    def is_account_exist(self, **kwargs):
        """이메일 가입 여부 및 계정 이름 확인"""
        user_check = False
        for key, value in kwargs.items():
            if kwargs.get('email'):
                user_check = self.queryset.filter(email=value).values(key).exists()
            if kwargs.get('username'):
                user_check = self.queryset.filter(username=value).values(key).exists()
        return user_check

    def is_value_phone_check(self, phone):
        """휴대폰 번호 중복 체크"""
        is_phone = self.queryset.filter(phone=phone).exists()
        return is_phone

    def is_valid_email_check(self, email):
        """이메일 형식 체크"""
        try:
            validate_email(email)
            return True
        except Exception as e:
            print(f'이메일 형식 에러 : {e}')
            return False

    def params_validate(self, request):
        """파라미터 유효성 검사"""
        request_data = request.data
        loss_params = []
        is_params_checked = True
        response_message = {}
        status_code = status.HTTP_200_OK

        # 필수 파라미터 체크
        email = request_data.get('email', None)
        password = request_data.get('password', None)
        username = request_data.get('username', None)
        fullname = request_data.get('fullname', None)

        if email is None:
            loss_params.append('email')
        if password is None:
            loss_params.append('password')
        if username is None:
            loss_params.append('username')
        if fullname is None:
            loss_params.append('fullname')

        if loss_params:
            is_params_checked = False
            response_message = {'400 - 1': f'필수파라미터({",".join(loss_params)})가 없습니다.'}
            status_code = status.HTTP_400_BAD_REQUEST
            return response_message, status_code, is_params_checked

        return response_message, status_code, is_params_checked

    def email_send(self, user):
        """email 인증 확인"""
        user_email = UserEmailAuthentication.objects.filter(user__email=user.email).values('security_code').first()

        try:
            title = '[Instagram] 계정 활성화 이메일'
            content = f'인증번호는 {user_email["security_code"]} 입니다.'
            email = EmailMessage(title, content, to=[user.email])
            email.send()
        except Exception as e:
            print(f'email send Error : {e}')

    def signup(self, request):
        """회원가입을 위한 비지니스 로직"""
        request_data = request.data
        is_checked = False
        response_message = {}
        status_code = status.HTTP_400_BAD_REQUEST

        email = request_data.get('email')
        password = request_data.get('password')
        username = request_data.get('username')
        fullname = request_data.get('fullname')
        phone = request_data.get('phone', None)
        photo = request_data.get('photo', None)
        gender = request_data.get('gender', 0)
        web_site = request_data.get('web_site', None)
        introduction = request_data.get('introduction', None)

        if self.is_valid_email_check(email) is False:
            response_message = {'400 - 2': '입력하신 이메일 형식이 잘못되었습니다.'}
        elif 'Insta-left' in email:
            response_message = {'400 - 5': '입력하신 이메일 ID는 사용하실 수 없습니다.'}
        elif self.is_account_exist(email=email) is True:
            response_message = {'400 - 3': '입력하신 이메일로 가입된 계정이 존재합니다.'}
        elif self.is_account_exist(username=username) is True:
            response_message = {'400 - 4': '입력하신 계정이름이 존재합니다.'}
        elif self.is_value_phone_check(phone):
            response_message = {'400 - 6': '입력하신 휴대폰 번호는 사용중입니다.'}
        else:
            with transaction.atomic():
                user = User.objects.create(
                    email=email,
                    password=password,
                    username=username,
                    fullname=fullname,
                    phone=phone,
                    photo=photo,
                    gender=gender,
                    web_site=web_site,
                    introduction=introduction,
                )
                user.set_password(password)
                user.save()

                UserEmailAuthentication.objects.create(
                    user=user,
                    security_code=random.randrange(1111, 9999)  # 보안 코드
                )
            # 이메일 인증 처리 부분
            self.email_send(user)
            status_code = status.HTTP_200_OK
            response_message = {
                "pk": user.pk,
                "email": user.email
            }
            is_checked = True

        return response_message, status_code, is_checked

    def create(self, request, *args, **kwargs):
        """
        회원가입

        ---
        ## /account/signup/
        """
        try:
            response_message, status_code, is_checked = self.params_validate(request)
            if is_checked:
                response_message, status_code, is_checked = self.signup(request)
            return Response(
                data=response_message if is_checked else response_message,
                status=status_code if is_checked else status_code
            )
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)


class WithdrawalViewSet(viewsets.ModelViewSet):
    """
    partial_update : 회원탈퇴
    """
    queryset = User.objects.all()
    authentication_classes = [JSONWebTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]  # 인증된 사용자

    def params_validate(self, request):
        """파라미터 유효성 검사 (탈퇴이유)"""
        request_data = request.data
        is_params_checked = True
        reason = request_data.get('reason', None)
        return is_params_checked, reason

    def withdrawal(self, user, reason=''):  # 탈퇴 사유 적기
        """회원탈퇴를 위한 비지니스 로직 작성"""
        response_message = {}
        status_code = status.HTTP_403_FORBIDDEN

        now = timezone.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            user.email = f'Insta-left{user.pk}@instagram.com'
            user.username = '탈퇴계정'
            user.fullname = '탈퇴회원'
            user.gender = 0
            user.photo = None
            user.web_site = ''
            user.introduction = f'탈퇴 사유 : {reason} \n 탈퇴 날짜 : {now}'
            user.is_active = False
            user.save()

            is_checked = True
            status_code = status.HTTP_200_OK
        except Exception as e:
            print(f'회원탈퇴 Error : {e}')
            is_checked = False
            response_message = {'403': '회원 탈퇴에 실패하였습니다.'}

        return response_message, status_code, is_checked

    def partial_update(self, request, *args, **kwargs):
        """
        회원탈퇴

        ---
        ##  /account/withdrawal/
        """
        try:
            is_params_checked, reason = self.params_validate(request)
            if is_params_checked:
                response_message, status_code, is_checked = self.withdrawal(self.request.user, reason)
                request.session.flush()
                return Response(data=response_message, status=status_code)
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)


class SigninViewSet(viewsets.ModelViewSet):
    """
    create: 로그인
    """

    queryset = User.objects.all()
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def params_validate(self, request):
        """파라미터 유효성 검사"""
        request_data = request.data
        loss_params = []
        is_params_checked = True
        response_message = {}
        status_code = status.HTTP_400_BAD_REQUEST

        email = request_data.get('email', None)
        password = request_data.get('password', None)

        if email is None:
            loss_params.append('email')
        if password is None:
            loss_params.append('password')

        if loss_params:
            is_params_checked = False
            response_message = {'400 - 1': f'필수파라미터({",".join(loss_params)})가 없습니다.'}
            return response_message, status_code, is_params_checked

        return response_message, status_code, is_params_checked

    def signin(self, request):
        """로그인 비지니스 로직"""
        request_data = request.data
        is_checked = False
        response_message = {}
        status_code = status.HTTP_400_BAD_REQUEST

        email = request_data.get('email')
        password = request_data.get('password')

        if 'Insta-left' in email:
            response_message = {'400 - 3': '탈퇴한 회원입니다.'}
            return response_message, status_code, is_checked

        user = authenticate(email=email, password=password) if email and password else None

        if user is None:
            response_message = {
                '400 - 2': '이메일 또는 패스워드가 일치하지 않습니다.(회원 계정 활성을 위해 이메일 인증이 필요합니다.)'
            }
            return response_message, status_code, is_checked
        else:
            JWT_PAYLOAD_HANDLER = api_settings.JWT_PAYLOAD_HANDLER
            JWT_ENCODE_HANDLER = api_settings.JWT_ENCODE_HANDLER

            is_checked = True
            payload = JWT_PAYLOAD_HANDLER(user)
            jwt_token = JWT_ENCODE_HANDLER(payload)
            update_last_login(None, user)

            response_message.update({
                'email': user.email,
                'token': jwt_token
            })
            self.token_save(jwt_token, user)
            status_code = status.HTTP_200_OK
            return response_message, status_code, is_checked

    def token_save(self, jwt, user):
        """발급 token 저장"""
        try:
            token, is_token = JWTokens.objects.get_or_create(
                token=jwt,
                user=user
            )
            # print(is_token)
            # if not is_token:
            #     token.delete()
        except Exception as e:
            print(f'token 발급 실패 : {e}')

    def create(self, request, *args, **kwargs):
        """
        로그인

        ---
        ## /account/signin/
        """
        try:
            response_message, status_code, is_checked = self.signin(request)
            if is_checked:
                response_message, status_code, is_checked = self.signin(request)
            return Response(
                data=response_message if is_checked else response_message,
                status=status_code if is_checked else status_code
            )
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)


class SignoutViewSet(viewsets.ModelViewSet):
    """
    update: 로그아웃
    """
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated]

    def signout(self, request):
        """로그아웃 비지니스 로직"""
        is_checked = False
        response_message = {}
        status_code = status.HTTP_400_BAD_REQUEST

        if request.user.is_authenticated:
            is_logout = self.token_check(request.user)
            if not is_logout:
                response_message = {'401': '유효하지 않는 토큰 정보입니다.'}
                status_code = status.HTTP_401_UNAUTHORIZED
                return response_message, status_code, is_checked

            is_checked = True
            status_code = status.HTTP_200_OK
            return response_message, status_code, is_checked
        else:
            response_message = {'400': '유효하지 않은 정보 입니다.'}
            return response_message, status_code, is_checked

    def token_check(self, user):
        """
        로그아웃을 위한 token 체크 (중복 로그아웃 방지)
        """
        is_token = False
        auth_token = self.request.META.get('HTTP_AUTHORIZATION')
        bearer, jwt = auth_token.split(' ')
        token_search = JWTokens.objects.filter(token=jwt, user=user)
        if token_search:
            token_search.delete()
            is_token = True


        return is_token

    def update(self, request, *args, **kwargs):
        """
        로그아웃

        ---
        ## /account/signout/
        """
        try:
            response_message, status_code, is_checked = self.signout(request)
            return Response(
                data=response_message if is_checked else response_message,
                status=status_code if is_checked else status_code
            )
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)


class ActivateViewSet(viewsets.ModelViewSet):
    """
    update: 유저를 활성화한다. (email 인증 코드를 입력한 유저만 로그인 할 수 있다.)
    """
    queryset = UserEmailAuthentication.objects.all()
    authentication_classes = []
    permission_classes = []

    def params_validate(self, request):
        """파라미터 유효성 검사"""
        request_data = request.data
        is_params_checked = True
        status_code = status.HTTP_200_OK
        loss_params = []

        email = request_data.get('email', None)
        security_code = request_data.get('security_code', None)

        if email is None:
            loss_params.append('user_id')
        if security_code is None:
            loss_params.append('security_code')

        if security_code is None:
            is_params_checked = False
            response_message = {'400 - 1': '필수파라미터(security_code)가 없습니다.'}
            status_code = status.HTTP_200_OK
            return response_message, status_code, is_params_checked
        else:
            response_message = {
                'email': email,
                'security_code': security_code
            }

        return response_message, status_code, is_params_checked

    def activate(self, email, security_code):
        """email 인증 처리"""
        is_checked = False
        response_message = {'400 - 2': '이메일 인증코드가 잘못되었습니다.'}
        status_code = status.HTTP_400_BAD_REQUEST

        user = User.objects.filter(email=email).first()
        sec_code = self.queryset.filter(user=user).first()

        if user and sec_code.security_code == int(security_code):
            now = timezone.now()
            if sec_code.created_at + datetime.timedelta(minutes=3) >= now:
                is_checked = True

                sec_code.security_code = -1
                sec_code.verification = True
                sec_code.save()

                user.is_active = True
                user.save()

                response_message = {}
                status_code = status.HTTP_200_OK

        return response_message, status_code, is_checked

    def update(self, request, *args, **kwargs):
        try:
            response_message, status_code, is_checked = self.params_validate(request)
            if is_checked:
                email = response_message.get('email')
                security_code = response_message.get('security_code')
                response_message, status_code, is_checked = self.activate(email, security_code)
            return Response(
                data=response_message if is_checked else response_message,
                status=status_code if is_checked else status_code
            )
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)


class UserInformationViewSet(viewsets.ModelViewSet):
    """
    list: 유저정보 조회
    partial_update: 유저정보 수정
    """
    authentication_classes = [JSONWebTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    queryset = User.objects.all()

    def get_user_information(self, user):
        user_information = {}
        status_code = status.HTTP_403_FORBIDDEN
        token = self.request.META.get('HTTP_AUTHORIZATION')

        if user.is_authenticated and JWTokens.objects.filter(token=token, user=user).exists():
            email_auth = UserEmailAuthentication.objects.filter(user=user).first()

            user_information.update({
                "id": user.pk,
                "email": user.email,
                "phone": user.phone,
                "username": user.username,
                "fullname": user.fullname,
                "photo": user.photo.url if user.photo else None,
                "gender": user.gender,
                "web_site": user.web_site,
                "introduction": user.introduction,
                "is_active": user.is_active,
                "is_superuser": user.is_superuser,
                "user_email_authentication": {
                    "verification": email_auth.verification if email_auth else None
                }
            })
            if user.is_superuser:
                admin = Administrator.objects.filter(user=user).first()
                user_information.update({
                    "administrator": {
                        "type": '전체 관리자' if admin.type == 0 else '비지니스 관리자',
                        "is_active": admin.is_active
                    }
                })
            status_code = status.HTTP_200_OK
        else:
            user_information = {'403': '자격 인증 정보가 없어 유저 정보를 확인할 수 없습니다.'}

        return user_information, status_code

    def list(self, request, *args, **kwargs):
        """
        유저정보 조회

        ---
        ## /account/information/
        """
        try:
            user_information, status_code = self.get_user_information(self.request.user)
            return Response(data=user_information, status=status_code)
        except Exception as e:
            print(f'error : {e}')
            response_message = {'500': '서버 에러'}
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(data=response_message, status=status_code)

    # def partial_update(self, request, *args, **kwargs):
    #     """
    #     유저정보 수정
    #
    #     ---
    #     ## /account/information/
    #     """
    #     try:
    #         return Response()
    #     except Exception as e:
    #         print(f'error : {e}')
    #         response_message = {'500': '서버 에러'}
    #         status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    #         return Response(data=response_message, status=status_code)
