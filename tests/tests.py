from django.test import TestCase
from django.http.request import HttpRequest
from django.contrib.sessions.backends.db import SessionStore
from core.account.models import User


class Test(TestCase):
    """공용 테스트 케이스"""

    user_email = 'test001@test.com'
    user_phone = '01000000000'
    user_username = '테스트계정001'
    user_fullname = '테스트001'

    user2_email = 'test002@test.com'
    user2_phone = '01012344321'
    user2_username = '테스트계정002'
    user2_fullname = '테스트002'

    def setUp(self) -> None:
        """테스트 환경을 위한 DB 세팅"""
        self.user = User(
            email=self.user_email,
            phone=self.user_phone,
            username=self.user_username,
            fullname=self.user_fullname,
            gender=1,
            introduction='테스트 계정 입니다.',
            is_active=True
        )
        self.user.set_password('1234qwer')
        self.user.save()

        self.user2 = User(
            email=self.user2_email,
            phone=self.user2_phone,
            username=self.user2_username,
            fullname=self.user2_fullname,
            gender=1,
            introduction='테스트 계정2 입니다.',
            is_active=True
        )
        self.user2.set_password('1234qwer')
        self.user2.save()

        self.request = HttpRequest()
        self.request.user = self.user
        session = SessionStore()
        self.request.session = session

        self.request2 = HttpRequest()
        self.request2.user2 = self.user2
        session2 = SessionStore()
        self.request2.session = session2
