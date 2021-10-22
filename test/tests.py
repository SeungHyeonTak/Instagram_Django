from django.test import TestCase
from django.http.request import HttpRequest
from core.account.models import User


class Test(TestCase):
    """공용 테스트 케이스"""

    def setUp(self) -> None:
        """테스트 환경을 위한 DB 세팅"""
        self.user = User(
            email='test001@test.com',
            phone='01000000000',
            username='테스트계정001',
            fullname='테스트001',
            gender=1,
            introduction='테스트 계정 입니다.',
            is_active=True
        )
        self.user.set_password('1234qwer')
        self.user.save()

        self.user2 = User(
            email='test002@test.com',
            phone='01012344321',
            username='테스트계정002',
            fullname='테스트002',
            gender=1,
            introduction='테스트 계정2 입니다.',
            is_active=True
        )
        self.user2.set_password('1234qwer')
        self.user2.save()

        self.request = HttpRequest()
        self.request.user = self.user

        self.request2 = HttpRequest()
        self.request2.user2 = self.user2
