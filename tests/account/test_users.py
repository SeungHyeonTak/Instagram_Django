from tests.tests import Test
from apps.api.views.account import SignupViewSet, WithdrawalViewSet
from core.account.models import User, UserEmailAuthentication


class UsersTest(Test):
    """유저에 관련된 테스트"""

    def setUp(self):
        super().setUp()

    def test_signup(self):
        """회원가입 성공"""
        print('[회원가입] 성공')
        self.request.data = {
            'email': 'testSignup@test.com',
            'password': '1234qwer',
            'username': '테스트회원가입',
            'fullname': '테스트계정회원가입',
            'phone': '01033334444',
            'gender': 2,
        }
        user_signup = SignupViewSet()
        message, status, is_checked = user_signup.signup(self.request)

        self.assertEqual(True, is_checked)

    def test_signup_email_overlap(self):
        """회원가입 이메일 중복일때"""
        print('[회원가입] 이메일 중복')
        user_signup = SignupViewSet()

        self.request.data = {
            'email': 'testSignup@test.com',
            'password': '1234qwer',
            'username': '테스트회원가입1',
            'fullname': '테스트계정회원가입1',
            'phone': '01033334441',
            'gender': 2,
        }
        user_signup.signup(self.request)

        self.request.data = {
            'email': 'testSignup@test.com',
            'password': '1234qwer',
            'username': '테스트회원가입2',
            'fullname': '테스트계정회원가입2',
            'phone': '01033334442',
            'gender': 2,
        }
        message, status, is_checked = user_signup.signup(self.request)

        self.assertEqual(False, is_checked)
        self.assertEqual('400 - 3', '400 - 3' if '400 - 3' in message.keys() else '0')

    def test_signup_phone_overlap(self):
        """회원가입 휴대폰 번호 중복일때"""
        print('[회원가입] 휴대폰 번호 중복')
        user_signup = SignupViewSet()

        self.request.data = {
            'email': 'testSignup1@test.com',
            'password': '1234qwer',
            'username': '테스트회원가입1',
            'fullname': '테스트계정회원가입1',
            'phone': '01033334441',
            'gender': 2,
        }
        user_signup.signup(self.request)

        self.request.data = {
            'email': 'testSignup2@test.com',
            'password': '1234qwer',
            'username': '테스트회원가입2',
            'fullname': '테스트계정회원가입2',
            'phone': '01033334441',
            'gender': 2,
        }

        message, status, is_checked = user_signup.signup(self.request)

        self.assertEqual(False, is_checked)
        self.assertEqual('400 - 6', '400 - 6' if '400 - 6' in message.keys() else '0')

    def test_signup_left_email_id_overlap(self):
        """
        회원가입시 사용할 수 없는 이메일 ID
        -> 회원탈퇴시 사용자 정보 보호에 따라 email ID가 'Insta-left{pk}' 로 변경됨
        """
        print("[회원가입] 사용할 수 없는 email ID")

        user_signup = SignupViewSet()

        self.request.data = {
            'email': 'Insta-left1231@test.com',
            'password': '1234qwer',
            'username': '테스트회원가입',
            'fullname': '테스트계정회원가입',
            'phone': '01033334444',
            'gender': 2,
        }
        message, status, is_checked = user_signup.signup(self.request)

        self.assertEqual(False, is_checked)
        self.assertEqual('400 - 5', '400 - 5' if '400 - 5' in message.keys() else '0')

    def test_signup_username_overlap(self):
        """회원가입 계정이름이 중복일때"""
        print("[회원가입] 계정이름 중복")
        user_signup = SignupViewSet()

        self.request.data = {
            'email': 'testSignup1@test.com',
            'password': '1234qwer',
            'username': '테스트회원가입1',
            'fullname': '테스트계정회원가입1',
            'phone': '01033334441',
            'gender': 2,
        }
        user_signup.signup(self.request)

        self.request.data = {
            'email': 'testSignup2@test.com',
            'password': '1234qwer',
            'username': '테스트회원가입1',
            'fullname': '테스트계정회원가입2',
            'phone': '01033334441',
            'gender': 2,
        }

        message, status, is_checked = user_signup.signup(self.request)

        self.assertEqual(False, is_checked)
        self.assertEqual('400 - 4', '400 - 4' if '400 - 4' in message.keys() else '0')

    def test_signup_email_check_overlap(self):
        """회원가입 이메일 형식이 잘못되었을때"""
        print("[회원가입] 이메일 형식이 잘못되었을때")
        user_signup = SignupViewSet()

        self.request.data = {
            'email': 'abcdefg',
            'password': '1234qwer',
            'username': '테스트회원가입1',
            'fullname': '테스트계정회원가입2',
            'phone': '01033334441',
            'gender': 2,
        }

        message, status, is_checked = user_signup.signup(self.request)

        self.assertEqual(False, is_checked)
        self.assertEqual('400 - 2', '400 - 2' if '400 - 2' in message.keys() else '0')

    def test_signup_activate(self):
        """회원가입 후 email 인증 코드 생성"""
        print('[회원가입] 이메일 인증코드 생성 확인')
        user_signup = SignupViewSet()

        self.request.data = {
            'email': 'testSignup1@test.com',
            'password': '1234qwer',
            'username': '테스트회원가입1',
            'fullname': '테스트계정회원가입1',
            'phone': '01033334441',
            'gender': 2,
        }

        message, status, is_checked = user_signup.signup(self.request)

        if is_checked:
            user = User.objects.get(email=self.request.data.get('email'))
            user_code = UserEmailAuthentication.objects.filter(user=user).exists()
        else:
            user, user_code = None, None

        self.assertEqual(True, user_code)

    def test_withdrawal(self):
        """회원탈퇴 성공"""
        print('[회원탈퇴] 성공')
        user_signup = SignupViewSet()
        user_withdrawal = WithdrawalViewSet()

        self.request.data = {
            'email': 'testSignup1@test.com',
            'password': '1234qwer',
            'username': '테스트회원가입1',
            'fullname': '테스트계정회원가입1',
            'phone': '01033334441',
            'gender': 2,
        }
        reason = '탈퇴 테스트'

        message, status, is_checked = user_signup.signup(self.request)

        if is_checked:
            user = User.objects.get(email=self.request.data.get('email'))
        else:
            user = None

        message, status, is_checked = user_withdrawal.withdrawal(user, reason=reason)
        self.assertEqual(True, is_checked)
        self.assertEqual(f'Insta-left{user.pk}@instagram.com', user.email)
        self.assertEqual(False, user.is_active)

    # def test_signin(self):
    #     """로그인 성공"""
    #     print('로그인 성공')
    #
    # def test_signin_email_check(self):
    #     """로그인 이메일 틀렸을때"""
    #     print('로그인 이메일 틀림')
    #
    # def test_user_is_active(self):
    #     """사용자 계정 비활성화"""
    #     print('사용자 계정 비활성화 일때')
