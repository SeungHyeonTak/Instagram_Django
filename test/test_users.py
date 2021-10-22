from .tests import Test


class UsersTest(Test):
    """유저에 관련된 테스트"""

    def setUp(self):
        super().setUp()

    def test_signup(self):
        """회원가입 성공"""
        print('회원가입 성공')

    def test_signup_email_overlap(self):
        """회원가입 이메일 중복일때"""
        print('회원가입 이메일 중복')

    def test_signup_phone_overlap(self):
        """회원가입 휴대폰 번호 중복일때"""
        print('회원가입 휴대폰 번호 중복')

    def test_withdrawal(self):
        """회원탈퇴 성공"""
        print('회원탈퇴 성공')

    def test_signin(self):
        """로그인 성공"""
        print('로그인 성공')

    def test_signin_email_check(self):
        """로그인 이메일 틀렸을때"""
        print('로그인 이메일 틀림')

    def test_user_is_active(self):
        """사용자 계정 비활성화"""
        print('사용자 계정 비활성화 일때')
