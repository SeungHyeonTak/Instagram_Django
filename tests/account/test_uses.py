from tests.tests import Test
from apps.api.views.use import *


class UsesTest(Test):
    """사용자가 사용할 기능에 대해 테스트"""

    def setUp(self):
        super().setUp()
        self.request.data = {
            'email': self.user_email,
            'phone': self.user_phone,
            'username': self.user_username,
            'password': self.user_password
        }

    def test_post1(self):
        """게시물 생성"""
        print('[게시물] 생성 성공')
        self.request.data = {
            'photo': 'test.png',
            'content': 'test content'
        }
        post = PostsViewSet()
        message, status, is_checked = post.post_create(self.request)
        self.assertEqual(True, is_checked)
        self.assertEqual(201, status)

    def test_post2(self):
        """게시물 생성 실패"""
        print('[게시물] 생성 실패')
        self.request.data = {
            'photo': '',
        }
        post = PostsViewSet()
        message, status, is_checked = post.post_create(self.request)
        self.assertEqual(False, is_checked)
        self.assertEqual('400 - 2', '400 - 2' if '400 - 2' in message.keys() else '0')
        self.assertEqual(400, status)

    def test_commend1(self):
        """댓글 작성"""
        print('[댓글] 작성 성공')
        self.request.data = {
            'photo': 'test.png'
        }
        post = PostsViewSet()
        post.post_create(self.request)
        test = Post.objects.all().first()

        self.request.data.update({
            'content': 'test 댓글'
        })

        comment = CommentViewSet()
        message, status, is_checked = comment.comment_create(self.request, test.pk)
        self.assertEqual(True, is_checked)
        self.assertEqual(201, status)

    def test_commend2(self):
        """댓글 작성 실패"""
        print('[댓글] 작성 실패')

        self.request.data.update({
            'content': 'test 댓글'
        })

        comment = CommentViewSet()
        message, status, is_checked = comment.comment_create(self.request, 2)
        self.assertEqual(False, is_checked)
        self.assertEqual(400, status)
        self.assertEqual('400 - 2', '400 - 2' if message.keys() else '0')
