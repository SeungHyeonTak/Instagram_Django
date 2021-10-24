# Instagram API Project

## project setup

### pyenv 

```shell
$ pyenv virtualenv 3.9.5 pyenv
```

```shell
$ pyenv local pyenv
```

이후 python interpreter에서 pyenv 설정 해주기

```shell
pip install -r requirements.txt
```

### 실행

```shell
$ ./manage.py runserver 127.0.0.1:8000 --settings=config.settings.local
```

## 기술 스택

- python 3.9.5
  - pyenv
- Django 3.2.3
- JWT
- PostgreSQL 13

## 구현사항

- 회원가입 [o]
- 회원탈퇴 [o]
- 로그인 [o]
- 로그아웃 [o]
- JWT [o]
- 유저 정보 보기 [o]
- 유저 정보 수정 [o]
- 게시물 작성 [o]
- 게시물 수정
- 게시물 삭제
- 게시물 목록 조회 [o]
- 게시물 좋아요
- 댓글 기능
- 댓글 좋아요
- 팔로우 기능
- account TDD [o]
- use TDD

