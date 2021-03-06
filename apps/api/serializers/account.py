from rest_framework import serializers
from core.account.models import User, UserEmailAuthentication


class UserSerializer(serializers.HyperlinkedModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={
            'input_type': 'password',
            'placeholder': 'Password'
        }
    )

    class Meta:
        model = User
        fields = '__all__'


class UserEmailAuthenticationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserEmailAuthentication
        fields = ('security_code',)


class SigninSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={
            'input_type': 'password',
            'placeholder': 'Password'
        }
    )

    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'password',
        )


class SignoutSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ()


class WithdrawalSerializer(serializers.ModelSerializer):
    reason = serializers.CharField()

    class Meta:
        model = User
        fields = ('reason',)
