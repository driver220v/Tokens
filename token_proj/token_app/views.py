from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.db.models import Q
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework import permissions
from rest_framework.views import APIView

from token_app.serializer import UserSerializer
from django.conf import settings
import redis
from rest_framework import status
from rest_framework.response import Response
import secrets
# Connect to our Redis instance
from token_proj.settings import REDIS_PASSWORD

# todo видел что в редисе есть опция db она отвечает за одновременно обслуживание баз данных
#  пеочпему в тутриалах установления инстанса коннекшена к редимс db=0?
redis_instance = redis.StrictRedis(host=settings.REDIS_HOST,
                                   port=settings.REDIS_PORT, db=0,
                                   password=REDIS_PASSWORD)


class CreateUserView(APIView):
    permission_classes = [
        permissions.AllowAny  # Or anon users can't register
    ]
    serializer_class = UserSerializer
    queryset = User.objects

    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.create(serializer.validated_data)
            if not user.is_authenticated:
                login(request, user)
            content = {
                'user': serializer.validated_data['username'],
                'password': serializer.validated_data['password']
            }
            return Response(content, status.HTTP_200_OK)
        else:
            return Response(serializer._errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    def get(self, request, *args, **kwargs):
        user = request.user
        if user.is_authenticated:
            logout(request)
            return Response(status.HTTP_200_OK)
        return Response(status.HTTP_200_OK)


class AuthToken(APIView):
    # todo смотрел в документацию не понимаю для чего здесь authentication_classes
    #   как правильно сделать аутинтификацию ?
    authentication_classes = [SessionAuthentication, BasicAuthentication]

    def get(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        # token, который дейтсивтелен в течении 900 секунд
        try:
            User.objects.filter(Q(password=password) & Q(username=username))
        except User.DoesNotExist:
            return Response({'user': 'None'}, status=status.HTTP_400_BAD_REQUEST)
        user_token = secrets.token_hex(32)
        redis_instance.set(name=user_token, value=secrets.token_hex(32), ex=900)
        redis_instance.get(name=user_token)
        content = {
            'token': user_token,
        }
        return Response(content, status=status.HTTP_200_OK)


class SomeBackendView(APIView):
    # todo как проверять headers?
    #  отправлять content-type: application/json а на строне бэкенда все проверять
    def post(self, request, *args, **kwargs):
        try:
            user_token = request.data.get('Token')
        except Exception as e:
            return Response({'error': 'No Token was provided'})

        token = redis_instance.get(name=user_token)
        if token is None:
            content = {'error': 'Token expired'}
            return Response(content, status.HTTP_401_UNAUTHORIZED)
        else:
            content = {'message': 'you may send anything you want'}
            return Response(content, status.HTTP_200_OK)
