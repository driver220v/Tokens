from django.contrib import admin
from django.urls import path, include

from token_app.views import AuthToken, CreateUserView, LogoutView, SomeBackendView

urlpatterns = [
    path('', CreateUserView.as_view()),
    path('api-token-auth/', AuthToken.as_view()),
    path('logout/', LogoutView.as_view()),
    path('some-back/', SomeBackendView.as_view())
]
