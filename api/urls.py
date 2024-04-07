# users/urls.py
from django.urls import path, re_path

from .views import Signup, Signin, Signout, GoogleSignup, GoogleSignin, FacebookSignup, FacebookSignin, PasswordChange
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
   openapi.Info(
      title="Your Project API",
      default_version='v1',
      description="API documentation for your project",
   ),
   public=True,
)


urlpatterns = [
    path('signup/', Signup.as_view(), name='signup'),
    path('signin/', Signin.as_view(), name='signin'),
    path('signout/', Signout.as_view(), name='signout'),
    path('social_signup/google/', GoogleSignup.as_view(), name='google_signup'),
    path('social_signup/facebook/', FacebookSignup.as_view(), name='facebook_signup'),
    path('social_signin/google/', GoogleSignin.as_view(), name='google_signin'),
    path('social_signin/facebook/', FacebookSignin.as_view(), name='facebook_signin'),
    path('password_change/', PasswordChange.as_view(), name='password_change'),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]

