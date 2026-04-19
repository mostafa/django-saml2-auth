from django.urls import include, path

from django_saml2_auth import views as saml_views

urlpatterns = [
    path("sso/", include(("django_saml2_auth.urls", "django_saml2_auth"))),
    path("signin/", saml_views.signin, name="integration_signin"),
    path("signout/", saml_views.signout, name="integration_signout"),
]
