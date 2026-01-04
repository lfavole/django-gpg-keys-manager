"""URL patterns for the gpg_keys app."""

from django.urls import path

from . import views

urlpatterns = [
    path("list", views.PublicKeysFormView.as_view(), name="gpg_keys_list"),
    path("verify/<int:pk>", views.VerifyKeyView.as_view(), name="gpg_keys_verify"),
]
