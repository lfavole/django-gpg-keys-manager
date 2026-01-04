"""Apps configuration for the GPG Keys application."""

from django.apps import AppConfig


class GPGKeysConfig(AppConfig):
    """Configuration for the GPG Keys application."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "gpg_keys"
