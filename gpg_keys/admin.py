"""Admin configuration for GPG key models."""

from django.contrib import admin

from .models import GPGKey, TemporaryGPGKey


@admin.register(GPGKey)
class GPGKeyAdmin(admin.ModelAdmin):
    """Admin configuration for GPGKey model."""


@admin.register(TemporaryGPGKey)
class TemporaryGPGKeyAdmin(admin.ModelAdmin):
    """Admin configuration for TemporaryGPGKey model."""
