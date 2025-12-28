from django.contrib import admin

from .models import GPGKey, TemporaryGPGKey


@admin.register(GPGKey)
class GPGKeyAdmin(admin.ModelAdmin):
    pass


@admin.register(TemporaryGPGKey)
class TemporaryGPGKeyAdmin(admin.ModelAdmin):
    pass
