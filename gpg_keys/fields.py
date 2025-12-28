import pgpy
from django import forms
from django.db import models
from django.utils.functional import Promise

from .models import GPGKey, TemporaryGPGKey
from .utils import get_request


class PGPKeyField(models.TextField):
    description = "A field to store PGP public keys"

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return value.strip()

    def validate(self, value, model_instance):
        super().validate(value, model_instance)
        if value is None:
            return
        try:
            pgpy_key, _ = pgpy.PGPKey.from_blob(value)
        except Exception as e:
            raise ValueError(f"Invalid PGP public key: {e}")

    def formfield(self, **kwargs):
        defaults = {"form_class": forms.CharField}
        defaults.update(kwargs)
        return super().formfield(**defaults)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        return name, path, args, kwargs

    def value_to_string(self, obj):
        value = self.value_from_object(obj)
        return self.get_prep_value(value)

    def to_python(self, value):
        if isinstance(value, str) or value is None:
            return value.strip() if value else value
        raise ValueError("This field only accepts string values.")

    def clean(self, value, model_instance):
        value = super().clean(value, model_instance)


class KeyFieldMixin:
    def __init__(self, *args, **kwargs):
        temporary = kwargs.pop("temporary", False)

        # Find the neeeded queryset (temporary or not)
        self.queryset_class = TemporaryGPGKey if temporary else GPGKey

        self.filter = kwargs.pop("filter", None)

        super().__init__(None, *args, **kwargs)

    @property
    def queryset(self):
        if self._queryset is not None:
            return self._queryset

        req = get_request()
        if req is None or req.user.is_anonymous:
            queryset = self.queryset_class.objects.none()
        else:
            queryset = self.queryset_class.objects.filter(user=req.user)
            if self.filter:
                if isinstance(self.filter, dict):
                    queryset = queryset.filter(**self.filter)
                else:
                    queryset = queryset.filter(self.filter)

        self.queryset = queryset
        return queryset

    @queryset.setter
    def queryset(self, queryset):
        self._queryset = None if queryset is None else queryset.all()
        if queryset is not None:
            self.widget.choices = self.choices

    # https://github.com/SmileyChris/django-countries/commit/ed870d76
    @property
    def choices(self):
        """
        When it's time to get the choices, if it was a lazy then figure it out
        now and memoize the result.
        """
        if hasattr(self, "_choices"):
            if isinstance(self._choices, Promise):
                self._choices = list(self._choices)
            return self._choices
        self.choices = self.iterator(self)
        return self._choices

    @choices.setter
    def choices(self, value):
        self._choices = value


class GPGKeyField(KeyFieldMixin, forms.ModelChoiceField):
    pass


class MultipleGPGKeyField(KeyFieldMixin, forms.ModelMultipleChoiceField):
    pass
