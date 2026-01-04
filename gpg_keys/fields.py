"""Form fields for GPG keys management."""

from typing import Any

import pgpy
from django import forms
from django.db import models
from django.db.backends.base.base import BaseDatabaseWrapper
from django.utils.functional import Promise

from .models import GPGKey, TemporaryGPGKey
from .utils import get_request


class PGPKeyField(models.TextField):
    """A model field to store PGP public keys."""

    description = "A field to store PGP public keys"

    def from_db_value(  # noqa: PLR6301
        self,
        value: str | None,
        expression: models.Expression,  # noqa: ARG002
        connection: BaseDatabaseWrapper,  # noqa: ARG002
    ) -> str | None:
        """
        Strip spaces around the PGP key if it is present.

        Returns:
            The PGP key or None if no key is present.

        """
        if value is None:
            return value
        return value.strip()

    def validate(self, value: Any, model_instance: models.Model) -> None:  # noqa: ANN401
        """
        Check that the PGP key is correct.

        Raises:
            ValueError: if the PGP key is incorrect.

        """
        super().validate(value, model_instance)
        if value is None:
            return
        try:
            _pgpy_key, _ = pgpy.PGPKey.from_blob(value)
        except Exception as e:
            msg = f"Invalid PGP public key: {e}"
            raise ValueError(msg) from e

    def formfield(self, **kwargs) -> Any:  # noqa: ANN401
        """
        Return the form field that allows inputting a GPG key.

        Returns:
            The form field.

        """
        defaults = {"form_class": forms.CharField}
        defaults.update(kwargs)
        return super().formfield(**defaults)

    def value_to_string(self, obj: models.Model) -> Any:  # noqa: ANN401
        """
        Turn the value into a DB-compatible value.

        Returns:
            A value that can be stored in the database.

        """
        value = self.value_from_object(obj)
        return self.get_prep_value(value)

    def to_python(self, value: Any) -> str | None:  # noqa: ANN401, PLR6301
        """
        Validate the type of the variable.

        Returns:
            A normalized value.

        Raises:
            ValueError: if the value is not a string or None.

        """
        if isinstance(value, str) or value is None:
            return value.strip() if value else value
        msg = "This field only accepts string values."
        raise ValueError(msg)


class KeyFieldMixin:
    """Common functionality to GPGKeyField and MultipleGPGKeyField."""

    def __init__(self, *args, **kwargs) -> None:
        """Initialize a new GPGKeyField or MultipleGPGKeyField."""
        temporary = kwargs.pop("temporary", False)

        # Find the neeeded queryset (temporary or not)
        self.queryset_class = TemporaryGPGKey if temporary else GPGKey

        self.filter = kwargs.pop("filter", None)

        super().__init__(None, *args, **kwargs)  # pyright: ignore[reportCallIssue]

    @property
    def queryset(self) -> models.QuerySet:
        """The queryset to use to populate the field's choices."""
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
    def queryset(self, queryset: models.QuerySet) -> None:
        self._queryset = None if queryset is None else queryset.all()
        if queryset is not None:
            self.widget.choices = self.choices

    # https://github.com/SmileyChris/django-countries/commit/ed870d76
    @property
    def choices(self) -> list:
        """When it's time to get the choices, if it was a lazy then figure it out now and memoize the result."""
        if hasattr(self, "_choices"):
            if isinstance(self._choices, Promise):
                self._choices = list(self._choices)
            return self._choices
        self.choices = self.iterator(self)
        return self._choices

    @choices.setter
    def choices(self, value: list) -> None:
        self._choices = value


class GPGKeyField(KeyFieldMixin, forms.ModelChoiceField):
    """A field that allows a single GPG key."""


class MultipleGPGKeyField(KeyFieldMixin, forms.ModelMultipleChoiceField):
    """A field that allows multiple GPG keys."""
