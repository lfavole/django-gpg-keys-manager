"""Models for GPG key management."""

import shlex
import uuid
from typing import ClassVar, Self

import pgpy
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _


class NotPublicKeyError(Exception):
    """Exception raised when a provided key is not a public key (for example, a private key)."""


class GPGKeyManager(models.Manager):
    """Custom manager for GPGKey model to filter out temporary keys by default."""

    def get_queryset(self) -> models.QuerySet:
        """
        Return a QuerySet filtering out temporary keys by default.

        Returns:
            QuerySet: A QuerySet of GPGKey objects excluding temporary keys.

        """
        return super().get_queryset().filter(temporary=False)


class GPGKey(models.Model):
    """A GPG public key associated with a user."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="gpg_keys",
        verbose_name=_("User"),
    )
    _public_key = models.TextField(_("Public key"), db_column="public_key", unique=True, blank=True)
    fingerprint = models.CharField(max_length=255, unique=True, blank=True)
    emails = models.TextField(blank=True)
    _verification_message = models.CharField(db_column="verification_message", max_length=255, blank=True)
    verified = models.BooleanField("Verified", default=False)
    primary = models.BooleanField("Primary", default=False)
    temporary = models.BooleanField("Temporary", default=False)

    objects = GPGKeyManager()

    class Meta:
        """Meta options for GPGKey model."""

        verbose_name = _("GPG key")
        verbose_name_plural = _("GPG keys")
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["user", "primary"],
                condition=models.Q(primary=True),
                name="unique_primary_key_per_user",
            ),
            models.UniqueConstraint(fields=["fingerprint"], name="unique_fingerprint"),
        ]

    def __str__(self) -> str:
        """
        Return the string representation of the GPGKey instance.

        Returns:
            str: A string representation of the GPGKey.

        """
        ret = [self.fingerprint[:8], *self.emails.split("\n"), "Vérifiée" if self.verified else "Non vérifiée"]
        if self.primary:
            ret.append("Principale")
        return " - ".join(ret)

    def __init__(self, *args, **kwargs) -> None:
        """Initialize GPGKey instance and create verification message if not present."""
        super().__init__(*args, **kwargs)
        _ = self.verification_message  # Create a verification message

    def save(self, *args, **kwargs) -> None:
        """Override save method to enforce primary key constraints."""
        if type(self) is GPGKey:
            if self.primary:
                # If this key is being set as primary, unset any existing primary keys for the user
                type(self).objects.filter(user=self.user, primary=True).exclude(pk=self.pk).update(primary=False)

            elif not type(self).objects.filter(user=self.user, primary=True).exists():
                # If no primary key exists for the user, set this key as primary
                self.primary = True

        super().save(*args, **kwargs)

    @property
    def verification_command(self) -> str:
        """
        The command the user should run to verify their key.

        Returns:
            str: The command to run for verification.

        Raises:
            ValueError: If the request context is not available.

        """
        if self.verified:
            return ""
        from .utils import get_request  # noqa: PLC0415 (avoid import loop)

        req = get_request()
        if req is None:
            msg = "Request context is not available for generating verification command."
            raise ValueError(msg)
        target_url = req.build_absolute_uri(reverse("gpg_keys_verify", args=(self.pk,)))

        return " | ".join([
            f"echo {shlex.quote(self.verification_message)}",
            f"gpg --local-user {shlex.quote(self.fingerprint)} --clearsign",
            f"curl -X POST --data-binary @- {shlex.quote(target_url)}",
        ])

    @property
    def public_key(self) -> str:
        """The public key associated with this GPG key."""
        return self._public_key

    @public_key.setter
    def public_key(self, value: str) -> None:
        self._public_key = value.strip()
        self.fingerprint = self.pgpy.fingerprint
        emails = []
        for uid in self.pgpy.userids:
            if uid.email and uid.email.lower() not in emails:
                emails.append(uid.email.lower())
        self.emails = "\n".join(emails)

    @property
    def verification_message(self) -> str:
        """The verification message associated with this GPG key."""
        if not self._verification_message:
            self._verification_message = str(uuid.uuid4())
            try:
                self.full_clean()
            except ValidationError:
                pass
            else:
                self.save()

        return self._verification_message

    @verification_message.setter
    def verification_message(self, value: str) -> None:
        self._verification_message = value

    @classmethod
    def from_blob(cls, public_key_data: str) -> Self:
        """
        Create a GPGKey instance from a public key blob.

        Returns:
            GPGKey: A GPGKey instance created from the provided public key data.

        """
        ret = cls(public_key=public_key_data)
        _ = ret.pgpy  # Check for errors
        return ret

    @property
    def pgpy(self) -> pgpy.PGPKey:
        """
        The PGPKey object associated with this GPG key.

        Returns:
            PGPKey: The PGPKey object.

        Raises:
            NotPublicKeyError: If the provided key is not a public key.

        """
        ret, _ = pgpy.PGPKey.from_blob(self.public_key)
        if not ret.is_public:
            raise NotPublicKeyError(_("The provided key is not a public key."))
        return ret

    # Add a handler when we edit the public_key field to update the fingerprint, emails, and names


class TemporaryGPGKeyManager(models.Manager):
    """Custom manager for TemporaryGPGKey model to filter only temporary keys."""

    def get_queryset(self) -> models.QuerySet:
        """
        Return a QuerySet fetching only temporary keys by default.

        Returns:
            QuerySet: A QuerySet of GPGKey objects containing only temporary keys.

        """
        return super().get_queryset().filter(temporary=True)


class TemporaryGPGKey(GPGKey):
    """A temporary GPG public key fetched from a keyserver but not yet added."""

    objects = TemporaryGPGKeyManager()

    class Meta:
        """Meta options for TemporaryGPGKey model."""

        verbose_name = _("Temporary GPG key")
        verbose_name_plural = _("Temporary GPG keys")
        proxy = True

    def __init__(self, *args, **kwargs) -> None:
        """Initialize GPGKey instance and mark it as temporary."""
        super().__init__(*args, **kwargs)
        self.temporary = True
