import shlex
import uuid

import pgpy
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _


class NotPublicKey(Exception):
    pass


class GPGKeyManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(temporary=False)


class GPGKey(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="gpg_keys", verbose_name=_("User")
    )
    _public_key = models.TextField(_("Public key"), db_column="public_key", unique=True, blank=True)
    fingerprint = models.CharField(max_length=255, unique=True, blank=True)
    emails = models.TextField(blank=True)
    _verification_message = models.CharField(db_column="verification_message", max_length=255, blank=True)
    verified = models.BooleanField("Verified", default=False)
    primary = models.BooleanField("Primary", default=False)
    temporary = models.BooleanField("Temporary", default=False)

    objects = GPGKeyManager()

    @property
    def verification_command(self):
        if self.verified:
            return ""
        from .utils import get_request  # avoid import loop

        req = get_request()
        if req is None:
            raise ValueError("Request context is not available for generating verification command.")
        target_url = req.build_absolute_uri(reverse("gpg_keys_verify", args=(self.id,)))

        return " | ".join(
            [
                f"echo {shlex.quote(self.verification_message)}",
                f"gpg --local-user {shlex.quote(self.fingerprint)} --clearsign",
                f"curl -X POST --data-binary @- {shlex.quote(target_url)}",
            ]
        )

    class Meta:
        verbose_name = _("GPG key")
        verbose_name_plural = _("GPG keys")
        constraints = [
            models.UniqueConstraint(
                fields=["user", "primary"], condition=models.Q(primary=True), name="unique_primary_key_per_user"
            ),
            models.UniqueConstraint(fields=["fingerprint"], name="unique_fingerprint"),
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _ = self.verification_message  # Create a verification message

    @property
    def public_key(self):
        return self._public_key

    @public_key.setter
    def public_key(self, value):
        self._public_key = value.strip()
        self.fingerprint = self.pgpy.fingerprint
        emails = []
        for uid in self.pgpy.userids:
            if uid.email and uid.email.lower() not in emails:
                emails.append(uid.email.lower())
        self.emails = "\n".join(emails)

    @property
    def verification_message(self):
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
    def verification_message(self, value):
        self._verification_message = value

    def save(self, *args, **kwargs):
        if type(self) is GPGKey:
            if self.primary:
                # If this key is being set as primary, unset any existing primary keys for the user
                type(self).objects.filter(user=self.user, primary=True).exclude(id=self.id).update(primary=False)

            elif not type(self).objects.filter(user=self.user, primary=True).exists():
                # If no primary key exists for the user, set this key as primary
                self.primary = True

        super().save(*args, **kwargs)

    @classmethod
    def from_blob(cls, public_key_data):
        ret = cls(public_key=public_key_data)
        ret.pgpy  # Check for errors
        return ret

    @property
    def pgpy(self) -> pgpy.PGPKey:
        ret, _ = pgpy.PGPKey.from_blob(self.public_key)
        if not ret.is_public:
            raise NotPublicKey(_("The provided key is not a public key."))
        return ret

    # Add a handler when we edit the public_key field to update the fingerprint, emails, and names

    def __str__(self):
        ret = [self.fingerprint[:8], *self.emails.split("\n"), "Vérifiée" if self.verified else "Non vérifiée"]
        if self.primary:
            ret.append("Principale")
        return " - ".join(ret)


class TemporaryGPGKeyManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(temporary=True)


class TemporaryGPGKey(GPGKey):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.temporary = True

    objects = TemporaryGPGKeyManager()

    class Meta:
        verbose_name = _("Temporary GPG key")
        verbose_name_plural = _("Temporary GPG keys")
        proxy = True
