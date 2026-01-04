"""Forms for GPG key management."""

import pgpy
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .fields import GPGKeyField, MultipleGPGKeyField
from .models import GPGKey
from .utils import get_request


class SearchPublicKeysForm(forms.Form):
    """Form for searching public GPG keys on keyservers."""


class AddTemporaryPublicKeysForm(forms.Form):
    """Form for adding temporary public GPG keys."""

    keys = MultipleGPGKeyField(temporary=True, to_field_name="fingerprint", widget=forms.CheckboxSelectMultiple)


class ManagePublicKeysForm(forms.Form):
    """Form for managing existing public GPG keys."""

    key = GPGKeyField(to_field_name="fingerprint", widget=forms.RadioSelect)


class AddPublicKeyForm(forms.Form):
    """Form for adding a new public GPG key."""

    public_key = forms.CharField(widget=forms.Textarea, label=_("Public key"))

    def clean_public_key(self) -> GPGKey:
        """
        Validate the provided public key and return it as a GPGKey object.

        Returns:
            A GPGKey object representing the public key.

        Raises:
            ValidationError: if the public key is invalid or does not meet the required criteria.

        """
        public_key = self.cleaned_data["public_key"]

        try:
            public_key = GPGKey.from_blob(public_key)
        except Exception as e:
            msg = _("Invalid public key: %s")
            raise ValidationError(msg % (e,)) from e

        emails = public_key.emails.split("\n")
        req = get_request()
        if req is None:
            msg = "Request context is not available for validating public key emails."
            raise ValidationError(msg)

        try:
            from allauth.account.models import EmailAddress  # noqa: PLC0415
        except ImportError:
            pass
        else:
            unverified_emails = EmailAddress.objects.filter(user=req.user, email__in=emails, verified=False)
            if unverified_emails:
                msg = _("This key contains the following unverified email addresses:\n%s")
                raise ValidationError(msg % (_(", ").join(email.email for email in unverified_emails),))

        public_key.user = req.user

        return public_key


class VerifyKeyForm(forms.Form):
    """Form for verifying ownership of a GPG key via a signed message."""

    signed_message = forms.CharField(widget=forms.Textarea)

    def clean_signed_message(self) -> pgpy.PGPMessage:
        """
        Validate the provided signed message and return it as a PGPMessage object.

        Returns:
            A PGPMessage object representing the signed message.

        Raises:
            ValidationError: if the signed message is invalid or does not meet the required criteria.

        """
        signed_message = self.cleaned_data["signed_message"]

        try:
            message: pgpy.PGPMessage = pgpy.PGPMessage.from_blob(signed_message)
        except Exception as e:
            msg = _("Invalid PGP message: %s")
            raise ValidationError(msg % (e,)) from e

        if not message.is_signed:
            raise ValidationError(_("The provided message is not signed."))

        if len(message.signers) > 1:
            raise ValidationError(_("The message has multiple signers, only one is allowed."))

        if not message.signers:
            raise ValidationError(_("The message has no signers."))

        return message
