import pgpy
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from .fields import GPGKeyField, MultipleGPGKeyField
from .models import GPGKey
from .utils import get_request


class SearchPublicKeysForm(forms.Form):
    pass


class AddTemporaryPublicKeysForm(forms.Form):
    keys = MultipleGPGKeyField(temporary=True, to_field_name="fingerprint", widget=forms.CheckboxSelectMultiple)


class ManagePublicKeysForm(forms.Form):
    key = GPGKeyField(to_field_name="fingerprint", widget=forms.RadioSelect)


class AddPublicKeyForm(forms.Form):
    public_key = forms.CharField(widget=forms.Textarea, label=_("Public key"))

    def clean_public_key(self):
        public_key = self.cleaned_data["public_key"]

        try:
            public_key = GPGKey.from_blob(public_key)
        except Exception as e:
            raise ValidationError(_("Invalid public key: %s") % (e,))

        emails = public_key.emails.split("\n")
        req = get_request()
        if req is None:
            raise ValidationError("Request context is not available for validating public key emails.")

        try:
            from allauth.account.models import EmailAddress
        except ImportError:
            pass
        else:
            unverified_emails = EmailAddress.objects.filter(user=req.user, email__in=emails, verified=False)
            if unverified_emails:
                raise ValidationError(
                    _("This key contains the following unverified email addresses:\n%s")
                    % (_(", ").join(email.email for email in unverified_emails),)
                )

        public_key.user = req.user

        return public_key


class VerifyKeyForm(forms.Form):
    signed_message = forms.CharField(widget=forms.Textarea)

    def clean_signed_message(self):
        signed_message = self.cleaned_data["signed_message"]

        try:
            message: pgpy.PGPMessage = pgpy.PGPMessage.from_blob(signed_message)
        except Exception as e:
            raise ValidationError(_("Invalid PGP message: %s") % (e,))

        if not message.is_signed:
            raise ValidationError(_("The provided message is not signed."))

        if len(message.signers) > 1:
            raise ValidationError(_("The message has multiple signers, only one is allowed."))

        if not message.signers:
            raise ValidationError(_("The message has no signers."))

        return message
