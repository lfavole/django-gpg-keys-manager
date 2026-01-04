"""Views for the GPG Keys application."""

from typing import TYPE_CHECKING, ClassVar

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import redirect_to_login
from django.db.models import Q
from django.forms import Form
from django.http import HttpRequest, HttpResponse
from django.middleware.csrf import CsrfViewMiddleware
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.utils.translation import ngettext
from django.views.decorators.csrf import csrf_exempt

from .common_views import AjaxFormView, MultipleFormView
from .forms import (
    AddPublicKeyForm,
    AddTemporaryPublicKeysForm,
    ManagePublicKeysForm,
    SearchPublicKeysForm,
    VerifyKeyForm,
)
from .models import GPGKey
from .utils import is_curl, is_xhr, search_and_add_keys

if TYPE_CHECKING:
    import pgpy


@method_decorator(login_required, name="dispatch")
class PublicKeysFormView(MultipleFormView, AjaxFormView):
    """A form to manage public GPG keys."""

    template_name = "gpg_keys/public_keys.html"
    success_url = reverse_lazy("gpg_keys_list")

    form_classes: ClassVar[dict[type[Form], dict[str, str]]] = {
        SearchPublicKeysForm: {
            "search": "search_public_keys",
        },
        AddTemporaryPublicKeysForm: {
            "add_temporary": "add_temporary_public_keys",
        },
        ManagePublicKeysForm: {
            "remove": "remove_public_key",
            "primary": "set_primary_key",
            "verify": "verify_public_key",
        },
        AddPublicKeyForm: {
            "add": "add_public_key",
        },
    }

    def get_ajax_data(self) -> dict[str, list[dict]]:
        """
        Return the list of public keys for the current user.

        Returns:
            A dictionary containing the list of public keys.

        """
        return {
            "keys": [
                {
                    "fingerprint": key.fingerprint,
                    "emails": key.emails.split("\n"),
                    "primary": key.primary,
                    "verified": key.verified,
                }
                for key in GPGKey.objects.filter(user=self.request.user)
            ],
        }

    def search_public_keys(self, form: Form) -> None:  # noqa: ARG002
        """Search for public keys in public keyservers and add them as temporary keys."""
        if self.request.user.is_anonymous:
            return
        try:
            from .utils import handle_added_email  # noqa: PLC0415 (avoid import loop)
        except ImportError:
            keys_added, keys_skipped = search_and_add_keys([self.request.user.email], self.request.user)
        else:
            keys_added, keys_skipped = handle_added_email(Q(user=self.request.user))
        if not is_xhr(self.request):
            message = []
            if keys_added:
                message.append(
                    ngettext(
                        "Added %(keys_added)d public key from your verified email address.",
                        "Added %(keys_added)d public keys from your verified email addresses.",
                        keys_added,
                    )
                    % {"keys_added": keys_added}
                )
            if keys_skipped:
                message.append(
                    ngettext(
                        "Skipped %(keys_skipped)d already existing public key.",
                        "Skipped %(keys_skipped)d already existing public keys.",
                        keys_skipped,
                    )
                    % {"keys_skipped": keys_skipped}
                )
            if message:
                messages.success(self.request, " ".join(message))

    def add_temporary_public_keys(self, form: Form) -> None:  # noqa: PLR6301
        """Add a temporary public key: remove its temporary attribute."""
        form.cleaned_data["keys"].update(temporary=False)

    def add_public_key(self, add_form: Form) -> None:
        """Add a new public key."""
        public_key: GPGKey = add_form.cleaned_data["public_key"]

        public_key.save()

        if not is_xhr(self.request):
            messages.success(self.request, _("Public key added successfully."))

    def remove_public_key(self, form: Form) -> None:
        """Remove an existing public key."""
        selected_key: GPGKey = form.cleaned_data["key"]

        selected_key.delete()

        if not is_xhr(self.request):
            messages.success(self.request, _("Public key removed successfully."))

    def set_primary_key(self, form: Form) -> None:  # noqa: D102
        selected_key: GPGKey = form.cleaned_data["key"]

        selected_key.primary = True
        selected_key.save()

        if not is_xhr(self.request):
            messages.success(self.request, _("Primary key set successfully."))

    def verify_public_key(self, form: Form) -> HttpResponse:  # noqa: PLR6301
        """
        Start the verification process for the given public key by redirecting to the corresponding page.

        Returns:
            An HttpResponse object.

        """
        selected_key: GPGKey = form.cleaned_data["key"]

        return redirect("gpg_keys_verify", selected_key.pk)


@method_decorator(csrf_exempt, name="dispatch")
class VerifyKeyView(AjaxFormView):
    """A form to verify public GPG keys."""

    template_name = "gpg_keys/verify_key.html"
    form_class = VerifyKeyForm
    success_url = reverse_lazy("gpg_keys_list")

    def __init__(self, *args, **kwargs) -> None:
        """Initialize a new VerifyKeyView instance."""
        super().__init__(*args, **kwargs)
        self._key = None
        self._raw_post = False

    def get_ajax_data(self) -> dict:
        """
        Return the verification status for the given public key.

        Returns:
            A dictionary containing the verification status.

        """
        if not self.key:
            return super().get_ajax_data()

        if is_xhr(self.request) and self.request.GET.get("check") and self.key.verified:
            messages.success(self.request, _("Key %(key)s verified successfully.") % {"key": self.key})

        return {
            "name": str(self.key),
            "fingerprint": self.key.fingerprint,
            "verified": self.key.verified,
            "verification_command": self.key.verification_command,
            "verification_message": self.key.verification_message,
        }

    def get_form_kwargs(self) -> dict:
        """
        Return the keyword arguments for the form: if the request body is a raw signed message, use it directly.

        Returns:
            The updated default keyword arguments.

        """
        kwargs = super().get_form_kwargs()

        self._raw_post = False
        if self.request.method == "POST":
            try:
                data = {"signed_message": self.request.body.decode()}
            except UnicodeDecodeError:
                pass
            else:
                if self.get_form_class()(data).is_valid():
                    kwargs["data"] = data
                    self._raw_post = True

        return kwargs

    @property
    def key(self) -> GPGKey | None:
        """
        The key to verify, if it's inferred from the request (e.g. by validating the form for a specific key).

        It's useful to detect the usage of a wrong key.
        """
        if self._key is not None:
            return self._key
        if self.request.user.is_anonymous:
            return None
        pk = self.kwargs.get("pk")
        if not pk:
            return None
        self.key = get_object_or_404(GPGKey, id=pk, user=self.request.user)
        return self._key

    @key.setter
    def key(self, value: GPGKey) -> None:
        self._key = value

    def get_context_data(self, **kwargs) -> dict:
        """
        Add the key variable to the context.

        Returns:
            The updated template context.

        """
        kwargs = super().get_context_data(**kwargs)

        if "key" not in kwargs:
            kwargs["key"] = self.key

        return kwargs

    def get(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        """
        Handle GET requests: return a verification form or redirect to the management page if the key is verified.

        Returns:
            An HttpResponse object.

        """
        if self.key and self.key.verified and not is_xhr(self.request):
            messages.info(self.request, _("Key %(key)s is already verified.") % {"key": self.key})

            # Redirect, do not display the success message
            return super().form_valid(self.get_form_class()())

        if self.request.user.is_anonymous:
            # redirect to the login page
            return redirect_to_login(request.build_absolute_uri())

        return super().get(request, *args, **kwargs)

    def post(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        """
        Handle POST requests and call form_valid to verify the key.

        Returns:
            An HttpResponse object.

        """
        if self.key and self.key.verified:
            if is_curl(self.request):
                return HttpResponse(_("The key is already verified, no need to resubmit"))

            if not is_xhr(self.request):
                if not self.request.GET.get("verified"):
                    messages.info(self.request, _("Key %(key)s is already verified.") % {"key": self.key})

                # Redirect, do not display the success message
                return super().form_valid(self.get_form_class()())

        # check if the request is a raw POST request (body = signed message)
        _kwargs = self.get_form_kwargs()
        if not self._raw_post:
            if self.request.user.is_anonymous:
                # redirect to the login page
                return login_required(lambda: None)(request)
            ret = CsrfViewMiddleware(lambda: None).process_view(request, None, (), {})
            if ret:
                return ret
        return super().post(request, *args, **kwargs)

    def form_valid(self, form: Form) -> HttpResponse:
        """
        Process the form: attempt to verify the key and return a form_invalid response if the verification failed.

        Returns:
            An HttpResponse object.

        """
        signed_message: pgpy.PGPMessage = form.cleaned_data["signed_message"]

        # Find the key
        # If it isn't provided, figure it from the fingerprint
        # Don't verify ownership because it might be called from curl (without cookies)
        # And who bothers if you use another key? You wouldn't get the message to sign anyway
        if not self.key:
            self.key = get_object_or_404(GPGKey, fingerprint=signed_message.signatures[0].signer_fingerprint)

        # Check if the key is the correct one
        # It will only happen from the web interface
        if self.key.fingerprint != signed_message.signatures[0].signer_fingerprint:
            form.add_error("signed_message", _("The message is not signed by the provided key."))
            return self.form_invalid(form)

        if self.key.verification_message != signed_message.message:
            form.add_error("signed_message", _("The message does not match the verification message."))
            return self.form_invalid(form)

        try:
            verified = self.key.pgpy.verify(signed_message)
        except Exception as e:  # noqa: BLE001
            msg = _("Error during verification: %s")
            form.add_error("signed_message", msg % (e,))
            return self.form_invalid(form)

        if not verified:
            form.add_error("signed_message", _("The signature could not be verified."))
            return self.form_invalid(form)

        self.key.verified = True
        self.key.save()

        if not is_xhr(self.request):
            messages.success(self.request, _("Key %(key)s verified successfully.") % {"key": self.key})

        if is_curl(self.request):
            return HttpResponse(_("The key is now verified, check your browser"))

        return super().form_valid(form)
