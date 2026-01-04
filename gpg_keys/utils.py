"""Utility functions for GPG key management."""

import inspect
from http import HTTPStatus
from urllib.parse import quote, urlparse
from urllib.request import urlopen

import pgpy
from django.conf import settings
from django.db import models
from django.http import HttpRequest

from .models import GPGKey, TemporaryGPGKey


def get_request() -> HttpRequest | None:
    """
    Return the first HttpRequest instance found in stack frames' local variables.

    Walks back the call stack looking for a local variable named 'request' that is
    an instance of `django.http.HttpRequest`.

    Returns:
        An HttpRequest instance if found, otherwise None.

    """
    frame = inspect.currentframe()
    try:
        f = frame.f_back
        while f is not None:
            req = f.f_locals.get("request")
            if isinstance(req, HttpRequest):
                return req
            f = f.f_back
    finally:
        # Help GC
        del frame
    return None


class KeyDownloadError(Exception):
    """Custom exception for key download errors."""


DEFAULT_KEYSERVERS = ["keys.openpgp.org"]


def download_key(key_id_or_email: str, key_server: str = DEFAULT_KEYSERVERS[0]) -> pgpy.PGPKey:
    """
    Download a public GPG key from a keyserver given a key ID or email.

    Args:
        key_id_or_email: The key ID or email address to search for.
        key_server: The keyserver URL to use.

    Returns:
        The downloaded PGPKey object.

    Raises:
        KeyDownloadError: If the key cannot be downloaded.

    """
    parse_result = urlparse(key_server)
    key_server = parse_result.hostname or parse_result.path
    try:
        with urlopen(f"https://{key_server}/pks/lookup?op=get&options=mr&search={quote(key_id_or_email)}") as response:
            if response.status != HTTPStatus.OK:
                msg = f"Failed to download key: HTTP {response.status}"
                raise KeyDownloadError(msg)  # noqa: TRY301
            key_data = response.read().decode("utf-8")
            public_key, _ = pgpy.PGPKey.from_blob(key_data)
            return public_key  # Return the PGPKey object
    except Exception as e:
        msg = f"An error occurred while downloading the key: {e}"
        raise KeyDownloadError(msg) from e


def search_and_add_keys(
    emails: list[str | models.Model] | models.QuerySet,
    default_user: models.Model | None = None,
) -> tuple[int, int]:
    """
    Given an iterable of EmailAddress instances or email strings, search keyservers and add TemporaryGPGKey objects.

    Returns:
        A (keys_added, keys_skipped) tuple.

    """
    keys_added = 0
    keys_skipped = 0
    manager = getattr(GPGKey, "_base_manager", GPGKey.objects)

    for item in emails:
        email = str(item)
        user = default_user
        try:
            from allauth.account.models import EmailAddress  # noqa: PLC0415
        except ImportError:
            pass
        else:
            if isinstance(item, EmailAddress):
                email = item.email
                user = item.user

        for keyserver in getattr(settings, "GPG_KEYSERVERS", DEFAULT_KEYSERVERS):
            try:
                public_key = download_key(email, key_server=keyserver)
                break
            except KeyDownloadError:
                continue
        else:
            continue

        temp_key = TemporaryGPGKey.from_blob(str(public_key))

        if manager.filter(fingerprint=temp_key.fingerprint).exists():
            keys_skipped += 1
            continue

        temp_key.user = user
        temp_key.save()
        keys_added += 1

    return keys_added, keys_skipped


if "allauth" in settings.INSTALLED_APPS:
    from allauth.account.models import EmailAddress
    from allauth.account.signals import email_added, email_changed, email_removed

    def handle_added_email(query: str | models.Q | list | tuple) -> tuple[int, int]:
        """
        Resolve `query` into a queryset of EmailAddress and delegate to search_and_add_keys.

        Returns:
            A tuple (keys_added, keys_skipped).

        """
        eas = EmailAddress.objects.all()
        if isinstance(query, models.Q):
            eas = eas.filter(query)
        elif isinstance(query, (list, tuple)):
            eas = eas.filter(email__in=query)
        else:
            eas = eas.filter(email=query)

        return search_and_add_keys(eas)

    def handle_removed_email(email_address: str | EmailAddress) -> None:
        """Remove any TemporaryGPGKey objects that were associated only with the given email address."""
        if isinstance(email_address, EmailAddress):
            email_address = email_address.email
        # Remove any TemporaryGPGKey that has this email if no EmailAddress exists with this email
        temporary_keys = TemporaryGPGKey.objects.filter(emails__contains=email_address.lower())
        keys_to_remove_pks = []
        for key in temporary_keys:
            emails = key.emails.split("\n")
            # Filter and keep only where an associated EmailAddress exists
            # Optimize the query, do only one query
            emails = [email.email for email in EmailAddress.objects.filter(email__in=emails)]
            if not emails:
                keys_to_remove_pks.append(key.pk)

        if keys_to_remove_pks:
            TemporaryGPGKey.objects.filter(pk__in=keys_to_remove_pks).delete()

    if getattr(settings, "GPG_AUTO_FETCH_KEYS_FROM_KEYSERVERS", False):
        email_added.connect(lambda email_address, **_: handle_added_email(email_address))
        email_changed.connect(lambda to_email_address, **_: handle_added_email(to_email_address))

    email_changed.connect(lambda from_email_address, **_: handle_removed_email(from_email_address))
    email_removed.connect(lambda email_address, **_: handle_removed_email(email_address))


def is_xhr(request: HttpRequest) -> bool:
    """
    Determine if the request is an XMLHttpRequest (AJAX) or a curl request.

    Returns:
        True if the request is an XMLHttpRequest or a curl request, False otherwise.

    """
    return (
        request.headers.get("x-requested-with") == "XMLHttpRequest"
        or request.headers.get("accept") == "application/json"
        or is_curl(request)
    )


def is_curl(request: HttpRequest) -> bool:
    """
    Determine if the request was made using curl.

    Returns:
        True if the request was made using curl, False otherwise.

    """
    return request.headers.get("user-agent", "").lower().startswith("curl/")


def terminal_border_message(message: str) -> str:
    """
    Return a message string wrapped in a border for terminal display.

    Returns:
        The bordered message string.

    """
    border = "+" + "-" * (len(message) + 2) + "+"
    return f"{border}\n| {message} |\n{border}"
