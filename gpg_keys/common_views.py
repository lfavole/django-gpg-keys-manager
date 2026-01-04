"""Common views for GPG key management: base classes for AJAX form handling and multiple form handling."""

from typing import Any, ClassVar

from django import forms
from django.core.exceptions import PermissionDenied
from django.core.handlers.exception import response_for_exception
from django.http import (
    Http404,
    HttpRequest,
    HttpResponse,
    HttpResponsePermanentRedirect,
    HttpResponseRedirect,
    JsonResponse,
)
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _
from django.views.generic.edit import FormView

from .utils import is_xhr


# taken from allauth:
# https://codeberg.org/allauth/django-allauth/src/commit/5baeee79/allauth/account/mixins.py
class AjaxFormView(FormView):
    """
    A mixin that can be used to render form views that respond with JSON when the request is an JSON or AJAX request.

    The JSON response includes the form HTML, form data, and any
    additional data provided by overriding `get_ajax_data`.
    """

    def get_ajax_data(self) -> Any:  # noqa: ANN401, PLR6301
        """
        Return additional data to include in the AJAX response. Override this method to provide custom data.

        Returns:
            A dictionary of additional data to include in the AJAX response.

        """
        return None

    def ajax_response(
        self,
        request: HttpRequest,
        response: HttpResponse,
        form: forms.Form | None = None,
        data: Any = None,  # noqa: ANN401
    ) -> JsonResponse | HttpResponse:
        """
        Return an AJAX response if the request is an XMLHttpRequest, otherwise return the original response.

        Args:
            request: The HTTP request.
            response: The original HTTP response.
            form: The form instance or exception to include in the response.
            data: Additional data to include in the response.

        Returns:
            A JsonResponse if the request is an XMLHttpRequest, otherwise the original response.

        """
        if not is_xhr(request):
            return response

        resp = {}
        status = response.status_code

        if isinstance(response, (HttpResponseRedirect, HttpResponsePermanentRedirect)):
            status = 200
            resp["location"] = response["Location"]

        if form:
            status = 200
            if isinstance(form, Http404):
                status = 404
            elif isinstance(form, PermissionDenied):
                status = 403
            elif request.method == "POST" and not form.is_valid():
                status = 400

            resp["form"] = self.ajax_response_form(form)
            if hasattr(response, "render"):
                response.render()
            resp["html"] = response.content.decode("utf8")

        if data is not None:
            resp["data"] = data

        return JsonResponse(resp, status=status)

    @staticmethod
    def ajax_response_form(form: forms.Form | Exception) -> dict:
        """
        Return a JSON-serializable representation of the form.

        Returns:
            A dictionary containing the form's fields, field order, and non-field errors.

        """
        if isinstance(form, Exception):
            return {"fields": {}, "field_order": [], "errors": [force_str(form)]}
        form_spec = {
            "fields": {},
            "field_order": [],
            "errors": form.non_field_errors(),
        }
        for field in form:
            field_spec = {
                "label": force_str(field.label),
                "value": field.value(),
                "help_text": force_str(field.help_text),
                "errors": [force_str(e) for e in field.errors],
                "widget": {"attrs": {k: force_str(v) for k, v in field.field.widget.attrs.items()}},
            }
            form_spec["fields"][field.html_name] = field_spec
            form_spec["field_order"].append(field.html_name)
        return form_spec

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:  # noqa: ANN401
        """
        Wrap dispatch to catch PermissionDenied and Http404 exceptions and return an AJAX response if needed.

        Returns:
            An HttpResponse object.

        Raises:
            PermissionDenied: if the user does not have permission to access the view.
            Http404: if the requested resource is not found.

        """
        try:
            return super().dispatch(request, *args, **kwargs)
        except (PermissionDenied, Http404) as err:
            if is_xhr(request):
                # Render the response and pass it to the middleware
                return self.ajax_response(self.request, response_for_exception(request, err), form=err)
            raise

    def get(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        """
        Handle GET requests: instantiate a blank version of the form.

        Returns:
            An HttpResponse object.

        """
        response = super().get(request, *args, **kwargs)
        form = self.get_form()
        return self.ajax_response(self.request, response, form=form, data=self.get_ajax_data())

    def post(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:  # noqa: ARG002
        """
        Handle POST requests: instantiate a form instance and pass it to the form valid/invalid methods.

        Returns:
            An HttpResponse object.

        """
        form = self.get_form()
        response = self.form_valid(form) if form.is_valid() else self.form_invalid(form)
        return self.ajax_response(self.request, response, form=form, data=self.get_ajax_data())


FORM_IS_VALID = object()


class MultipleFormView(FormView):
    """
    A view that displays and handles multiple forms on a single page.

    Attributes:
        form_classes: A dictionary mapping form classes to a dictionary of action names
            and their corresponding handler method names.

    """

    form_classes: ClassVar[dict[type[forms.Form], dict[str, str]]] = {}

    def get_form_class(self) -> type[forms.Form]:
        """
        Return the first form class as a default.

        Returns:
            The first form class in the form_classes dictionary.

        """
        return next(iter(self.form_classes))

    @staticmethod
    def _snake_case(name: str) -> str:
        return "".join(["_" + c.lower() if c.isupper() else c for c in name]).lstrip("_")

    def get(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:  # noqa: ARG002
        """
        Handle GET requests: instantiate a blank version of all forms.

        Returns:
            An HttpResponse object.

        """
        context = {self._snake_case(form_class.__name__): form_class() for form_class in self.form_classes}
        response = self.render_to_response(self.get_context_data(**context))
        if isinstance(self, AjaxFormView):
            form = next(iter(context.values()))
            return self.ajax_response(self.request, response, form=form, data=self.get_ajax_data())
        return response

    def post(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:  # noqa: ARG002
        """
        Handle POST requests: check if an action was triggered for a form, and call the corresponding handler method.

        Returns:
            An HttpResponse object.

        """
        context = {self._snake_case(form_class.__name__): form_class() for form_class in self.form_classes}
        # We need a form for the form_valid and form_invalid views so we take the first one
        # (because it contains the errors) and if it hasn't been created, we use the first one
        form = next(iter(context.values()))
        response = None

        # Try to instantiate each form class
        for form_class, actions in self.form_classes.items():
            # Find if a corresponding action was triggered
            try:
                action = next(word for word in actions if word in request.POST or request.POST.get("action") == word)
            except StopIteration:
                continue

            # Trigger the action
            form = form_class(**self.get_form_kwargs())
            if form.is_valid():
                # Try to run the custom handler, add the errors if needed
                method = getattr(self, actions[action])
                try:
                    ret = method(form)
                except forms.ValidationError as e:
                    form.add_error(None, e)
                    ret = None
                # Set the response to return when the form is valid
                # or use a placeholder to use the default one
                response = ret or FORM_IS_VALID

            context[self._snake_case(form_class.__name__)] = form
            break
        else:
            # No action was selected
            if is_xhr(request):
                # Force the form to be valid, return the data just like a GET request
                form.is_bound = True
                form._errors = {}  # noqa: SLF001
                response = FORM_IS_VALID
            else:
                # Create cleaned_data
                form.cleaned_data = {}
                form.add_error(None, _("No action selected."))
                response = self.form_invalid(form)

        if response is None:
            response = self.render_to_response(self.get_context_data(**context))

        if response is FORM_IS_VALID:
            response = self.form_valid(form)

        if isinstance(self, AjaxFormView):
            return self.ajax_response(self.request, response, form=form, data=self.get_ajax_data())
        return response
