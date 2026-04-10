"""Utility functions for dealing with various parts of the library.
E.g. creating SAML client, creating user, exception handling, etc.
"""

import base64
import binascii
import json
from functools import wraps
from importlib import import_module
import logging
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple, Union

from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import NoReverseMatch, reverse
from django.utils.module_loading import import_string
from django_saml2_auth.errors import (
    EMPTY_FUNCTION_PATH,
    GENERAL_EXCEPTION,
    IMPORT_ERROR,
    NO_REVERSE_MATCH,
    PATH_ERROR,
)
from django_saml2_auth.exceptions import SAMLAuthError
from django_saml2_auth.get_path import get_path

# Keys removed from SAMLAuthError.extra before rendering error.html (avoid leaking raw exceptions).
_ERROR_TEMPLATE_STRIP_EXTRA_KEYS = frozenset({"exc", "exc_type"})


def run_hook(
    function_path: str,
    *args: Optional[Tuple[Any]],
    **kwargs: Optional[Mapping[str, Any]],
) -> Optional[Any]:
    """Runs a hook function with given args and kwargs. For example, given
    "models.User.create_new_user", the "create_new_user" function is imported from
    the "models.User" module and run with args and kwargs. Functions can be
    imported directly from modules, without having to be inside any class.

    Args:
        function_path (str): A path to a hook function,
            e.g. models.User.create_new_user (static method)

    Raises:
        SAMLAuthError: function_path isn't specified
        SAMLAuthError: There's nothing to import. Check your hook's import path!
        SAMLAuthError: Import error
        SAMLAuthError: Re-raise any exception caused by the called function

    Returns:
        Optional[Any]: Any result returned from running the hook function. None is returned in case
            of any exceptions, errors in arguments and related issues.
    """
    if not function_path:
        raise SAMLAuthError(
            "function_path isn't specified",
            extra={
                "exc_type": ValueError,
                "error_code": EMPTY_FUNCTION_PATH,
                "reason": "There was an error processing your request.",
                "status_code": 500,
            },
        )

    path = function_path.split(".")
    if len(path) < 2:
        # Nothing to import
        raise SAMLAuthError(
            "There's nothing to import. Check your hook's import path!",
            extra={
                "exc_type": ValueError,
                "error_code": PATH_ERROR,
                "reason": "There was an error processing your request.",
                "status_code": 500,
            },
        )

    module_path = ".".join(path[:-1])
    result = None
    try:
        cls = import_module(module_path)
    except ModuleNotFoundError:
        try:
            cls = import_string(module_path)
        except ImportError as exc:
            raise SAMLAuthError(
                str(exc),
                extra={
                    "exc": exc,
                    "exc_type": type(exc),
                    "error_code": IMPORT_ERROR,
                    "reason": "There was an error processing your request.",
                    "status_code": 500,
                },
            )
    try:
        result = getattr(cls, path[-1])(*args, **kwargs)
    except SAMLAuthError as exc:
        # Re-raise the exception
        raise exc
    except AttributeError as exc:
        raise SAMLAuthError(
            str(exc),
            extra={
                "exc": exc,
                "exc_type": type(exc),
                "error_code": IMPORT_ERROR,
                "reason": "There was an error processing your request.",
                "status_code": 500,
            },
        )
    except Exception as exc:
        raise SAMLAuthError(
            str(exc),
            extra={
                "exc": exc,
                "exc_type": type(exc),
                "error_code": GENERAL_EXCEPTION,
                "reason": "There was an error processing your request.",
                "status_code": 500,
            },
        )

    return result


def get_reverse(objects: Union[Any, Iterable[Any]]) -> Optional[str]:
    """Given one or a list of views/urls(s), returns the corresponding URL to that view.

    Args:
        objects (Union[Any, Iterable[Any]]): One or many views/urls representing a resource

    Raises:
        SAMLAuthError: We got a URL reverse issue: [...]

    Returns:
        Optional[str]: The URL to the resource or None.
    """
    if not isinstance(objects, (list, tuple)):
        objects = [objects]

    for obj in objects:
        try:
            return reverse(obj)
        except NoReverseMatch:
            pass
    raise SAMLAuthError(
        f"We got a URL reverse issue: {str(objects)}",
        extra={
            "exc_type": NoReverseMatch,
            "error_code": NO_REVERSE_MATCH,
            "reason": "There was an error processing your request.",
            "status_code": 500,
        },
    )


def exception_handler(
    function: Callable[..., Union[HttpResponse, HttpResponseRedirect]],
) -> Callable[..., Union[HttpResponse, HttpResponseRedirect]]:
    """This decorator can be used by view function to handle exceptions

    Args:
        function (Callable[..., Union[HttpResponse, HttpResponseRedirect]]):
            View function to decorate

    Returns:
        Callable[..., Union[HttpResponse, HttpResponseRedirect]]:
            Decorated view function with exception handling
    """

    if get_path(settings.SAML2_AUTH, "DISABLE_EXCEPTION_HANDLER", False):
        return function

    def handle_exception(exc: Exception, request: HttpRequest) -> HttpResponse:
        """Render page with exception details

        Args:
            exc (Exception): An exception
            request (HttpRequest): Incoming http request object

        Returns:
            HttpResponse: Rendered error page with details
        """
        logger = logging.getLogger(__name__)
        if get_path(settings.SAML2_AUTH, "DEBUG", False):
            # Log the exception with traceback
            logger.exception(exc)
        else:
            # Log the exception without traceback
            logger.debug(exc)

        context: Optional[Dict[str, Any]] = None
        if isinstance(exc, SAMLAuthError) and exc.extra:
            context = {
                k: v
                for k, v in exc.extra.items()
                if k not in _ERROR_TEMPLATE_STRIP_EXTRA_KEYS
            }
        else:
            context = {}

        if isinstance(exc, SAMLAuthError) and exc.extra:
            status = exc.extra.get("status_code")
        else:
            status = 500

        return render(request, "django_saml2_auth/error.html", context=context, status=status)

    @wraps(function)
    def wrapper(request: HttpRequest) -> HttpResponse:
        """Decorated function is wrapped and called here

        Args:
            request ([type]): [description]

        Returns:
            HttpResponse: Either a redirect or a response with error details
        """
        result = None
        try:
            result = function(request)
        except (SAMLAuthError, Exception) as exc:
            result = handle_exception(exc, request)
        return result

    return wrapper


# Upper bound on RelayState / compact-JWT string length for shape-only checks (DoS mitigation).
JWT_WELL_FORMED_MAX_INPUT_CHARS = 65536


def _decode_jwt_b64url_segment(segment: str) -> bytes:
    """Decode a JWS compact-serialization segment (base64url, RFC 7515)."""
    padding = -len(segment) % 4
    return base64.urlsafe_b64decode(segment + ("=" * padding))


def is_jwt_well_formed(token: Optional[str]) -> bool:
    """Return True if ``token`` looks like a JWS compact JWT (three base64url segments,
    JSON header and payload, header contains ``alg``).

    Used to tell whether ``RelayState`` is carrying a JWT vs a redirect URL/path. This does
    **not** verify signatures or claims — only structural shape.

    Args:
        token: Raw string (e.g. ``RelayState``), or None.

    Returns:
        True if the string matches JWS compact JWT shape, otherwise False.
    """
    if not isinstance(token, str):
        return False

    token = token.strip()
    if not token:
        return False

    if len(token) > JWT_WELL_FORMED_MAX_INPUT_CHARS:
        return False

    parts = token.split(".")
    if len(parts) != 3:
        return False

    header_b64, payload_b64, signature_b64 = parts
    if not header_b64 or not payload_b64:
        return False

    try:
        header_raw = _decode_jwt_b64url_segment(header_b64)
        payload_raw = _decode_jwt_b64url_segment(payload_b64)
        _decode_jwt_b64url_segment(signature_b64)
        header = json.loads(header_raw.decode("utf-8"))
        json.loads(payload_raw.decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return False

    if not isinstance(header, dict):
        return False

    alg = header.get("alg")
    if not isinstance(alg, str) or not alg.strip():
        return False

    return True
