"""
Tests for utils.py
"""

import pytest
from django.http import HttpRequest, HttpResponse
from django.urls import NoReverseMatch
from pytest_django.fixtures import SettingsWrapper

from django_saml2_auth.exceptions import SAMLAuthError
from django_saml2_auth.utils import (
    JWT_WELL_FORMED_MAX_INPUT_CHARS,
    exception_handler,
    get_reverse,
    is_jwt_well_formed,
    run_hook,
)


def divide(a: int, b: int = 1) -> int:
    """Simple division function for testing run_hook

    Args:
        a (int): Dividend
        b (int, optional): Divisor. Defaults to 1.

    Returns:
        int: Quotient
    """
    return int(a / b)


def hello(_: HttpRequest) -> HttpResponse:
    """Simple view function for testing exception_handler

    Args:
        _ (HttpRequest): Incoming HTTP request (not used)

    Returns:
        HttpResponse: Outgoing HTTP response
    """
    return HttpResponse(content="Hello, world!")


def goodbye(_: HttpRequest) -> HttpResponse:
    """Simple view function for testing exception_handler

    Args:
        _ (HttpRequest): Incoming HTTP request (not used)

    Raises:
        SAMLAuthError: Goodbye, world!
    """
    raise SAMLAuthError(
        "Goodbye, world!",
        extra={
            "exc": RuntimeError("World not found!"),
            "exc_type": RuntimeError,
            "error_code": 0,
            "reason": "Internal world error!",
            "status_code": 500,
        },
    )


def test_run_hook_success():
    """Test run_hook function against divide function imported from current module."""
    result = run_hook("django_saml2_auth.tests.test_utils.divide", 2, b=2)
    assert result == 1


def test_run_hook_no_function_path():
    """Test run_hook function by passing invalid function path and checking if it raises."""
    with pytest.raises(SAMLAuthError) as exc_info:
        run_hook("")
        run_hook(None)

    assert str(exc_info.value) == "function_path isn't specified"


def test_run_hook_nothing_to_import():
    """Test run_hook function by passing function name only (no path) and checking if it raises."""
    with pytest.raises(SAMLAuthError) as exc_info:
        run_hook("divide")

    assert str(exc_info.value) == "There's nothing to import. Check your hook's import path!"


def test_run_hook_import_error():
    """Test run_hook function by passing correct path, but nonexistent function and
    checking if it raises."""
    with pytest.raises(SAMLAuthError) as exc_info:
        run_hook("django_saml2_auth.tests.test_utils.nonexistent_divide", 2, b=2)

    assert str(exc_info.value) == (
        "module 'django_saml2_auth.tests.test_utils' has no attribute 'nonexistent_divide'"
    )
    assert isinstance(exc_info.value.extra["exc"], AttributeError)
    assert exc_info.value.extra["exc_type"] is AttributeError


def test_run_hook_division_by_zero():
    """Test function imported by run_hook to verify if run_hook correctly captures the exception."""
    with pytest.raises(SAMLAuthError) as exc_info:
        run_hook("django_saml2_auth.tests.test_utils.divide", 2, b=0)

    assert str(exc_info.value) == "division by zero"
    # Actually a ZeroDivisionError wrapped in SAMLAuthError
    assert isinstance(exc_info.value.extra["exc"], ZeroDivisionError)
    assert exc_info.value.extra["exc_type"] is ZeroDivisionError


def test_get_reverse_success():
    """Test get_reverse with existing view."""
    result = get_reverse("acs")
    assert result == "/acs/"


def test_get_reverse_no_reverse_match():
    """Test get_reverse with nonexistent view."""
    with pytest.raises(SAMLAuthError) as exc_info:
        get_reverse("nonexistent_view")

    assert str(exc_info.value) == "We got a URL reverse issue: ['nonexistent_view']"
    assert issubclass(exc_info.value.extra["exc_type"], NoReverseMatch)


def test_exception_handler_success():
    """Test exception_handler decorator with a normal view function that returns response."""
    decorated_hello = exception_handler(hello)
    result = decorated_hello(HttpRequest())
    assert result.content.decode("utf-8") == "Hello, world!"


def test_exception_handler_handle_exception():
    """Test exception_handler decorator with a view function that raises exception and see if the
    exception_handler catches and returns the correct errors response."""
    decorated_goodbye = exception_handler(goodbye)
    result = decorated_goodbye(HttpRequest())
    contents = result.content.decode("utf-8")
    assert result.status_code == 500
    assert "Reason: Internal world error!" in contents


def test_exception_handler_diabled_success(settings: SettingsWrapper):
    """Test exception_handler decorator in disabled state with a valid function."""
    settings.SAML2_AUTH["DISABLE_EXCEPTION_HANDLER"] = True

    decorated_hello = exception_handler(hello)
    result = decorated_hello(HttpRequest())
    assert result.content.decode("utf-8") == "Hello, world!"


def test_exception_handler_disabled_on_exception(settings: SettingsWrapper):
    """Test exception_handler decorator in a disabled state to make sure it raises the
    exception."""
    settings.SAML2_AUTH["DISABLE_EXCEPTION_HANDLER"] = True

    decorated_goodbye = exception_handler(goodbye)
    with pytest.raises(SAMLAuthError):
        decorated_goodbye(HttpRequest())


# Minimal JWS compact shape: HS256 header, empty object payload, shortest valid signature segment.
_MINIMAL_JWS_COMPACT = "eyJhbGciOiJIUzI1NiJ9.e30.xx"


def test_jwt_well_formed():
    """Test if passed RelayState is a well formed JWT (JWS compact: header.payload.sig, JSON, alg)."""
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MjQyIiwibmFtZSI6Ikplc3NpY2EgVGVtcG9yYWwiLCJuaWNrbmFtZSI6Ikplc3MifQ.EDkUUxaM439gWLsQ8a8mJWIvQtgZe0et3O3z4Fd_J8o"  # noqa
    assert is_jwt_well_formed(token) is True
    assert is_jwt_well_formed(_MINIMAL_JWS_COMPACT) is True
    assert is_jwt_well_formed("/") is False
    assert is_jwt_well_formed("") is False
    assert is_jwt_well_formed(None) is False  # type: ignore[arg-type]
    assert is_jwt_well_formed("a.b") is False
    assert is_jwt_well_formed("not-base64.not-base64.not-base64") is False
    # Header decodes but is not JSON object with alg
    assert is_jwt_well_formed("YWFh.YWFh.YWFh") is False


@pytest.mark.parametrize(
    ("sample", "expected"),
    [
        # Leading / trailing whitespace around a valid compact JWT
        ("  eyJhbGciOiJIUzI1NiJ9.e30.xx  ", True),
        ("\teyJhbGciOiJIUzI1NiJ9.e30.xx\n", True),
        # Unicode in JSON payload (UTF-8)
        (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiAi4oKsIn0.xx",
            True,
        ),
        # Four segments (e.g. mistaken JWE or extra dot)
        ("a.b.c.d", False),
        # Empty or partial segments
        ("..xx", False),
        (".payload.sig", False),
        ("header..sig", False),
        # Header JSON is not an object (array / scalar / null)
        ("W10.e30.xx", False),
        ("MQ.e30.xx", False),
        ("bnVsbA.e30.xx", False),
        # Header object without alg (only typ)
        ("eyJ0eXAiOiAiSldUIn0.e30.xx", False),
        # alg present but not a non-empty string
        ("eyJhbGciOiAyNTZ9.e30.xx", False),
        ("eyJhbGciOiAiIn0.e30.xx", False),
        ("eyJhbGciOiAiICAgIn0.e30.xx", False),
        # Payload not valid JSON
        ("eyJhbGciOiJIUzI1NiJ9.YWFh.xx", False),
        # Signature segment cannot be base64url-decoded (library rejects 1-char body)
        ("eyJhbGciOiJIUzI1NiJ9.e30.x", False),
        # Whitespace-only after strip
        ("   \t\n  ", False),
        # Not a string
        (123, False),
        (b"bytes", False),
    ],
    ids=[
        "strip_spaces",
        "strip_tab_newline",
        "unicode_payload",
        "four_segments",
        "empty_header_and_payload",
        "empty_header",
        "empty_payload",
        "header_json_array",
        "header_json_number",
        "header_json_null",
        "header_typ_only",
        "alg_not_string",
        "alg_empty",
        "alg_whitespace_only",
        "payload_not_json",
        "signature_too_short_b64",
        "whitespace_only",
        "not_str_int",
        "not_str_bytes",
    ],
)
def test_is_jwt_well_formed_corner_cases(sample, expected):
    assert is_jwt_well_formed(sample) is expected


def test_is_jwt_well_formed_rejects_oversized_input():
    """Very long RelayState strings are rejected before decoding (DoS mitigation)."""
    assert is_jwt_well_formed("a" * (JWT_WELL_FORMED_MAX_INPUT_CHARS + 1)) is False
    # Under the limit but not JWT-shaped: cheap rejection, no crash
    assert is_jwt_well_formed("a" * JWT_WELL_FORMED_MAX_INPUT_CHARS) is False
