"""
Callable paths for SAML2_AUTH.TRIGGER used by docker integration tests.

Each function records its name in ``hook_log`` so tests can assert the full
login pipeline exercised every hook.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict, List, Mapping, Optional, Union
from urllib.request import urlopen

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser

hook_log: List[str] = []
_custom_metadata_tempfiles: List[str] = []


def reset_hook_log() -> None:
    hook_log.clear()
    for path in _custom_metadata_tempfiles:
        try:
            os.unlink(path)
        except OSError:
            pass
    _custom_metadata_tempfiles.clear()


def _log(name: str) -> None:
    hook_log.append(name)


def get_metadata_autoconf_urls(user_id: Optional[str] = None) -> List[Dict[str, str]]:
    _log("GET_METADATA_AUTO_CONF_URLS")
    url = getattr(settings, "INTEGRATION_IDP_METADATA_URL", "")
    assert url, "INTEGRATION_IDP_METADATA_URL must be set for integration tests"
    return [{"url": url}]


def get_custom_metadata(
    user_id: Optional[str] = None,
    domain: Optional[str] = None,
    saml_response: Optional[str] = None,
) -> Mapping[str, Any]:
    """Alternate metadata path: download to a temp file and return ``{"local": [path]}``."""
    _log("GET_CUSTOM_METADATA")
    url = getattr(settings, "INTEGRATION_IDP_METADATA_URL", "")
    assert url
    raw = urlopen(url, timeout=15).read()
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.write(fd, raw)
    os.close(fd)
    _custom_metadata_tempfiles.append(path)
    return {"local": [path]}


def get_custom_assertion_url() -> str:
    _log("GET_CUSTOM_ASSERTION_URL")
    return "http://testserver/sso/acs/"


def get_user_id_from_saml_response(saml_response: str, user_id: Optional[str]) -> Optional[str]:
    _log("GET_USER_ID_FROM_SAML_RESPONSE")
    return user_id


def extract_user_identity(user: Dict[str, Any], authn_response: Any) -> Dict[str, Any]:
    _log("EXTRACT_USER_IDENTITY")
    out = dict(user)
    ui: Dict[str, Any] = out.get("user_identity") or {}
    if not out.get("email"):
        for key, vals in ui.items():
            if not vals:
                continue
            lk = key.lower()
            if "mail" in lk or lk.endswith("emailaddress") or lk.endswith("/email"):
                out["email"] = str(vals[0]).lower()
                break
    if not out.get("username"):
        out["username"] = out.get("email") or ""
    if out.get("email"):
        out["email"] = str(out["email"]).lower()
    if out.get("username"):
        out["username"] = str(out["username"]).lower()
    out["integration_marker"] = True
    return out


def get_user(user: Union[str, Dict[str, Any]]) -> Optional[AbstractBaseUser]:
    """Return None when no row exists so ``get_or_create_user`` can create the user."""
    _log("GET_USER")
    user_model = get_user_model()
    field = getattr(user_model, "USERNAME_FIELD", "username")
    try:
        if isinstance(user, dict):
            uid = user["email"] if field == "email" else user["username"]
            return user_model.objects.get(**{f"{field}__iexact": uid})
        return user_model.objects.get(**{f"{field}__iexact": str(user)})
    except user_model.DoesNotExist:
        return None


def create_user(user: Dict[str, Any]) -> None:
    _log("CREATE_USER")


def before_login(user: Dict[str, Any]) -> None:
    _log("BEFORE_LOGIN")


def after_login(session: Any, user: Dict[str, Any]) -> None:
    _log("AFTER_LOGIN")


def custom_create_jwt(user: AbstractBaseUser) -> str:
    _log("CUSTOM_CREATE_JWT")
    from django_saml2_auth.user import create_jwt_token

    user_model = get_user_model()
    uid = getattr(user, user_model.USERNAME_FIELD)  # type: ignore[misc]
    token = create_jwt_token(uid)
    assert token is not None
    return token


def custom_decode_jwt(token: str) -> Optional[str]:
    _log("CUSTOM_DECODE_JWT")
    from django_saml2_auth.user import decode_jwt_token

    return decode_jwt_token(token)


def custom_token_query(token: str) -> str:
    _log("CUSTOM_TOKEN_QUERY")
    return f"integration_token_flag=1&token={token}"


def get_custom_frontend_url(relay_state: Optional[str]) -> str:
    _log("GET_CUSTOM_FRONTEND_URL")
    return "https://app.example.com/saml-callback"


def trigger_paths() -> Dict[str, Optional[str]]:
    """All TRIGGER entries wired for the main end-to-end test."""
    base = "django_saml2_auth.tests.integration.hooks"
    return {
        "GET_METADATA_AUTO_CONF_URLS": f"{base}.get_metadata_autoconf_urls",
        "GET_CUSTOM_METADATA": None,
        "GET_CUSTOM_ASSERTION_URL": f"{base}.get_custom_assertion_url",
        "GET_USER_ID_FROM_SAML_RESPONSE": f"{base}.get_user_id_from_saml_response",
        "EXTRACT_USER_IDENTITY": f"{base}.extract_user_identity",
        "GET_USER": f"{base}.get_user",
        "CREATE_USER": f"{base}.create_user",
        "BEFORE_LOGIN": f"{base}.before_login",
        "AFTER_LOGIN": f"{base}.after_login",
        "CUSTOM_CREATE_JWT": f"{base}.custom_create_jwt",
        "CUSTOM_DECODE_JWT": f"{base}.custom_decode_jwt",
        "CUSTOM_TOKEN_QUERY": f"{base}.custom_token_query",
        "GET_CUSTOM_FRONTEND_URL": f"{base}.get_custom_frontend_url",
    }


def trigger_paths_custom_metadata_only() -> Dict[str, Optional[str]]:
    """Use GET_CUSTOM_METADATA instead of GET_METADATA_AUTO_CONF_URLS."""
    paths = trigger_paths()
    paths["GET_METADATA_AUTO_CONF_URLS"] = None
    paths["GET_CUSTOM_METADATA"] = "django_saml2_auth.tests.integration.hooks.get_custom_metadata"
    paths["GET_CUSTOM_ASSERTION_URL"] = None
    return paths
