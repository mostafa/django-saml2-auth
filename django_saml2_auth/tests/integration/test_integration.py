"""
Docker-backed SAML integration tests (``django_saml2_auth.tests.integration``).

Includes metadata checks, ``GET_CUSTOM_METADATA``, and a full SP-initiated SAML
flow through ``signin`` → IdP → ``acs`` with every ``TRIGGER`` entry exercised.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from pytest_django.fixtures import SettingsWrapper

from django_saml2_auth.tests.integration import hooks
from django_saml2_auth.tests.integration.idp_flow import complete_simplesamlphp_login


def _fetch_metadata_xml(metadata_url: str) -> str:
    response = urlopen(metadata_url, timeout=10)
    assert response.status == 200
    return response.read().decode()


def _entity_ids_from_metadata_xml(xml_text: str) -> list[str]:
    root = ET.fromstring(xml_text)
    return [el.attrib["entityID"] for el in root.iter() if el.attrib.get("entityID")]


def _integration_saml2_auth(saml_idp_container: Dict[str, Any]) -> Dict[str, Any]:
    """SAML2_AUTH used for end-to-end tests (IdP + hooks + JWT redirect)."""
    triggers = hooks.trigger_paths()
    return {
        "DEFAULT_NEXT_URL": "https://app.example.com/",
        "CREATE_USER": True,
        "NEW_USER_PROFILE": {
            "USER_GROUPS": [],
            "ACTIVE_STATUS": True,
            "STAFF_STATUS": False,
            "SUPERUSER_STATUS": False,
        },
        "ASSERTION_URL": "http://testserver",
        "ENTITY_ID": "http://testserver/saml2-metadata",
        "FRONTEND_URL": "https://app.example.com/default-callback",
        "USE_JWT": True,
        "JWT_SECRET": "integration-test-secret",
        "JWT_EXP": 600,
        "JWT_ALGORITHM": "HS256",
        "TOKEN_REQUIRED": False,
        "LOGIN_CASE_SENSITIVE": False,
        "ALLOWED_REDIRECT_HOSTS": ["app.example.com"],
        "ATTRIBUTES_MAP": {
            "email": "email",
            "username": "email",
            "first_name": "first_name",
            "last_name": "last_name",
        },
        "AUTHN_REQUESTS_SIGNED": False,
        "WANT_ASSERTIONS_SIGNED": False,
        "WANT_RESPONSE_SIGNED": False,
        "TRIGGER": triggers,
    }


pytestmark = pytest.mark.integration


class TestSamlIntegrationMetadata:
    """IdP container smoke tests (no Django DB)."""

    def test_metadata_endpoint_is_reachable(self, saml_idp_container: Dict[str, Any]) -> None:
        content = _fetch_metadata_xml(saml_idp_container["metadata_url"])
        assert "<?xml version" in content
        assert "EntityDescriptor" in content

    def test_metadata_contains_entity_id_attribute(
        self, saml_idp_container: Dict[str, Any]
    ) -> None:
        content = _fetch_metadata_xml(saml_idp_container["metadata_url"])
        assert _entity_ids_from_metadata_xml(content)


@pytest.mark.urls("django_saml2_auth.tests.integration.urls")
@pytest.mark.django_db
class TestSaml2IntegrationAppE2E:
    """Full SP-initiated flow with all TRIGGER hooks (``integration.hooks``)."""

    def test_signin_acs_jwt_redirect_exercises_all_hooks(
        self,
        saml_idp_container: Dict[str, Any],
        settings: SettingsWrapper,
    ) -> None:
        hooks.reset_hook_log()
        settings.INTEGRATION_IDP_METADATA_URL = saml_idp_container["metadata_url"]
        settings.SAML2_AUTH = _integration_saml2_auth(saml_idp_container)

        client = Client(HTTP_HOST="testserver")
        r1 = client.get(
            "/signin/",
            {"next": "https://app.example.com/dashboard"},
            follow=False,
        )
        assert r1.status_code == 302, r1.content[:500]
        idp_url = r1["Location"]
        assert idp_url.startswith("http")

        saml_b64, relay = complete_simplesamlphp_login(
            idp_url, username="user1", password="user1pass"
        )
        post_data: Dict[str, Any] = {"SAMLResponse": saml_b64}
        if relay is not None:
            post_data["RelayState"] = relay

        r2 = client.post("/sso/acs/", post_data, follow=False)
        assert r2.status_code == 302, r2.content[:800]
        dest = r2["Location"]
        assert dest.startswith("https://app.example.com/saml-callback")
        q = parse_qs(urlparse(dest).query)
        assert "token" in q
        assert q.get("integration_token_flag") == ["1"]

        user_model = get_user_model()
        rows = list(user_model.objects.values("username", "email"))
        assert rows, f"expected a Django user after ACS; hooks={hooks.hook_log}"
        u = user_model.objects.get(username__iexact=rows[0]["username"])
        assert u.is_active
        principal = (u.get_username() or getattr(u, "email", "") or "").lower()
        assert "user" in principal and "example.com" in principal

        for name in (
            "GET_METADATA_AUTO_CONF_URLS",
            "GET_CUSTOM_ASSERTION_URL",
            "GET_USER_ID_FROM_SAML_RESPONSE",
            "EXTRACT_USER_IDENTITY",
            "CREATE_USER",
            "BEFORE_LOGIN",
            "AFTER_LOGIN",
            "CUSTOM_CREATE_JWT",
            "CUSTOM_TOKEN_QUERY",
            "GET_CUSTOM_FRONTEND_URL",
        ):
            assert name in hooks.hook_log, f"missing hook {name}; log={hooks.hook_log}"

        assert hooks.hook_log.count("GET_USER") >= 1

    def test_get_metadata_via_get_custom_metadata_downloads_tempfile(
        self,
        saml_idp_container: Dict[str, Any],
        settings: SettingsWrapper,
    ) -> None:
        hooks.reset_hook_log()
        settings.INTEGRATION_IDP_METADATA_URL = saml_idp_container["metadata_url"]
        base = _integration_saml2_auth(saml_idp_container)
        base["TRIGGER"] = hooks.trigger_paths_custom_metadata_only()
        base["METADATA_AUTO_CONF_URL"] = "http://ignored.invalid/metadata"
        settings.SAML2_AUTH = base

        from django_saml2_auth.saml import get_metadata, get_saml_client
        from django_saml2_auth.views import acs

        md = get_metadata()
        assert "local" in md and md["local"]
        path = md["local"][0]
        assert path.endswith(".xml")
        with open(path, encoding="utf-8") as f:
            xml = f.read()
        assert "EntityDescriptor" in xml

        client = get_saml_client("http://testserver", acs)
        assert client is not None
        assert "GET_CUSTOM_METADATA" in hooks.hook_log


@pytest.mark.django_db
def test_custom_decode_jwt_trigger_invokes_hook(settings: SettingsWrapper) -> None:
    """``CUSTOM_DECODE_JWT`` is only used from ``decode_custom_or_default_jwt`` (ACS / SP token)."""
    hooks.reset_hook_log()
    settings.SAML2_AUTH = {
        "JWT_SECRET": "integration-test-secret",
        "JWT_ALGORITHM": "HS256",
        "JWT_EXP": 600,
        "TRIGGER": {
            "CUSTOM_DECODE_JWT": "django_saml2_auth.tests.integration.hooks.custom_decode_jwt",
        },
    }
    from django_saml2_auth.user import create_jwt_token, decode_custom_or_default_jwt

    token = create_jwt_token("any-user-id")
    assert token is not None
    decode_custom_or_default_jwt(token)
    assert "CUSTOM_DECODE_JWT" in hooks.hook_log
