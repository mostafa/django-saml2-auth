"""
Complete the browser leg of SP-initiated SAML against SimpleSAMLphp (jamedjo image).

Django's test client handles the SP; httpx performs IdP redirects and form posts.
"""

from __future__ import annotations

import html as html_module
import re
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin

import httpx

_REDIRECTS = (301, 302, 303, 307, 308)


def _follow_redirects(client: httpx.Client, response: httpx.Response) -> httpx.Response:
    r = response
    while r.status_code in _REDIRECTS:
        loc = r.headers.get("location")
        if not loc:
            break
        url = urljoin(str(r.url), loc)
        r = client.get(url)
    return r


def _hidden_inputs(html: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for m in re.finditer(
        r'<input[^>]+type="hidden"[^>]*>',
        html,
        flags=re.IGNORECASE,
    ):
        tag = m.group(0)
        nm = re.search(r'name="([^"]+)"', tag)
        val = re.search(r'value="([^"]*)"', tag)
        if nm:
            fields[nm.group(1)] = html_module.unescape(val.group(1)) if val else ""
    return fields


def _first_form_action(html: str) -> Optional[str]:
    m = re.search(r'<form[^>]+action="([^"]+)"', html, flags=re.IGNORECASE)
    return html_module.unescape(m.group(1)) if m else None


def _has_username_password_form(html: str) -> bool:
    return bool(
        re.search(r'<input[^>]+name="username"', html, flags=re.IGNORECASE)
        and re.search(r'<input[^>]+name="password"', html, flags=re.IGNORECASE)
    )


def complete_simplesamlphp_login(
    idp_entry_url: str,
    username: str,
    password: str,
) -> Tuple[str, Optional[str]]:
    """
    Follow IdP redirects and submit credentials until an HTML form contains SAMLResponse.

    Returns:
        (saml_response_b64, relay_state or None)
    """
    client = httpx.Client(follow_redirects=False, timeout=60.0)
    url = idp_entry_url
    # After a POST (login or hidden form), SimpleSAMLphp may end on a URL that must not be
    # re-fetched with GET (e.g. loginuserpass.php? with no query → 400). Reuse the POST
    # response body instead of issuing that GET.
    pending: Optional[httpx.Response] = None

    for _ in range(35):
        if pending is not None:
            r = pending
            pending = None
        else:
            r = _follow_redirects(client, client.get(url))

        text = r.text
        if "SAMLResponse" in text and "<form" in text.lower():
            action = _first_form_action(text)
            if not action:
                raise RuntimeError("SAMLResponse form missing action")
            hidden = _hidden_inputs(text)
            if "SAMLResponse" not in hidden:
                raise RuntimeError("SAMLResponse input not found")
            return hidden["SAMLResponse"], hidden.get("RelayState")

        action = _first_form_action(text)
        if not action:
            raise RuntimeError(
                f"Unexpected IdP page (status {r.status_code}, url={r.url}): {text[:500]!r}"
            )

        abs_action = urljoin(str(r.url), action)
        hidden = _hidden_inputs(text)

        if _has_username_password_form(text):
            payload = {**hidden, "username": username, "password": password}
            r = client.post(abs_action, data=payload)
            r = _follow_redirects(client, r)
            if r.status_code != 200:
                raise RuntimeError(f"After login POST expected 200, got {r.status_code} at {r.url}")
            pending = r
            continue

        if hidden:
            r = _follow_redirects(client, client.post(abs_action, data=hidden))
            if r.status_code != 200:
                raise RuntimeError(
                    f"After hidden POST expected 200, got {r.status_code} at {r.url}"
                )
            pending = r
            continue

        raise RuntimeError(f"No SAMLResponse and no known form at {r.url}: {text[:400]!r}")

    raise RuntimeError("Too many IdP steps without SAMLResponse")
