"""Fixtures for ``django_saml2_auth.tests.integration`` (Docker IdP)."""

from __future__ import annotations

import time
from typing import Any, Dict, Iterator
from urllib.error import URLError
from urllib.request import urlopen

import pytest
from testcontainers.core.container import DockerContainer

try:
    import docker as _docker_module

    _HAS_DOCKER_PYTHON = True
except ImportError:
    _docker_module = None
    _HAS_DOCKER_PYTHON = False

_IDP_DOCKER_IMAGE = "jamedjo/test-saml-idp:latest"
_IDP_METADATA_PATH = "/simplesaml/saml2/idp/metadata.php"


def _docker_available() -> bool:
    if not _HAS_DOCKER_PYTHON or _docker_module is None:
        return False
    try:
        client = _docker_module.from_env()
        client.ping()
        return True
    except Exception:
        return False


def _wait_for_idp(base_url: str, timeout: int = 60) -> bool:
    metadata_url = f"{base_url}{_IDP_METADATA_PATH}"
    start = time.time()
    while time.time() - start < timeout:
        try:
            urlopen(metadata_url, timeout=2)
            return True
        except (URLError, OSError):
            time.sleep(0.5)
    return False


@pytest.fixture(scope="module")
def saml_idp_container() -> Iterator[Dict[str, Any]]:
    """SimpleSAMLphp IdP with SP metadata matching Django's test client (http://testserver)."""
    if not _docker_available():
        pytest.skip("Docker is not available")

    container = DockerContainer(_IDP_DOCKER_IMAGE)
    container.with_exposed_ports(8080)
    container.maybe_emulate_amd64()
    container.with_env("SIMPLESAMLPHP_SP_ENTITY_ID", "http://testserver/saml2-metadata")
    container.with_env(
        "SIMPLESAMLPHP_SP_ASSERTION_CONSUMER_SERVICE",
        "http://testserver/sso/acs/",
    )
    container.start()

    host = container.get_container_host_ip()
    port = container.get_exposed_port(8080)
    base_url = f"http://{host}:{port}"

    if not _wait_for_idp(base_url):
        container.stop()
        pytest.fail("SAML IdP container did not become ready in time")

    yield {
        "container": container,
        "host": host,
        "port": port,
        "base_url": base_url,
        "metadata_url": f"{base_url}{_IDP_METADATA_PATH}",
    }

    container.stop()
