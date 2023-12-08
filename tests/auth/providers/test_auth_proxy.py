"""Test the Auth Proxy auth provider."""
from ipaddress import ip_address
from unittest.mock import AsyncMock
import uuid

from hass_nabucasa import remote
from multidict import MultiDict
import pytest
import voluptuous as vol

from homeassistant.auth import AuthManager, auth_store, models as auth_models
from homeassistant.auth.providers import auth_proxy as ap_auth
from homeassistant.components.http import CONF_TRUSTED_PROXIES, CONF_USE_X_FORWARDED_FOR
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.setup import async_setup_component


@pytest.fixture
def store(hass):
    """Mock store."""
    return auth_store.AuthStore(hass)


@pytest.fixture
def provider(hass, store):
    """Mock provider."""
    return ap_auth.AuthProxyAuthProvider(
        hass,
        store,
        ap_auth.CONFIG_SCHEMA(
            {
                "type": "auth_proxy",
                "auth_proxy": {
                    "user_header": "X-Auth-Request-User",
                },
            }
        ),
    )


@pytest.fixture
def provider_with_name(hass, store):
    """Mock provider with trusted users config."""
    return ap_auth.AuthProxyAuthProvider(
        hass,
        store,
        ap_auth.CONFIG_SCHEMA(
            {
                "type": "auth_proxy",
                "auth_proxy": {
                    "user_header": "X-Auth-Request-User",
                    "name_header": "X-Auth-Request-Preferred-Username",
                },
            }
        ),
    )


@pytest.fixture
def provider_bypass_login(hass, store):
    """Mock provider with allow_bypass_login config."""
    return ap_auth.AuthProxyAuthProvider(
        hass,
        store,
        ap_auth.CONFIG_SCHEMA(
            {
                "type": "auth_proxy",
                "auth_proxy": {
                    "user_header": "X-Auth-Request-User",
                },
                "allow_bypass_login": True,
            }
        ),
    )


@pytest.fixture
def manager(hass, store, provider):
    """Mock manager."""
    return AuthManager(hass, store, {(provider.type, provider.id): provider}, {})


@pytest.fixture
def manager_with_name(hass, store, provider_with_name):
    """Mock manager with trusted user."""
    return AuthManager(
        hass,
        store,
        {(provider_with_name.type, provider_with_name.id): provider_with_name},
        {},
    )


@pytest.fixture
def manager_bypass_login(hass, store, provider_bypass_login):
    """Mock manager with allow bypass login."""
    return AuthManager(
        hass,
        store,
        {(provider_bypass_login.type, provider_bypass_login.id): provider_bypass_login},
        {},
    )


async def test_config_schema() -> None:
    """Test CONFIG_SCHEMA."""
    # Valid configuration
    ap_auth.CONFIG_SCHEMA(
        {
            "type": "auth_proxy",
            "auth_proxy": {
                "user_header": "X-Auth-Request-User",
                "name_header": "X-Auth-Request-Preferred-Username",
            },
        }
    )
    # Missing user_header
    with pytest.raises(vol.Invalid):
        ap_auth.CONFIG_SCHEMA(
            {
                "type": "auth_proxy",
                "auth_proxy": {
                    "name_header": "X-Auth-Request-Preferred-Username",
                },
            }
        )


async def test_validate_access(hass: HomeAssistant, provider) -> None:
    """Test validate access from trusted proxies."""

    await async_setup_component(
        hass,
        "http",
        {
            "http": {
                CONF_TRUSTED_PROXIES: ["192.168.128.0/31", "fd00::1"],
                CONF_USE_X_FORWARDED_FOR: True,
            }
        },
    )

    headers = MultiDict()
    headers.add("X-Auth-Request-User", "test")

    provider.async_validate_access(ip_address("192.168.128.0"), headers)
    provider.async_validate_access(ip_address("192.168.128.1"), headers)
    provider.async_validate_access(ip_address("fd00::1"), headers)

    with pytest.raises(ap_auth.InvalidAuthError):
        provider.async_validate_access(ip_address("192.168.128.0"), MultiDict())
    with pytest.raises(ap_auth.InvalidAuthError):
        provider.async_validate_access(ip_address("192.168.128.2"), headers)
    with pytest.raises(ap_auth.InvalidAuthError):
        provider.async_validate_access(ip_address("fd00::2"), headers)


async def test_validate_access_cloud(hass: HomeAssistant, provider) -> None:
    """Test validate access from trusted networks are blocked from cloud."""
    await async_setup_component(
        hass,
        "http",
        {
            "http": {
                CONF_TRUSTED_PROXIES: ["192.168.128.0/31", "fd00::1"],
                CONF_USE_X_FORWARDED_FOR: True,
            }
        },
    )
    hass.config.components.add("cloud")

    headers = MultiDict()
    headers.add("X-Auth-Request-User", "test")

    provider.async_validate_access(ip_address("192.168.128.0"), headers)

    remote.is_cloud_request.set(True)
    with pytest.raises(ap_auth.InvalidAuthError):
        provider.async_validate_access(ip_address("192.168.128.0"), headers)


async def test_create_new_credential(manager, provider) -> None:
    """Test that we create a new credential."""
    credentials = await provider.async_get_or_create_credentials(
        {"username": "good-user", "name": "Good User"}
    )
    assert credentials.is_new is True

    user = await manager.async_get_or_create_user(credentials)
    assert user.is_active


async def test_match_existing_credentials(store, provider) -> None:
    """See if we match existing users."""
    existing = auth_models.Credentials(
        id=uuid.uuid4(),
        auth_provider_type="command_line",
        auth_provider_id=None,
        data={"username": "good-user"},
        is_new=False,
    )
    provider.async_credentials = AsyncMock(return_value=[existing])
    credentials = await provider.async_get_or_create_credentials(
        {"username": "good-user", "name": "irrelevant"}
    )
    assert credentials is existing


async def test_login_flow(hass: HomeAssistant, manager, provider) -> None:
    """Test login flow."""
    await async_setup_component(
        hass,
        "http",
        {
            "http": {
                CONF_TRUSTED_PROXIES: ["192.168.128.0/31", "fd00::1"],
                CONF_USE_X_FORWARDED_FOR: True,
            }
        },
    )

    headers = MultiDict()
    headers.add("X-Auth-Request-User", "test")

    with pytest.raises(ap_auth.InvalidAuthError):
        await provider.async_login_flow(
            {"peer_ip_address": ip_address("192.168.128.2"), "headers": headers}
        )

    flow = await provider.async_login_flow(
        {"peer_ip_address": ip_address("192.168.128.0"), "headers": headers}
    )
    step = await flow.async_step_init()
    assert step["step_id"] == "init"

    step = await flow.async_step_init({})
    assert step["type"] == FlowResultType.CREATE_ENTRY
    assert step["data"]["username"] == "test"


async def test_bypass_login_flow(
    hass: HomeAssistant, manager_bypass_login, provider_bypass_login
) -> None:
    """Test login flow can be bypass if only one user available."""
    await async_setup_component(
        hass,
        "http",
        {
            "http": {
                CONF_TRUSTED_PROXIES: ["192.168.128.0/31", "fd00::1"],
                CONF_USE_X_FORWARDED_FOR: True,
            }
        },
    )

    headers = MultiDict()
    headers.add("X-Auth-Request-User", "test")

    with pytest.raises(ap_auth.InvalidAuthError):
        await provider_bypass_login.async_login_flow(
            {"peer_ip_address": ip_address("192.168.128.2"), "headers": headers}
        )

    flow = await provider_bypass_login.async_login_flow(
        {"peer_ip_address": ip_address("192.168.128.0"), "headers": headers}
    )
    step = await flow.async_step_init()
    assert step["type"] == FlowResultType.CREATE_ENTRY
    assert step["data"]["username"] == "test"
