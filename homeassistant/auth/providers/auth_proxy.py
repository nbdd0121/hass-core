"""Auth proxy auth provider.

It uses headers from HTTP reverse proxy, when authentication is handled by reverse proxy itself.
"""
from __future__ import annotations

from collections.abc import Mapping
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network
from typing import Any, cast

from multidict import MultiMapping
import voluptuous as vol

from homeassistant.auth import InvalidAuthError
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.network import is_cloud_connection

from ..models import Credentials, UserMeta
from . import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, LoginFlow

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network

AUTH_PROXY_SCHEMA = vol.Schema(
    {
        vol.Required("user_header"): str,
        vol.Optional("name_header"): str,
    },
    extra=vol.PREVENT_EXTRA,
)

CONFIG_SCHEMA = AUTH_PROVIDER_SCHEMA.extend(
    {
        vol.Required("auth_proxy"): AUTH_PROXY_SCHEMA,
        vol.Optional("allow_bypass_login", default=False): cv.boolean,
    },
    extra=vol.PREVENT_EXTRA,
)


@AUTH_PROVIDERS.register("auth_proxy")
class AuthProxyAuthProvider(AuthProvider):
    """Auth proxy auth provider.

    It uses headers from HTTP reverse proxy, when authentication is handled by reverse proxy itself.
    """

    DEFAULT_TITLE = "Auth Proxy"

    @property
    def user_header(self) -> str:
        """Return header for user ID."""
        return cast(str, self.config["auth_proxy"]["user_header"])

    @property
    def name_header(self) -> str | None:
        """Return header for user name."""
        return cast(str | None, self.config["auth_proxy"].get("name_header"))

    @property
    def trusted_proxies(self) -> list[IPNetwork]:
        """Return trusted proxies in the system."""
        if not self.hass.http:
            return []

        return [
            ip_network(trusted_proxy)
            for trusted_proxy in self.hass.http.trusted_proxies
        ]

    async def async_login_flow(self, context: dict[str, Any] | None) -> LoginFlow:
        """Return a flow to login."""
        assert context is not None

        ip_addr = cast(IPAddress, context.get("peer_ip_address"))
        headers = cast(MultiMapping[str], context.get("headers"))

        (user, name) = self.async_validate_access(ip_addr, headers)
        return AuthProxyLoginFlow(
            self,
            user,
            name,
            self.config["allow_bypass_login"],
        )

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        user = flow_result["username"]
        name = flow_result["name"]

        for credential in await self.async_credentials():
            if credential.data["username"] == user:
                return credential

        # Create new credentials.
        return self.async_create_credentials({"username": user, "name": name})

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials.

        Will be used to populate info when creating a new user.
        """
        name = credentials.data["name"]
        return UserMeta(name=name, is_active=True)

    @callback
    def async_validate_access(
        self, ip_addr: IPAddress, headers: MultiMapping[str]
    ) -> tuple[str, str]:
        """Validate the reverse proxy and its supplied headers.

        Raise InvalidAuthError if not authenticated.
        """

        # Verify that the request comes from a trusted proxy.
        # If not, then we must not use any of the auth headers.
        if not any(ip_addr in trusted_proxy for trusted_proxy in self.trusted_proxies):
            raise InvalidAuthError("Not authenticated")

        if is_cloud_connection(self.hass):
            raise InvalidAuthError("Can't allow access from Home Assistant Cloud")

        user = headers.get(self.user_header)
        if user is None:
            raise InvalidAuthError("Not authenticated")

        # If name header is not set, or if set but not supplied by the proxy,
        # just use the user name instead.
        name = user
        name_header = self.name_header
        if name_header is not None:
            name = headers.get(name_header) or user

        return (user, name)


class AuthProxyLoginFlow(LoginFlow):
    """Handler for the login flow."""

    def __init__(
        self,
        auth_provider: AuthProxyAuthProvider,
        user: str,
        name: str,
        allow_bypass_login: bool,
    ) -> None:
        """Initialize the login flow."""
        super().__init__(auth_provider)
        self._user = user
        self._name = name
        self._allow_bypass_login = allow_bypass_login

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> FlowResult:
        """Handle the step of the form."""

        if user_input is not None or self._allow_bypass_login:
            return await self.async_finish({"username": self._user, "name": self._name})

        return self.async_show_form(
            step_id="init",
        )
