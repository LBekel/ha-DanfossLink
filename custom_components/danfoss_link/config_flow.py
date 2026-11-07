"""Pair a controller by code or import an existing authenticated identity."""

from typing import Any

import probatio
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.helpers import selector

from .client import DanfossClient
from .const import (
    CONF_IDENTITY_DIRECTORY,
    CONF_PAIRING_CODE,
    DEFAULT_IDENTITY_DIRECTORY,
    DOMAIN,
)
from .pairing import PairingError, PairingSession
from .protocol import AuthenticationError, DanfossError, InvalidIdentityError


class DanfossConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._pairing: PairingSession | None = None

    @staticmethod
    def _error_key(error: DanfossError) -> str:
        if isinstance(error, PairingError):
            return error.error_key
        if isinstance(error, InvalidIdentityError):
            return "invalid_identity"
        if isinstance(error, AuthenticationError):
            return "invalid_auth"
        return "cannot_connect"

    async def _async_connect(self, directory: str) -> ConfigFlowResult:
        client = await self.hass.async_add_executor_job(DanfossClient, directory)
        await self.async_set_unique_id(client.peer_id)
        if self.source == "reauth":
            self._abort_if_unique_id_mismatch()
        else:
            self._abort_if_unique_id_configured()
        await self.hass.async_add_executor_job(client.get_rooms)
        data = {CONF_IDENTITY_DIRECTORY: directory}
        if self.source == "reauth":
            return self.async_update_reload_and_abort(
                self._get_reauth_entry(), data=data
            )
        return self.async_create_entry(title="Danfoss Link", data=data)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None and CONF_IDENTITY_DIRECTORY in user_input:
            return await self.async_step_import(user_input)
        return self.async_show_menu(step_id="user", menu_options=["pair", "import"])

    async def async_step_import(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            directory = self.hass.config.path(user_input[CONF_IDENTITY_DIRECTORY])
            try:
                return await self._async_connect(directory)
            except DanfossError as err:
                errors["base"] = self._error_key(err)
        default = DEFAULT_IDENTITY_DIRECTORY
        if self.source == "reauth":
            default = self._get_reauth_entry().data[CONF_IDENTITY_DIRECTORY]
        return self.async_show_form(
            step_id="import",
            data_schema=probatio.Schema(
                {
                    probatio.Required(
                        CONF_IDENTITY_DIRECTORY, default=default
                    ): selector.TextSelector()
                }
            ),
            errors=errors,
        )

    async def async_step_pair(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                if self._pairing is None:
                    self._pairing = await self.hass.async_add_executor_job(
                        PairingSession.prepare,
                        self.hass.config.path(".storage", DOMAIN),
                    )
                return await self.async_step_pair_code()
            except DanfossError as err:
                errors["base"] = self._error_key(err)
        return self.async_show_form(
            step_id="pair",
            data_schema=probatio.Schema({}),
            errors=errors,
        )

    async def async_step_pair_code(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if self._pairing is None:
            return await self.async_step_pair()
        if self._pairing.peer_id is not None:
            return await self.async_step_finish()
        errors: dict[str, str] = {}
        if user_input is not None:
            expected = (
                self._get_reauth_entry().unique_id if self.source == "reauth" else None
            )
            configured = frozenset(
                entry.unique_id
                for entry in self._async_current_entries()
                if entry.unique_id is not None and entry.unique_id != expected
            )
            try:
                await self.hass.async_add_executor_job(
                    self._pairing.pair,
                    user_input[CONF_PAIRING_CODE],
                    expected,
                    configured,
                )
            except DanfossError as err:
                errors["base"] = self._error_key(err)
                if self._pairing.peer_id is not None:
                    return self.async_show_form(
                        step_id="finish",
                        data_schema=probatio.Schema({}),
                        errors=errors,
                    )
            else:
                return await self.async_step_finish({})
        return self.async_show_form(
            step_id="pair_code",
            data_schema=probatio.Schema(
                {
                    probatio.Required(CONF_PAIRING_CODE): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.PASSWORD
                        )
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_finish(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if self._pairing is None or self._pairing.peer_id is None:
            return await self.async_step_pair()
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                await self.hass.async_add_executor_job(self._pairing.save_pairing)
                return await self._async_connect(str(self._pairing.directory))
            except DanfossError as err:
                errors["base"] = self._error_key(err)
        return self.async_show_form(
            step_id="finish",
            data_schema=probatio.Schema({}),
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        return await self.async_step_user()
