"""Poll and serialize controller operations outside Home Assistant's event loop."""

import asyncio
import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import DanfossClient
from .models import Room
from .protocol import AuthenticationError, DanfossError

_LOGGER = logging.getLogger(__name__)


class DanfossCoordinator(DataUpdateCoordinator[dict[int, Room]]):
    def __init__(
        self, hass: HomeAssistant, entry: ConfigEntry, client: DanfossClient
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name="Danfoss Link",
            update_interval=timedelta(seconds=60),
            always_update=False,
        )
        self.client = client
        self.operation_lock = asyncio.Lock()

    async def _async_update_data(self) -> dict[int, Room]:
        async with self.operation_lock:
            try:
                return await self.hass.async_add_executor_job(self.client.get_rooms)
            except AuthenticationError as err:
                raise ConfigEntryAuthFailed(str(err)) from err
            except DanfossError as err:
                raise UpdateFailed(str(err)) from err

    async def async_set_temperature(self, room_id: int, target: float) -> None:
        async with self.operation_lock:
            try:
                rooms = await self.hass.async_add_executor_job(
                    self.client.set_temperature, room_id, target
                )
            except AuthenticationError as err:
                self.async_set_update_error(err)
                self.config_entry.async_start_reauth(self.hass)
                raise HomeAssistantError(str(err)) from err
            except DanfossError as err:
                self.async_set_update_error(err)
                raise HomeAssistantError(str(err)) from err
            self.async_set_updated_data(rooms)
