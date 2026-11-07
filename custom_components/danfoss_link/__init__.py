"""Danfoss Link: one climate entity per controller room."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed

from .client import DanfossClient
from .const import CONF_IDENTITY_DIRECTORY
from .coordinator import DanfossCoordinator
from .protocol import InvalidIdentityError

PLATFORMS = [Platform.CLIMATE]
type DanfossConfigEntry = ConfigEntry[DanfossCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: DanfossConfigEntry) -> bool:
    try:
        client = await hass.async_add_executor_job(
            DanfossClient, entry.data[CONF_IDENTITY_DIRECTORY]
        )
    except InvalidIdentityError as err:
        raise ConfigEntryAuthFailed(str(err)) from err
    if client.peer_id != entry.unique_id:
        raise ConfigEntryAuthFailed(
            "Identity directory now belongs to a different controller"
        )
    coordinator = DanfossCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: DanfossConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
