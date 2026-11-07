"""Room climate entities. No invented off, whole-house or scheduling commands."""

from typing import Any

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACAction,
    HVACMode,
)
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import DanfossConfigEntry
from .const import DOMAIN
from .coordinator import DanfossCoordinator
from .models import Room
from .protocol import CommandError


async def async_setup_entry(
    hass: HomeAssistant,
    entry: DanfossConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    known: set[int] = set()

    @callback
    def add_rooms() -> None:
        new_ids = coordinator.data.keys() - known
        if new_ids:
            async_add_entities(
                [DanfossRoom(coordinator, room_id) for room_id in sorted(new_ids)]
            )
            known.update(new_ids)

    add_rooms()
    entry.async_on_unload(coordinator.async_add_listener(add_rooms))


class DanfossRoom(CoordinatorEntity[DanfossCoordinator], ClimateEntity):
    _attr_has_entity_name = True
    _attr_icon = "mdi:heating-coil"
    _attr_native_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_hvac_modes = [HVACMode.HEAT]
    _attr_hvac_mode = HVACMode.HEAT
    _enable_turn_on_off_backwards_compatibility = False

    def __init__(self, coordinator: DanfossCoordinator, room_id: int) -> None:
        super().__init__(coordinator)
        self.room_id = room_id
        self._last_name = coordinator.data[room_id].name
        self._attr_unique_id = f"{coordinator.client.peer_id}_room_{room_id}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.client.peer_id)},
            name="Danfoss Link",
            manufacturer="Danfoss",
            model="Link CC",
        )

    @property
    def room(self) -> Room | None:
        return self.coordinator.data.get(self.room_id)

    @property
    def name(self) -> str:
        if self.room is not None:
            self._last_name = self.room.name
        return self._last_name

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.room is not None
            and (not self.room.adjustable or self.room.valid_limits)
        )

    @property
    def supported_features(self) -> ClimateEntityFeature:
        if self.room and self.room.adjustable and self.room.valid_limits:
            return ClimateEntityFeature.TARGET_TEMPERATURE
        return ClimateEntityFeature(0)

    @property
    def native_current_temperature(self) -> float | None:
        return self.room.current if self.room else None

    @property
    def native_target_temperature(self) -> float | None:
        return self.room.target if self.room else None

    @property
    def min_temp(self) -> float:
        return (
            self.room.minimum
            if self.room and self.room.valid_limits
            else super().min_temp
        )

    @property
    def max_temp(self) -> float:
        return (
            self.room.maximum
            if self.room and self.room.valid_limits
            else super().max_temp
        )

    @property
    def hvac_action(self) -> HVACAction | None:
        if not self.room:
            return None
        return {"Heating": HVACAction.HEATING, "Deadband": HVACAction.IDLE}.get(
            self.room.regulation_state
        )

    async def async_set_temperature(self, **kwargs: Any) -> None:
        if not self.available or self.room is None:
            raise ServiceValidationError("Room is unavailable")
        if kwargs.get("hvac_mode", HVACMode.HEAT) != HVACMode.HEAT:
            raise ServiceValidationError(
                "Changing the room's HVAC mode is not supported"
            )
        try:
            target = self.room.validate_target(kwargs.get(ATTR_TEMPERATURE))
        except CommandError as err:
            raise ServiceValidationError(str(err)) from err
        await self.coordinator.async_set_temperature(self.room_id, target)

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        if hvac_mode != HVACMode.HEAT:
            raise ServiceValidationError(
                "Only heating is supported; no global mode was changed"
            )
