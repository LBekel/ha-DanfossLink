from dataclasses import replace
from types import MappingProxyType
from unittest.mock import AsyncMock, Mock

import pytest
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.util.unit_system import US_CUSTOMARY_SYSTEM

from custom_components.danfoss_link.climate import DanfossRoom
from custom_components.danfoss_link.coordinator import DanfossCoordinator
from custom_components.danfoss_link.models import Room
from custom_components.danfoss_link.protocol import DanfossError, InvalidIdentityError


def entry():
    return ConfigEntry(
        domain="danfoss_link",
        title="Danfoss Link",
        version=1,
        minor_version=1,
        source="user",
        unique_id="test-controller",
        data={"identity_directory": "/synthetic"},
        options={},
        discovery_keys=MappingProxyType({}),
        subentries_data=[],
    )


async def test_entity_mapping_and_service(hass, room_data):
    client = Mock(peer_id="test-controller")
    coordinator = DanfossCoordinator(hass, entry(), client)
    coordinator.async_set_updated_data({7: Room.parse(room_data)})
    entity = DanfossRoom(coordinator, 7)
    assert entity.unique_id == "test-controller_room_7"
    assert entity.icon == "mdi:heating-coil"
    assert entity.native_current_temperature == 20.5
    assert entity.native_target_temperature == 19.5
    assert entity.min_temp == 5 and entity.max_temp == 28
    assert entity.hvac_modes == ["heat"] and entity.hvac_action == "heating"
    coordinator.async_set_temperature = AsyncMock()
    await entity.async_set_temperature(temperature=20)
    coordinator.async_set_temperature.assert_awaited_once_with(7, 20)
    with pytest.raises(ServiceValidationError):
        await entity.async_set_temperature(temperature=100)
    with pytest.raises(ServiceValidationError):
        await entity.async_set_hvac_mode("off")
    coordinator.async_set_updated_data(
        {7: replace(coordinator.data[7], name="Renamed room")}
    )
    assert entity.name == "Renamed room"
    assert entity.unique_id == "test-controller_room_7"
    coordinator.async_set_updated_data({})
    assert not entity.available
    assert entity.native_current_temperature is None


async def test_coordinator_error_and_recovery(hass, room_data):
    client = Mock(
        peer_id="test-controller",
        get_rooms=Mock(return_value={7: Room.parse(room_data)}),
    )
    coordinator = DanfossCoordinator(hass, entry(), client)
    await coordinator.async_refresh()
    assert coordinator.last_update_success
    client.get_rooms.side_effect = DanfossError("Disconnected")
    await coordinator.async_refresh()
    assert not coordinator.last_update_success
    client.set_temperature.side_effect = DanfossError("Not confirmed")
    with pytest.raises(HomeAssistantError):
        await coordinator.async_set_temperature(7, 20)
    client.get_rooms.side_effect = None
    await coordinator.async_refresh()
    assert coordinator.last_update_success


async def test_real_config_flow_setup_discovery_and_unload(
    hass, room_data, monkeypatch
):
    import custom_components.danfoss_link as integration
    from custom_components.danfoss_link import config_flow

    rooms = {
        index: Room.parse({**room_data, "id": index, "name": f"Room {index}"})
        for index in range(13)
    }
    client = Mock(peer_id="test-controller", get_rooms=Mock(return_value=rooms))
    monkeypatch.setattr(config_flow, "DanfossClient", Mock(return_value=client))
    monkeypatch.setattr(integration, "DanfossClient", Mock(return_value=client))
    result = await hass.config_entries.flow.async_init(
        "danfoss_link",
        context={"source": "user"},
        data={"identity_directory": "private"},
    )
    assert result["type"] == "create_entry", result
    await hass.async_block_till_done()
    config_entry = result["result"]
    states = hass.states.async_all(Platform.CLIMATE)
    assert len(states) == 13
    assert all(state.attributes["current_temperature"] == 20.5 for state in states)
    assert all(state.attributes["temperature"] == 19.5 for state in states)
    assert all(
        state.attributes["min_temp"] == 5 and state.attributes["max_temp"] == 28
        for state in states
    )
    assert all(state.attributes["hvac_modes"] == ["heat"] for state in states)
    client.set_temperature.return_value = {**rooms, 0: replace(rooms[0], target=20)}
    await hass.services.async_call(
        "climate",
        "set_temperature",
        {"entity_id": "climate.danfoss_link_room_0", "temperature": 20},
        blocking=True,
    )
    client.set_temperature.assert_called_once_with(0, 20)
    assert (
        hass.states.get("climate.danfoss_link_room_0").attributes["temperature"] == 20
    )
    duplicate = await hass.config_entries.flow.async_init(
        "danfoss_link",
        context={"source": "user"},
        data={"identity_directory": "private"},
    )
    assert duplicate["type"] == "abort" and duplicate["reason"] == "already_configured"
    coordinator = config_entry.runtime_data
    coordinator.async_set_updated_data(
        {**rooms, 20: replace(rooms[0], id=20, name="New room")}
    )
    await hass.async_block_till_done()
    assert len(hass.states.async_all(Platform.CLIMATE)) == 14
    reauth = await hass.config_entries.flow.async_init(
        "danfoss_link",
        context={"source": "reauth", "entry_id": config_entry.entry_id},
        data=config_entry.data,
    )
    reauth = await hass.config_entries.flow.async_configure(
        reauth["flow_id"], {"next_step_id": "import"}
    )
    reauth = await hass.config_entries.flow.async_configure(
        reauth["flow_id"], {"identity_directory": "replacement"}
    )
    assert reauth["type"] == "abort" and reauth["reason"] == "reauth_successful"
    await hass.async_block_till_done()
    assert config_entry.data["identity_directory"].endswith("replacement")
    assert (
        sum(
            state.state != "unavailable"
            for state in hass.states.async_all(Platform.CLIMATE)
        )
        == 13
    )
    assert hass.states.get("climate.danfoss_link_new_room").state == "unavailable"
    await hass.config_entries.async_unload(config_entry.entry_id)
    await hass.async_block_till_done()
    assert all(
        state.state == "unavailable"
        for state in hass.states.async_all(Platform.CLIMATE)
    )


async def test_config_flow_rejects_missing_identity(hass, monkeypatch):
    from custom_components.danfoss_link import config_flow

    monkeypatch.setattr(
        config_flow, "DanfossClient", Mock(side_effect=InvalidIdentityError("Missing"))
    )
    result = await hass.config_entries.flow.async_init(
        "danfoss_link",
        context={"source": "user"},
        data={"identity_directory": "missing"},
    )
    assert result["type"] == "form" and result["errors"] == {"base": "invalid_identity"}


async def test_fahrenheit_service_is_converted_before_writing(
    hass, room_data, monkeypatch
):
    import custom_components.danfoss_link as integration
    from custom_components.danfoss_link import config_flow

    hass.config.units = US_CUSTOMARY_SYSTEM
    rooms = {7: Room.parse(room_data)}
    client = Mock(
        peer_id="test-controller",
        get_rooms=Mock(return_value=rooms),
        set_temperature=Mock(return_value={7: replace(rooms[7], target=20)}),
    )
    monkeypatch.setattr(config_flow, "DanfossClient", Mock(return_value=client))
    monkeypatch.setattr(integration, "DanfossClient", Mock(return_value=client))
    result = await hass.config_entries.flow.async_init(
        "danfoss_link",
        context={"source": "user"},
        data={"identity_directory": "private"},
    )
    assert result["type"] == "create_entry"
    await hass.async_block_till_done()
    await hass.services.async_call(
        "climate",
        "set_temperature",
        {"entity_id": "climate.danfoss_link_test_room", "temperature": 68},
        blocking=True,
    )
    client.set_temperature.assert_called_once_with(7, 20)
