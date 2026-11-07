import json
import shutil
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from custom_components.danfoss_link import config_flow
from custom_components.danfoss_link.client import DanfossClient
from custom_components.danfoss_link.models import Room
from custom_components.danfoss_link.pairing import PairingError, PairingSession
from custom_components.danfoss_link.protocol import DanfossError

CODE = "12345600007"  # Synthetic only.


@pytest.fixture
def prepared(identity_directory, room_data, monkeypatch):
    peer_id = DanfossClient(str(identity_directory)).peer_id
    session = Mock(spec=PairingSession)
    session.peer_id = None
    session.directory = identity_directory

    def complete(code, expected, configured):
        session.peer_id = peer_id
        return peer_id

    session.pair.side_effect = complete
    prepare = Mock(return_value=session)
    monkeypatch.setattr(config_flow.PairingSession, "prepare", prepare)
    rooms = {7: Room.parse(room_data)}
    read = Mock(return_value=rooms)
    monkeypatch.setattr(DanfossClient, "get_rooms", read)
    return SimpleNamespace(
        session=session,
        prepare=prepare,
        complete=complete,
        peer_id=peer_id,
        rooms=rooms,
        read=read,
    )


async def start_pairing(hass, context=None, data=None):
    result = await hass.config_entries.flow.async_init(
        "danfoss_link",
        context=context or {"source": "user"},
        data=data,
    )
    assert result["type"] == "menu" and result["step_id"] == "user"
    assert set(result["menu_options"]) == {"pair", "import"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": "pair"}
    )
    assert result["step_id"] == "pair"
    return await hass.config_entries.flow.async_configure(result["flow_id"], {})


async def test_pairing_menu_success_creates_climate_without_persisting_code(
    hass, prepared, caplog
):
    result = await start_pairing(hass)
    assert result["step_id"] == "pair_code"
    prepared.prepare.assert_called_once_with(
        hass.config.path(".storage", "danfoss_link")
    )
    prepared.session.pair.assert_not_called()
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"pairing_code": CODE}
    )
    assert result["type"] == "create_entry"
    prepared.session.pair.assert_called_once_with(CODE, None, frozenset())
    config_entry = result["result"]
    assert dict(config_entry.data) == {
        "identity_directory": str(prepared.session.directory)
    }
    assert CODE not in json.dumps(dict(config_entry.data)) + caplog.text
    await hass.async_block_till_done()
    assert len(hass.states.async_all("climate")) == 1


async def test_prepare_failure_happens_before_code_entry(hass, prepared):
    prepared.prepare.side_effect = DanfossError("Offline")
    result = await start_pairing(hass)
    assert result["step_id"] == "pair" and result["errors"] == {
        "base": "cannot_connect"
    }
    prepared.session.pair.assert_not_called()
    prepared.prepare.side_effect = None
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["step_id"] == "pair_code"


@pytest.mark.parametrize(
    "error_key",
    [
        "invalid_code",
        "local_code",
        "pairing_unavailable",
        "pairing_proof_failed",
        "pairing_failed",
        "already_configured",
        "wrong_controller",
        "cannot_store_pairing",
    ],
)
async def test_pairing_errors_keep_a_blank_code_form(hass, prepared, error_key, caplog):
    prepared.session.pair.side_effect = PairingError(error_key)
    result = await start_pairing(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"pairing_code": CODE}
    )
    assert result["step_id"] == "pair_code"
    assert result["errors"] == {"base": error_key}
    assert CODE not in str(result) + caplog.text
    assert not hass.config_entries.async_entries("danfoss_link")
    prepared.session.pair.assert_called_once()
    prepared.read.assert_not_called()


async def test_failed_room_read_retries_completion_not_pairing(hass, prepared):
    prepared.read.side_effect = [
        DanfossError("Controller reconnecting"),
        prepared.rooms,
        prepared.rooms,
    ]
    result = await start_pairing(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"pairing_code": CODE}
    )
    assert result["step_id"] == "finish" and result["errors"] == {
        "base": "cannot_connect"
    }
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] == "create_entry"
    prepared.session.pair.assert_called_once()
    await hass.async_block_till_done()


async def test_successful_remote_pairing_with_disk_error_remains_recoverable(
    hass, prepared
):
    def complete_without_saving(*args):
        prepared.complete(*args)
        raise PairingError("cannot_store_pairing")

    prepared.session.pair.side_effect = complete_without_saving
    result = await start_pairing(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"pairing_code": CODE}
    )
    assert result["step_id"] == "finish"
    assert result["errors"] == {"base": "cannot_store_pairing"}
    prepared.session.save_pairing.side_effect = [
        PairingError("cannot_store_pairing"),
        None,
    ]
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["step_id"] == "finish"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] == "create_entry"
    prepared.session.pair.assert_called_once()
    await hass.async_block_till_done()


async def test_reauth_pairing_preserves_controller_and_old_identity(
    hass, prepared, tmp_path
):
    result = await hass.config_entries.flow.async_init(
        "danfoss_link",
        context={"source": "user"},
        data={"identity_directory": str(prepared.session.directory)},
    )
    await hass.async_block_till_done()
    entry = result["result"]
    original = dict(entry.data)
    replacement = tmp_path / "replacement"
    shutil.copytree(prepared.session.directory, replacement)
    prepared.session.directory = replacement
    prepared.session.pair.side_effect = PairingError("wrong_controller")
    result = await start_pairing(
        hass,
        {"source": "reauth", "entry_id": entry.entry_id},
        entry.data,
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"pairing_code": CODE}
    )
    assert result["errors"] == {"base": "wrong_controller"}
    assert dict(entry.data) == original
    prepared.session.pair.assert_called_once_with(CODE, prepared.peer_id, frozenset())
    prepared.session.pair.side_effect = prepared.complete
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"pairing_code": CODE}
    )
    assert result["type"] == "abort" and result["reason"] == "reauth_successful"
    await hass.async_block_till_done()
    assert entry.unique_id == prepared.peer_id
    assert entry.data["identity_directory"] == str(replacement)
    assert (tmp_path / "identity" / "client-key.pem").is_file()


async def test_initial_menu_still_offers_import(hass, prepared):
    result = await hass.config_entries.flow.async_init(
        "danfoss_link", context={"source": "user"}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": "import"}
    )
    assert result["step_id"] == "import"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"identity_directory": str(prepared.session.directory)}
    )
    assert result["type"] == "create_entry"
    prepared.prepare.assert_not_called()
    await hass.async_block_till_done()
