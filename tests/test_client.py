import json
from contextlib import contextmanager
from dataclasses import replace

import pytest

from custom_components.danfoss_link.client import DanfossClient
from custom_components.danfoss_link.models import Room, parse_rooms, temperature
from custom_components.danfoss_link.protocol import (
    CommandError,
    DanfossError,
    InvalidIdentityError,
    ProtocolError,
)


@pytest.mark.parametrize("value", [777, None, True, "20", float("nan"), float("inf")])
def test_invalid_temperatures_are_unknown(value):
    assert temperature(value) is None


def test_room_fields_and_bounds(room_data):
    room = Room.parse(room_data)
    assert room.current == 20.5 and room.target == 19.5
    assert room.validate_target(5) == 5
    assert room.validate_target(28) == 28
    for value in (4.9, 28.1, 777, True, float("nan")):
        with pytest.raises(CommandError):
            room.validate_target(value)
    for invalid in (
        replace(room, adjustable=False),
        replace(room, minimum=None),
        replace(room, minimum=30),
        replace(room, maximum=None),
    ):
        with pytest.raises(CommandError):
            invalid.validate_target(20)
    room_data["hasTemperatureSensor"] = False
    assert Room.parse(room_data).current is None


def test_duplicate_room_id_is_rejected(room_data):
    with pytest.raises(ProtocolError):
        parse_rooms([room_data, room_data])


def test_unknown_regulation_state_is_not_invented(room_data):
    room_data["regulationState"] = {"unknown": "state"}
    assert Room.parse(room_data).regulation_state is None


def test_identity_import_and_mismatch(identity_directory):
    client = DanfossClient(str(identity_directory))
    assert client.peer_id == client.peer_id.lower()
    record_path = identity_directory / "pairing-test.json"
    data = json.loads(record_path.read_text())
    data["peer_id"] = "invalid"
    record_path.write_text(json.dumps(data))
    with pytest.raises(InvalidIdentityError):
        DanfossClient(str(identity_directory))


def test_missing_identity_is_explicit(tmp_path):
    with pytest.raises(InvalidIdentityError):
        DanfossClient(str(tmp_path))


def test_single_write_and_readback(identity_directory, room_data, monkeypatch):
    client = DanfossClient(str(identity_directory))
    calls = []

    class Session:
        def request(self, method, uri, content=None):
            calls.append((method, uri, content))
            if method == "PATCH":
                room_data["setpoint"]["temperature"] = content["setpoint"][
                    "temperature"
                ]
                return None
            return [room_data] if uri == "/api/rooms" else room_data

    @contextmanager
    def channel():
        yield Session()

    monkeypatch.setattr(client, "_channel", channel)
    assert client.set_temperature(7, 20)[7].target == 20
    assert calls == [
        ("GET", "/api/rooms/7", None),
        ("PATCH", "/api/rooms/7", {"id": 7, "setpoint": {"temperature": 20.0}}),
        ("GET", "/api/rooms", None),
    ]


@pytest.mark.parametrize("fail_at", ["PATCH", "readback"])
def test_uncertain_write_is_never_retried(
    identity_directory, room_data, monkeypatch, fail_at
):
    client = DanfossClient(str(identity_directory))
    patches = []

    class Session:
        def request(self, method, uri, content=None):
            if method == "PATCH":
                patches.append(content)
                if fail_at == "PATCH":
                    raise DanfossError("Connection lost")
                return None
            if uri == "/api/rooms":
                return [room_data]
            return room_data

    @contextmanager
    def channel():
        yield Session()

    monkeypatch.setattr(client, "_channel", channel)
    with pytest.raises(CommandError, match="not confirmed"):
        client.set_temperature(7, 20)
    assert len(patches) == 1


def test_fresh_limits_prevent_write(identity_directory, room_data, monkeypatch):
    client = DanfossClient(str(identity_directory))
    room_data["maxSetpoint"] = 18
    calls = []

    class Session:
        def request(self, method, uri, content=None):
            calls.append(method)
            return room_data

    @contextmanager
    def channel():
        yield Session()

    monkeypatch.setattr(client, "_channel", channel)
    with pytest.raises(CommandError):
        client.set_temperature(7, 20)
    assert calls == ["GET"]
