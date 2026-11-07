import io
import json
import struct

import pytest

from custom_components.danfoss_link.client import JsonSession
from custom_components.danfoss_link.protocol import (
    AuthenticationError,
    ProtocolError,
    control_reply,
    decode,
    field,
    read_frame,
)


class Stream:
    def __init__(self, content=b""):
        self.content = io.BytesIO(content)
        self.sent = bytearray()

    def recv(self, size):
        return self.content.read(min(size, 3))

    def sendall(self, data):
        self.sent.extend(data)


def response(content, *, request_id=1, status=200, kind="JsonWebResponse"):
    data = json.dumps(
        {
            "id": request_id,
            "data": {"type": kind, "data": {"status": status, "content": content}},
        }
    ).encode()
    return struct.pack(">H", len(data)) + data


def test_wire_vectors_and_fragmented_frames():
    assert field(1, 150) == b"\x08\x96\x01"
    assert decode(field(1, 4036857000, fixed=True) + field(2, "cc_json")) == {
        1: [4036857000],
        2: [b"cc_json"],
    }
    assert read_frame(Stream(b"\x00\x05hello")) == b"hello"


@pytest.mark.parametrize(
    "data", [b"\x08\x80", b"\x12\x04a", b"\x00", b"\x0f", b"\x08" + b"\xff" * 10]
)
def test_malformed_protobuf_rejected(data):
    with pytest.raises(ProtocolError):
        decode(data)


def test_frame_truncation_and_empty_frame():
    with pytest.raises(EOFError):
        read_frame(Stream(b"\x00\x05abc"))
    with pytest.raises(ProtocolError):
        read_frame(Stream(b"\x00\x00"))


def test_control_reply_handles_ping_but_correlates_response():
    ping, reply = b"\x04" + field(1, 9), b"\x15" + field(1, 2)
    stream = Stream(
        struct.pack(">H", len(ping)) + ping + struct.pack(">H", len(reply)) + reply
    )
    assert control_reply(stream, 21, 2) == {1: [2]}
    assert stream.sent == b"\x00\x03\x05\x08\x09"


def test_patch_payload_is_exact_and_scoped():
    stream = Stream(response(None))
    session = JsonSession(stream)
    session.request(
        "PATCH", "/api/rooms/7", {"id": 7, "setpoint": {"temperature": 20.0}}
    )
    request = json.loads(stream.sent[2:])
    assert request == {
        "id": 1,
        "data": {
            "type": "JsonWebRequest",
            "data": {
                "method": "PATCH",
                "uri": "/api/rooms/7",
                "headers": ["Accept: application/json; charset=utf-8"],
                "content": {"id": 7, "setpoint": {"temperature": 20.0}},
            },
        },
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"request_id": 2},
        {"request_id": True},
        {"kind": "Other"},
        {"status": 500},
        {"status": "200"},
    ],
)
def test_response_validation(kwargs):
    with pytest.raises(ProtocolError):
        JsonSession(Stream(response([], **kwargs))).request("GET", "/api/rooms")


def test_authorization_failure_is_not_an_empty_success():
    with pytest.raises(AuthenticationError):
        JsonSession(Stream(response(None, status=403))).request("GET", "/api/rooms")
