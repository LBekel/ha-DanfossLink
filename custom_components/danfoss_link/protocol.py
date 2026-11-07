"""Danfoss MDG framing and the small protobuf subset used by cc_json."""

import struct
from typing import Protocol


class DanfossError(Exception):
    """A safe-to-display Danfoss communication error."""


class AuthenticationError(DanfossError):
    """An authenticated identity no longer matches."""


class InvalidIdentityError(DanfossError):
    """The imported identity is incomplete or inconsistent."""


class ProtocolError(DanfossError):
    """An unexpected or malformed MDG response."""


class CommandError(DanfossError):
    """A temperature command could not be confirmed."""


class Stream(Protocol):
    def sendall(self, data: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...


type Message = dict[int, list[int | bytes]]


def varint(value: int) -> bytes:
    if not 0 <= value < 2**64:
        raise ValueError("Invalid protobuf integer")
    encoded = bytearray()
    while value > 127:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def field(number: int, value: str | bytes | int, *, fixed: bool = False) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    if isinstance(value, bytes):
        return varint(number << 3 | 2) + varint(len(value)) + value
    if fixed:
        return varint(number << 3 | 5) + struct.pack("<I", value)
    return varint(number << 3) + varint(value)


def decode(data: bytes) -> Message:
    offset = 0
    result: Message = {}

    def integer() -> int:
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset == len(data):
                raise ProtocolError("Truncated protobuf integer")
            byte = data[offset]
            offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                if value >= 2**64:
                    break
                return value
        raise ProtocolError("Oversized protobuf integer")

    while offset < len(data):
        key = integer()
        number, wire = key >> 3, key & 7
        if not 0 < number < 2**29:
            raise ProtocolError("Invalid protobuf field")
        if wire == 0:
            value = integer()
        elif wire in (1, 2, 5):
            size = integer() if wire == 2 else {1: 8, 5: 4}[wire]
            if size > len(data) - offset:
                raise ProtocolError("Truncated protobuf field")
            raw = data[offset : offset + size]
            offset += size
            value = raw if wire == 2 else int.from_bytes(raw, "little")
        else:
            raise ProtocolError("Unsupported protobuf wire type")
        result.setdefault(number, []).append(value)
    return result


def one[T: (int, bytes)](message: Message, number: int, expected: type[T]) -> T:
    values = message.get(number, [])
    if len(values) != 1 or not isinstance(values[0], expected):
        raise ProtocolError(f"Missing, duplicate or invalid field {number}")
    return values[0]


def exact(stream: Stream, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = stream.recv(size - len(chunks))
        if not part:
            raise EOFError("Peer closed the connection")
        chunks.extend(part)
    return bytes(chunks)


def send_frame(stream: Stream, payload: bytes) -> None:
    if not 0 < len(payload) <= 65535:
        raise ProtocolError("Invalid MDG frame size")
    stream.sendall(struct.pack(">H", len(payload)) + payload)


def read_frame(stream: Stream) -> bytes:
    size = int.from_bytes(exact(stream, 2), "big")
    if size == 0:
        raise ProtocolError("Empty MDG frame")
    return exact(stream, size)


def send(stream: Stream, tag: int, body: bytes = b"") -> None:
    send_frame(stream, bytes([tag]) + body)


def receive(stream: Stream, expected: int | None = None) -> tuple[int, Message]:
    payload = read_frame(stream)
    if expected is not None and payload[0] != expected:
        raise ProtocolError(f"Expected message {expected}, received {payload[0]}")
    return payload[0], decode(payload[1:])


def hello(magic: int) -> bytes:
    return field(1, magic, fixed=True) + field(2, 1) + field(3, 0)


def control_reply(stream: Stream, expected_tag: int, request_id: int) -> Message:
    for _ in range(32):
        tag, message = receive(stream)
        if tag == 4:
            send(stream, 5, field(1, one(message, 1, int)))
        elif tag == 1:
            if tuple(one(message, n, int) for n in (1, 2, 3)) != (4036857000, 1, 0):
                raise ProtocolError("Unsupported MDG handshake")
        elif tag == expected_tag and one(message, 1, int) == request_id:
            return message
        elif tag in (2, 3):
            raise ProtocolError("MDG closed the session or requested reconnection")
        else:
            raise ProtocolError(f"Unexpected control message {tag}")
    raise ProtocolError("Too many control messages")
