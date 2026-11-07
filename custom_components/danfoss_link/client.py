"""Synchronous, serialized and bounded authenticated Danfoss Link access."""

import base64
import json
import re
import socket
import threading
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from tlslite import X509
from tlslite.errors import BaseTLSException
from tlslite.utils.keyfactory import parsePEMKey

from .models import Room, parse_rooms
from .protocol import (
    AuthenticationError,
    CommandError,
    DanfossError,
    InvalidIdentityError,
    ProtocolError,
    control_reply,
    decode,
    field,
    hello,
    one,
    read_frame,
    receive,
    send,
    send_frame,
)
from .tls import (
    ControlTrust,
    DeadlineSocket,
    TLSChannel,
    check_client_key,
    public_identity,
    verify_peer,
)

HOSTS = ("77.66.11.90", "77.66.11.92", "5.179.92.180", "5.179.92.182")
TRANSACTION_TIMEOUT = 45


def _read_private(path: Path) -> str:
    with path.open("r", encoding="utf-8") as file:
        content = file.read(65537)
    if len(content) > 65536:
        raise InvalidIdentityError("Identity file is too large")
    return content


class JsonSession:
    def __init__(self, stream) -> None:
        self.stream = stream
        self.request_id = 0

    def request(self, method: str, uri: str, content=None):
        self.request_id += 1
        body = {
            "method": method,
            "uri": uri,
            "headers": ["Accept: application/json; charset=utf-8"],
        }
        if content is not None:
            body["content"] = content
        payload = {
            "id": self.request_id,
            "data": {"type": "JsonWebRequest", "data": body},
        }
        send_frame(
            self.stream,
            json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8"),
        )
        try:
            response = json.loads(read_frame(self.stream))
        except (ValueError, UnicodeError) as err:
            raise ProtocolError("Invalid JSON response") from err
        if not isinstance(response, dict) or type(response.get("id")) is not int:
            raise ProtocolError("Missing JSON response identity")
        if response["id"] != self.request_id:
            raise ProtocolError("Unexpected JSON response identity")
        envelope = response.get("data")
        if not isinstance(envelope, dict) or envelope.get("type") != "JsonWebResponse":
            raise ProtocolError("Unexpected JSON response type")
        data = envelope.get("data")
        if not isinstance(data, dict) or type(data.get("status")) is not int:
            raise ProtocolError("Missing JSON response status")
        if data["status"] in (401, 403):
            raise AuthenticationError("Controller refused the paired identity")
        if not 200 <= data["status"] < 300:
            raise ProtocolError(f"Controller returned status {data['status']}")
        return data.get("content")


class MDGTransport:
    """Shared authenticated control and routing transport for API and pairing."""

    def __init__(self, certificate: X509, private_key) -> None:
        check_client_key(certificate, private_key)
        self.certificate = certificate
        self.private_key = private_key
        self.trust = ControlTrust()
        self._lock = threading.Lock()
        self._preferred_host = HOSTS[0]

    def _connect(
        self, host: str, port: int, deadline: float, stack: ExitStack
    ) -> DeadlineSocket:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Danfoss transaction timed out")
        sock = socket.create_connection((host, port), timeout=min(5, remaining))
        stack.callback(sock.close)
        return DeadlineSocket(sock, deadline)

    def _control(self, deadline: float, stack: ExitStack) -> TLSChannel:
        hosts = (
            self._preferred_host,
            *(host for host in HOSTS if host != self._preferred_host),
        )
        last_error = None
        for host in hosts:
            try:
                with ExitStack() as attempt:
                    stream = TLSChannel(
                        self._connect(host, 443, deadline, attempt),
                        self.certificate,
                        self.private_key,
                        self.trust.verify,
                    )
                    send(stream, 1, hello(4036857000))
                    send(stream, 4, field(1, 1))
                    control_reply(stream, 5, 1)
                    stack.enter_context(attempt.pop_all())
                    self._preferred_host = host
                    return stream
            except (OSError, EOFError, BaseTLSException, ProtocolError) as err:
                last_error = err
        raise DanfossError("No MDG control server is reachable") from last_error

    def _route(
        self, response, deadline: float, stack: ExitStack, authenticate
    ) -> TLSChannel:
        route = decode(one(response, 3, bytes))
        endpoints = route.get(4, [])
        if not endpoints or not isinstance(endpoints[0], bytes):
            raise ProtocolError("MDG returned no routing endpoint")
        endpoint = decode(endpoints[0])
        host = one(endpoint, 1, bytes).decode("ascii")
        port = one(endpoint, 2, int)
        if not re.fullmatch(r"[a-zA-Z0-9.:-]+", host) or not 1 <= port <= 65535:
            raise ProtocolError("Invalid routing endpoint")
        raw = self._connect(host, port, deadline, stack)
        send(
            raw,
            0,
            hello(4036856981) + field(4, one(route, 5, bytes)) + field(5, "tlsv1_2"),
        )
        for _ in range(8):
            tag, reply = receive(raw)
            if tag == 2:
                if reply.get(1, [b"tlsv1_2"]) != [b"tlsv1_2"]:
                    raise ProtocolError("Unsupported routed transport")
                break
            if tag != 1:
                raise ProtocolError("Router could not connect the controller")
        else:
            raise ProtocolError("Routing did not complete")
        return TLSChannel(raw, self.certificate, self.private_key, authenticate)


class DanfossClient(MDGTransport):
    def __init__(self, directory: str) -> None:
        path = Path(directory)
        try:
            records = list(path.glob("pairing-*.json"))
            if len(records) != 1:
                raise InvalidIdentityError("Expected exactly one pairing JSON file")
            record = json.loads(_read_private(records[0]))
            if not isinstance(record, dict) or record.get("authenticated_by") != "PACE":
                raise InvalidIdentityError("Expected a PACE-authenticated pairing")
            peer_cert = base64.b64decode(
                record["certificate_der_base64"], validate=True
            )
            self.peer_id, self.peer_public_key = public_identity(peer_cert)
            if record["peer_id"] != self.peer_id:
                raise InvalidIdentityError(
                    "Stored controller identity does not match its certificate"
                )
            certificate = X509().parse(_read_private(path / "client.pem"))
            private_key = parsePEMKey(
                _read_private(path / "client-key.pem"), private=True
            )
            super().__init__(certificate, private_key)
        except (OSError, ValueError, TypeError, KeyError, SyntaxError) as err:
            raise InvalidIdentityError(
                "Cannot load a complete, matching paired identity"
            ) from err

    @contextmanager
    def _channel(self):
        deadline = time.monotonic() + TRANSACTION_TIMEOUT
        try:
            with ExitStack() as stack:
                control = self._control(deadline, stack)
                send(control, 20, field(1, 2) + field(2, self.peer_id))
                control_reply(control, 21, 2)
                send(
                    control,
                    10,
                    field(1, 3) + field(2, self.peer_id) + field(3, "cc_json"),
                )
                response = control_reply(control, 11, 3)
                if one(response, 2, int) != 0:
                    raise DanfossError("Controller is unavailable through MDG")
                stream = self._route(
                    response,
                    deadline,
                    stack,
                    lambda cert: verify_peer(cert, self.peer_id, self.peer_public_key),
                )
                yield JsonSession(stream)
        except (OSError, EOFError, BaseTLSException) as err:
            raise DanfossError("Danfoss connection failed or timed out") from err
        except UnicodeError as err:
            raise ProtocolError("Malformed MDG text response") from err

    def get_rooms(self) -> dict[int, Room]:
        with self._lock, self._channel() as session:
            return parse_rooms(session.request("GET", "/api/rooms"))

    def set_temperature(self, room_id: int, value: float) -> dict[int, Room]:
        if type(room_id) is not int or room_id < 0:
            raise CommandError("Invalid room identity")
        submitted = False
        try:
            with self._lock, self._channel() as session:
                room = Room.parse(session.request("GET", f"/api/rooms/{room_id}"))
                if room.id != room_id:
                    raise ProtocolError("Controller returned a different room")
                target = room.validate_target(value)
                submitted = True
                session.request(
                    "PATCH",
                    f"/api/rooms/{room_id}",
                    {"id": room_id, "setpoint": {"temperature": target}},
                )
                rooms = parse_rooms(session.request("GET", "/api/rooms"))
                updated = rooms.get(room_id)
                if (
                    updated is None
                    or updated.target is None
                    or abs(updated.target - target) > 0.01
                ):
                    raise CommandError(
                        "Controller did not confirm the requested temperature"
                    )
                return rooms
        except DanfossError as err:
            if submitted:
                raise CommandError(
                    "Temperature change was not confirmed; check the controller before retrying"
                ) from err
            raise
