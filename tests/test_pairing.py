import base64
import hashlib
import hmac
import json
import os
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from asn1crypto import pem, x509
from conftest import certificate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ecdsa.util import sigdecode_der

from custom_components.danfoss_link import pairing as p
from custom_components.danfoss_link.client import DanfossClient
from custom_components.danfoss_link.protocol import DanfossError, ProtocolError
from custom_components.danfoss_link.tls import public_identity

CODE = "12345600007"  # Synthetic; never sent to a real controller.


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setattr(p.PairingSession, "_control", Mock())
    return p.PairingSession.prepare(str(tmp_path / "managed"))


def server_exchange(
    stream, server_public, client_public, events, *, bad_proof=False, lost_contact=False
):
    _, message = p.receive(stream, 1)
    assert p.one(message, 1, int) == 4036856999
    values = (b"00007", server_public, client_public)
    password = b"".join(struct.pack(">H", len(v)) + v for v in values) + b"\xff"
    key = hashlib.pbkdf2_hmac("sha256", password, b"1234", 1024, 32)[:16] + bytes(16)
    scalar, x, a = 123456789, 987654321, 314159265
    encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    encrypted = (
        encryptor.update(scalar.to_bytes(40, "big") + bytes(24)) + encryptor.finalize()
    )
    p.send(
        stream,
        2,
        p.field(1, 1)
        + p.field(2, 0)
        + p.field(3, b"1234")
        + p.field(4, bytes(range(16)))
        + p.field(5, encrypted),
    )
    _, message = p.receive(stream, 3)
    client_xy = p.read_point(p.one(message, 1, bytes))
    p.send(stream, 3, p.field(1, p.point_bytes(p.CURVE.generator * x)))
    mapped = p.CURVE.generator * scalar + client_xy * x
    own = mapped * a
    _, message = p.receive(stream, 4)
    client_pk = p.read_point(p.one(message, 1, bytes))
    p.send(stream, 4, p.field(1, p.point_bytes(own)))
    key = hashlib.sha256(p.point_bytes(client_pk * a)).digest()
    _, message = p.receive(stream, 5)
    expected = hmac.new(key, p.point_bytes(own), hashlib.sha256).hexdigest().encode()
    valid = hmac.compare_digest(p.one(message, 1, bytes), expected)
    events.append(("client_proof", valid))
    proof = hmac.new(key, p.point_bytes(client_pk), hashlib.sha256).hexdigest().encode()
    p.send(stream, 5, p.field(1, b"x" * 64 if bad_proof else proof))
    if not valid or bad_proof:
        assert stream.recv(1) == b""
        return
    _, message = p.receive(stream, 6)
    assert p.one(message, 1, bytes) == b"Home Assistant"
    events.append(("contact", True))
    if not lost_contact:
        p.send(stream, 6, p.field(1, "Synthetic controller"))


def exchange(
    session, monkeypatch, *, code=CODE, bad_proof=False, lost_contact=False, error=None
):
    _, peer_cert = certificate()
    server_public = pem.armor("PUBLIC KEY", public_identity(peer_cert)[1])
    client_public = pem.armor(
        "PUBLIC KEY", public_identity(bytes(session.certificate.bytes))[1]
    )
    events = []
    monkeypatch.setattr(p, "control_reply", Mock(return_value={2: [0]}))
    client, server = socket.socketpair()
    client.settimeout(4)
    server.settimeout(4)

    class PeerStream:
        certificate_der = peer_cert

        def sendall(self, data):
            client.sendall(data)

        def recv(self, size):
            return client.recv(size)

    def route(response, deadline, stack, authenticate):
        authenticate(peer_cert)
        stack.callback(client.close)
        return PeerStream()

    def run_server():
        with server:
            server_exchange(
                server,
                server_public,
                client_public,
                events,
                bad_proof=bad_proof,
                lost_contact=lost_contact,
            )

    monkeypatch.setattr(session, "_route", route)
    with client, ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(run_server)
        if error is not None:
            with pytest.raises(p.PairingError, match=error):
                session.pair(code)
        else:
            assert session.pair(code) == public_identity(peer_cert)[0]
        future.result(timeout=5)
    return events, peer_cert


def test_code_normalization_preserves_leading_otp_zeroes():
    assert p.split_code("123-456 00007") == ("123456", b"00007")


@pytest.mark.parametrize(
    "code,error",
    [
        ("0000123456", "local_code"),
        ("00007", "invalid_code"),
        ("1234abc00007", "invalid_code"),
        ("", "invalid_code"),
        ("1" * 129, "invalid_code"),
        (1234567, "invalid_code"),
    ],
)
def test_invalid_codes_are_rejected_without_persistence(session, code, error):
    session._control.reset_mock()
    with pytest.raises(p.PairingError, match=error):
        session.pair(code)
    session._control.assert_not_called()
    assert session.directory is None
    assert list(session._root.iterdir()) == []


def test_preparation_does_not_leave_private_files(session):
    assert session.directory is None
    assert not list(session._root.iterdir())
    cert = x509.Certificate.load(bytes(session.certificate.bytes))
    assert cert.public_key["algorithm"]["parameters"].name == "specified"
    validity = cert["tbs_certificate"]["validity"]
    assert validity["not_before"].native.microsecond == 0
    assert validity["not_after"].native.microsecond == 0
    if validity["not_after"].native.year < 2050:
        assert validity["not_after"].name == "utc_time"
    assert p.public_identity(bytes(session.certificate.bytes))[0]
    session.certificate.publicKey.public_key.verify(
        cert["signature_value"].native,
        cert["tbs_certificate"].dump(),
        hashfunc=hashlib.sha256,
        sigdecode=sigdecode_der,
    )


def test_successful_pairing_is_persistent_and_importable(session, monkeypatch):
    events, peer_cert = exchange(session, monkeypatch)
    assert events == [("client_proof", True), ("contact", True)]
    client = DanfossClient(str(session.directory))
    assert client.peer_id == public_identity(peer_cert)[0]
    record = json.loads((session.directory / "pairing-controller.json").read_text())
    assert record["authenticated_by"] == "PACE"
    assert base64.b64decode(record["certificate_der_base64"]) == peer_cert
    assert set(record) == {
        "peer_id",
        "name",
        "authenticated_by",
        "certificate_der_base64",
        "paired_at_unix",
    }
    assert not list(session.directory.glob(".pairing-*"))
    session._control.reset_mock()
    assert session.pair(CODE) == client.peer_id
    session._control.assert_not_called()
    if os.name == "posix":
        assert session.directory.stat().st_mode & 0o777 == 0o700
        assert all(
            path.stat().st_mode & 0o777 == 0o600 for path in session.directory.iterdir()
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"code": "12345600008"},
        {"bad_proof": True},
    ],
)
def test_bad_code_or_proof_never_saves_or_exchanges_contact(
    session, monkeypatch, kwargs
):
    events, _ = exchange(session, monkeypatch, error="pairing_proof_failed", **kwargs)
    assert ("contact", True) not in events
    assert session.peer_id is None and session._record is None
    assert not list(session.directory.glob("pairing-*.json"))


def test_lost_contact_keeps_client_key_but_does_not_claim_success(session, monkeypatch):
    events, _ = exchange(
        session, monkeypatch, lost_contact=True, error="pairing_failed"
    )
    assert ("contact", True) in events
    assert (session.directory / "client-key.pem").is_file()
    assert session.peer_id is None
    assert not list(session.directory.glob("pairing-*.json"))


def test_expired_code_is_attempted_once(session, monkeypatch):
    session._control.reset_mock()
    monkeypatch.setattr(p, "control_reply", Mock(return_value={2: [1]}))
    route = Mock()
    monkeypatch.setattr(session, "_route", route)
    with pytest.raises(p.PairingError, match="pairing_unavailable"):
        session.pair(CODE)
    session._control.assert_called_once()
    route.assert_not_called()
    assert session.peer_id is None


@pytest.mark.parametrize("existing", [False, True])
def test_wrong_or_existing_controller_is_rejected_before_pace(
    session, monkeypatch, existing
):
    _, cert = certificate()
    peer_id = public_identity(cert)[0]
    monkeypatch.setattr(p, "control_reply", Mock(return_value={2: [0]}))
    monkeypatch.setattr(
        session, "_route", Mock(return_value=Mock(certificate_der=cert))
    )
    pace = Mock()
    monkeypatch.setattr(p, "pace", pace)
    with pytest.raises(
        p.PairingError, match="already_configured" if existing else "wrong_controller"
    ):
        session.pair(
            CODE,
            None if existing else "different-controller",
            frozenset([peer_id]) if existing else frozenset(),
        )
    pace.assert_not_called()
    assert session.peer_id is None


def test_storage_failure_retries_locally_without_pairing_again(session, monkeypatch):
    replace = os.replace
    monkeypatch.setattr(p.os, "replace", Mock(side_effect=OSError("Disk failure")))
    exchange(session, monkeypatch, error="cannot_store_pairing")
    assert session.peer_id is not None
    assert not (session.directory / "pairing-controller.json").exists()
    monkeypatch.setattr(p.os, "replace", replace)
    session._control.reset_mock()
    session.save_pairing()
    session._control.assert_not_called()
    assert DanfossClient(str(session.directory)).peer_id == session.peer_id


def test_preparation_connection_failure_never_requests_a_code(tmp_path, monkeypatch):
    monkeypatch.setattr(
        p.PairingSession, "_control", Mock(side_effect=DanfossError("Offline"))
    )
    with pytest.raises(DanfossError):
        p.PairingSession.prepare(str(tmp_path / "managed"))
    assert not list((tmp_path / "managed").iterdir())


def test_private_key_write_failure_is_reported_before_network_pairing(
    session, monkeypatch
):
    original_open = os.open

    def fail_private_key(path, *args, **kwargs):
        if str(path).endswith("client-key.pem"):
            raise PermissionError("Read-only storage")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(p.os, "open", fail_private_key)
    session._control.reset_mock()
    with pytest.raises(p.PairingError, match="cannot_store_pairing"):
        session.pair(CODE)
    session._control.assert_not_called()
    assert session.directory is None
    assert not list(session._root.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permissions")
def test_preparation_rejects_public_storage_directory(tmp_path, monkeypatch):
    root = tmp_path / "managed"
    root.mkdir(mode=0o755)
    control = Mock()
    monkeypatch.setattr(p.PairingSession, "_control", control)
    with pytest.raises(p.PairingError, match="cannot_store_pairing"):
        p.PairingSession.prepare(str(root))
    control.assert_not_called()
    assert not list(root.iterdir())


@pytest.mark.parametrize("data", [b"\x00", b"\x04" + bytes(80), b"\x04" + b"\xff" * 80])
def test_invalid_curve_points(data):
    with pytest.raises(ProtocolError):
        p.read_point(data)


def test_exact_kdf_and_aes_encoding():
    values = (b"00007", b"server", b"client")
    serialized = b"\x00\x0500007\x00\x06server\x00\x06client\xff"
    expected = hashlib.pbkdf2_hmac("sha256", serialized, b"1234", 1024, 32)[
        :16
    ] + bytes(16)
    assert p.derive_key(*values, b"1234") == expected
    encryptor = Cipher(algorithms.AES(expected), modes.CBC(bytes(16))).encryptor()
    encrypted = (
        encryptor.update((123456789).to_bytes(40, "big") + bytes(24))
        + encryptor.finalize()
    )
    assert p.decrypt_scalar(expected, encrypted) == 123456789
    with pytest.raises(ProtocolError):
        p.decrypt_scalar(expected, encrypted[:-1])
