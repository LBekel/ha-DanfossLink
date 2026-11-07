"""Portable remote PACE pairing with private, recoverable identity storage."""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import tempfile
import time
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path

from asn1crypto import algos, core, keys, pem, x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ecdsa import SigningKey
from ecdsa.curves import BRAINPOOLP320r1 as CURVE
from ecdsa.ellipticcurve import INFINITY, Point
from ecdsa.util import sigencode_der
from tlslite import X509
from tlslite.errors import BaseTLSException
from tlslite.utils.keyfactory import parsePEMKey

from .client import TRANSACTION_TIMEOUT, MDGTransport
from .protocol import (
    AuthenticationError,
    DanfossError,
    ProtocolError,
    Stream,
    control_reply,
    field,
    hello,
    one,
    receive,
    send,
)
from .tls import public_identity


class PairingError(DanfossError):
    """A pairing error with a localized config-flow error key."""

    def __init__(self, error_key: str) -> None:
        super().__init__(error_key)
        self.error_key = error_key


def split_code(code: str) -> tuple[str, bytes]:
    if not isinstance(code, str) or len(code) > 128:
        raise PairingError("invalid_code")
    code = re.sub(r"[- .,]", "", code.strip())
    if not re.fullmatch(r"[0-9]{6,32}", code):
        raise PairingError("invalid_code")
    if code.startswith("0000"):
        raise PairingError("local_code")
    return code[:-5], code[-5:].encode("ascii")


def generate_identity() -> tuple[bytes, bytes]:
    """Generate the APK-compatible explicit-curve identity without OpenSSL."""
    key = SigningKey.generate(curve=CURVE)
    public = keys.PublicKeyInfo.load(
        key.verifying_key.to_der(curve_parameters_encoding="explicit")
    )
    identifier = hashlib.sha1(public["public_key"].native).digest()
    name = x509.Name.build(
        {
            "country_name": "DK",
            "organization_name": "Home Assistant",
            "common_name": "localhost",
        }
    )
    signature = algos.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"})
    now = datetime.now(UTC).replace(microsecond=0)
    expires = now + timedelta(days=3650)
    expiry = (
        x509.Time({"utc_time": core.UTCTime(expires)})
        if expires.year < 2050
        else x509.Time({"general_time": core.GeneralizedTime(expires)})
    )
    tbs = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": secrets.randbits(128) or 1,
            "signature": signature,
            "issuer": name,
            "subject": name,
            "subject_public_key_info": public,
            "validity": {
                "not_before": x509.Time(
                    {"utc_time": core.UTCTime(now - timedelta(minutes=5))}
                ),
                "not_after": expiry,
            },
            "extensions": [
                {"extn_id": "key_identifier", "extn_value": identifier},
                {
                    "extn_id": "authority_key_identifier",
                    "extn_value": {"key_identifier": identifier},
                },
                {
                    "extn_id": "basic_constraints",
                    "critical": True,
                    "extn_value": {"ca": False},
                },
            ],
        }
    )
    certificate = x509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": signature,
            "signature_value": key.sign_deterministic(
                tbs.dump(),
                hashfunc=hashlib.sha256,
                sigencode=sigencode_der,
            ),
        }
    )
    return (
        pem.armor("CERTIFICATE", certificate.dump()),
        key.to_pem(format="ssleay", curve_parameters_encoding="explicit"),
    )


def point_bytes(point) -> bytes:
    if point == INFINITY:
        raise ProtocolError("PACE point at infinity")
    return (
        b"\x04"
        + int(point.x()).to_bytes(40, "big")
        + int(point.y()).to_bytes(40, "big")
    )


def read_point(data: bytes) -> Point:
    if len(data) != 81 or data[0] != 4:
        raise ProtocolError("Expected uncompressed BrainpoolP320r1 point")
    x, y = int.from_bytes(data[1:41], "big"), int.from_bytes(data[41:], "big")
    if not (
        x < CURVE.curve.p() and y < CURVE.curve.p() and CURVE.curve.contains_point(x, y)
    ):
        raise ProtocolError("Invalid PACE point")
    point = Point(CURVE.curve, x, y)
    if point * CURVE.order != INFINITY:
        raise ProtocolError("Invalid PACE point order")
    return point


def derive_key(
    otp: bytes, server_public: bytes, client_public: bytes, salt: bytes
) -> bytes:
    values = (otp, server_public, client_public)
    password = (
        b"".join(struct.pack(">H", len(value)) + value for value in values) + b"\xff"
    )
    # The APK's native wrapper zero-pads its 16-byte KDF result to an AES-256 key.
    return hashlib.pbkdf2_hmac("sha256", password, salt, 1024, 32)[:16] + bytes(16)


def decrypt_scalar(key: bytes, encrypted: bytes) -> int:
    if len(encrypted) != 64:
        raise ProtocolError("Invalid encrypted PACE scalar length")
    # The APK's Lua userdata IV is not converted to bytes by its native wrapper.
    decryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).decryptor()
    plain = decryptor.update(encrypted) + decryptor.finalize()
    return int.from_bytes(plain[:40], "big")


def proof(key: bytes, point) -> bytes:
    return hmac.new(key, point_bytes(point), hashlib.sha256).hexdigest().encode("ascii")


def _sync_directory(directory: Path) -> None:
    if os.name == "posix":
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def pace(
    stream: Stream, otp: bytes, server_public: bytes, client_public: bytes
) -> None:
    send(stream, 1, hello(4036856999))
    _, message = receive(stream, 2)
    if (one(message, 1, int), one(message, 2, int)) != (1, 0):
        raise ProtocolError("Unsupported PACE version")
    salt, iv, encrypted = (one(message, number, bytes) for number in (3, 4, 5))
    if not 0 < len(salt) <= 256 or len(iv) > 16:
        raise ProtocolError("Invalid PACE parameters")
    scalar = decrypt_scalar(
        derive_key(otp, server_public, client_public, salt), encrypted
    )
    x = secrets.randbelow(CURVE.order - 1) + 1
    send(stream, 3, field(1, point_bytes(CURVE.generator * x)))
    _, message = receive(stream, 3)
    mapped = CURVE.generator * scalar + read_point(one(message, 1, bytes)) * x
    if mapped == INFINITY:
        raise ProtocolError("Invalid PACE mapped generator")
    a = secrets.randbelow(CURVE.order - 1) + 1
    own = mapped * a
    send(stream, 4, field(1, point_bytes(own)))
    _, message = receive(stream, 4)
    peer = read_point(one(message, 1, bytes))
    key = hashlib.sha256(point_bytes(peer * a)).digest()
    send(stream, 5, field(1, proof(key, peer)))
    _, message = receive(stream, 5)
    if not hmac.compare_digest(one(message, 1, bytes), proof(key, own)):
        raise PairingError("pairing_proof_failed")


class PairingSession(MDGTransport):
    def __init__(self, root: str) -> None:
        self._root = Path(root)
        self._certificate_pem, self._key_pem = generate_identity()
        super().__init__(
            X509().parse(self._certificate_pem.decode("ascii")),
            parsePEMKey(self._key_pem.decode("ascii"), private=True),
        )
        self.directory: Path | None = None
        self.peer_id: str | None = None
        self._record: dict | None = None
        self._saved = False

    @classmethod
    def prepare(cls, root: str) -> "PairingSession":
        session = cls(root)
        try:
            session._root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.name == "posix" and session._root.stat().st_mode & 0o077:
                raise PairingError("cannot_store_pairing")
            with tempfile.TemporaryFile(dir=session._root):
                pass
            with ExitStack() as stack:
                session._control(time.monotonic() + TRANSACTION_TIMEOUT, stack)
        except OSError as err:
            raise PairingError("cannot_prepare") from err
        return session

    def _save_identity(self) -> None:
        if self.directory is not None:
            return
        try:
            directory = Path(tempfile.mkdtemp(prefix="identity-", dir=self._root))
            try:
                for name, data in (
                    ("client.pem", self._certificate_pem),
                    ("client-key.pem", self._key_pem),
                ):
                    fd = os.open(
                        directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                    )
                    with os.fdopen(fd, "wb") as file:
                        file.write(data)
                        file.flush()
                        os.fsync(file.fileno())
                _sync_directory(directory)
                _sync_directory(self._root)
            except OSError:
                for name in ("client.pem", "client-key.pem"):
                    (directory / name).unlink(missing_ok=True)
                directory.rmdir()
                raise
            self.directory = directory
        except OSError as err:
            raise PairingError("cannot_store_pairing") from err

    def save_pairing(self) -> None:
        if self.directory is None or self._record is None:
            raise ProtocolError("No completed pairing to save")
        if self._saved:
            return
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=".pairing-", dir=self.directory)
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(self._record, file, ensure_ascii=True, allow_nan=False)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, self.directory / "pairing-controller.json")
            _sync_directory(self.directory)
            self._saved = True
        except OSError as err:
            raise PairingError("cannot_store_pairing") from err
        finally:
            if temporary is not None:
                try:
                    Path(temporary).unlink(missing_ok=True)
                except OSError as err:
                    raise PairingError("cannot_store_pairing") from err

    def pair(
        self,
        code: str,
        expected_peer_id: str | None = None,
        configured_peer_ids: frozenset[str] = frozenset(),
    ) -> str:
        pair_id, otp = split_code(code)
        with self._lock:
            if self.peer_id is not None:
                self.save_pairing()
                return self.peer_id
            self._save_identity()
            deadline = time.monotonic() + TRANSACTION_TIMEOUT
            try:
                with ExitStack() as stack:
                    control = self._control(deadline, stack)
                    send(control, 32, field(1, 2) + field(2, pair_id))
                    response = control_reply(control, 33, 2)
                    result = one(response, 2, int)
                    if result == 1:
                        raise PairingError("pairing_unavailable")
                    if result != 0:
                        raise PairingError("pairing_failed")
                    # Only validate the certificate shape here. PACE below, not
                    # this untrusted routing connection, establishes its identity.
                    stream = self._route(response, deadline, stack, public_identity)
                    peer_id, server_public = public_identity(stream.certificate_der)
                    if expected_peer_id is not None and peer_id != expected_peer_id:
                        raise PairingError("wrong_controller")
                    if peer_id in configured_peer_ids:
                        raise PairingError("already_configured")
                    _, client_public = public_identity(bytes(self.certificate.bytes))
                    pace(
                        stream,
                        otp,
                        pem.armor("PUBLIC KEY", server_public),
                        pem.armor("PUBLIC KEY", client_public),
                    )
                    send(stream, 6, field(1, "Home Assistant"))
                    _, contact = receive(stream, 6)
                    name = (
                        one(contact, 1, bytes).decode("utf-8") if 1 in contact else ""
                    )
                    self._record = {
                        "peer_id": peer_id,
                        "name": name,
                        "authenticated_by": "PACE",
                        "certificate_der_base64": base64.b64encode(
                            stream.certificate_der
                        ).decode("ascii"),
                        "paired_at_unix": int(time.time()),
                    }
                    self.peer_id = peer_id
                    self.save_pairing()
                    return peer_id
            except AuthenticationError:
                raise
            except (OSError, EOFError, BaseTLSException, ValueError) as err:
                raise PairingError("pairing_failed") from err
