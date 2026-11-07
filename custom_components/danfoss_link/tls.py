"""Connection-local MDG compatibility using the maintained TLSLite-ng stack."""

import copy
import hashlib
import hmac
import socket
import time
from datetime import UTC, datetime
from pathlib import Path

from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, SignatureAlgorithmOID
from ecdsa import BadSignatureError, VerifyingKey
from ecdsa.curves import BRAINPOOLP320r1
from ecdsa.util import sigdecode_der
from tlslite import X509, HandshakeSettings, TLSConnection, X509CertChain

from .protocol import AuthenticationError, InvalidIdentityError


def public_identity(certificate: bytes) -> tuple[str, bytes]:
    cert = asn1_x509.Certificate.load(certificate, strict=True)
    spki = cert.public_key.dump()
    key = VerifyingKey.from_der(spki)
    if key.curve != BRAINPOOLP320r1:
        raise ValueError("Expected BrainpoolP320r1 identity")
    point = cert.public_key["public_key"].native
    digest = hashlib.sha1(point).digest()
    if not cert.key_identifier or not hmac.compare_digest(cert.key_identifier, digest):
        raise ValueError("Certificate key identifier mismatch")
    return digest.hex(":"), spki


def verify_peer(certificate: bytes, peer_id: str, public_key: bytes) -> None:
    try:
        identity, actual_key = public_identity(certificate)
    except (ValueError, TypeError) as err:
        raise AuthenticationError("Invalid controller certificate") from err
    if identity != peer_id or not hmac.compare_digest(actual_key, public_key):
        raise AuthenticationError("Controller key differs from the saved pairing")


class ControlTrust:
    """Accept only server certificates directly signed by the APK's MDG CA."""

    def __init__(self) -> None:
        pem = Path(__file__).with_name("mdg-ca.pem").read_bytes()
        self.root = x509.load_pem_x509_certificate(pem)
        self.key = X509().parse(pem.decode("ascii")).publicKey.public_key

    def verify(self, certificate: bytes) -> None:
        try:
            leaf = x509.load_der_x509_certificate(certificate)
            now = datetime.now(UTC)
            if leaf.issuer != self.root.subject:
                raise ValueError("Unexpected issuer")
            for cert in (leaf, self.root):
                if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
                    raise ValueError("Expired or not yet valid certificate")
            allowed = {
                SignatureAlgorithmOID.ECDSA_WITH_SHA256,
                SignatureAlgorithmOID.ECDSA_WITH_SHA384,
                SignatureAlgorithmOID.ECDSA_WITH_SHA512,
            }
            if leaf.signature_algorithm_oid not in allowed:
                raise ValueError("Unsupported certificate signature")
            known_extensions = (
                x509.BasicConstraints,
                x509.KeyUsage,
                x509.ExtendedKeyUsage,
                x509.SubjectKeyIdentifier,
                x509.AuthorityKeyIdentifier,
                x509.SubjectAlternativeName,
            )
            for extension in leaf.extensions:
                value = extension.value
                if extension.critical and not isinstance(value, known_extensions):
                    raise ValueError("Unsupported critical certificate extension")
                if isinstance(value, x509.BasicConstraints) and value.ca:
                    raise ValueError("Expected an end-entity certificate")
                if isinstance(value, x509.KeyUsage) and not value.digital_signature:
                    raise ValueError("Certificate cannot sign TLS handshakes")
                if isinstance(value, x509.ExtendedKeyUsage) and (
                    ExtendedKeyUsageOID.SERVER_AUTH not in value
                ):
                    raise ValueError("Certificate cannot authenticate a server")
            self.key.verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                hashfunc=getattr(hashlib, leaf.signature_hash_algorithm.name),
                sigdecode=sigdecode_der,
                allow_truncate=True,
            )
        except (
            ValueError,
            TypeError,
            BadSignatureError,
            x509.DuplicateExtension,
        ) as err:
            raise AuthenticationError(
                "MDG server certificate verification failed"
            ) from err


class DeadlineSocket:
    """Bound the entire transaction, not just individual socket reads."""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self.sock = sock
        self.deadline = deadline

    def _remaining(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Danfoss transaction timed out")
        self.sock.settimeout(min(10, remaining))

    def recv(self, size: int) -> bytes:
        self._remaining()
        return self.sock.recv(size)

    def send(self, data: bytes) -> int:
        self._remaining()
        return self.sock.send(data)

    def sendall(self, data: bytes) -> None:
        self._remaining()
        self.sock.sendall(data)

    def __getattr__(self, name):
        return getattr(self.sock, name)


class MDGConnection(TLSConnection):
    def _check_certchain_with_settings(self, cert_chain, settings):
        key = cert_chain.getEndEntityPublicKey()
        if (
            self.version == (3, 3)
            and getattr(key, "curve_name", None) == "BRAINPOOLP320r1"
        ):
            settings = copy.copy(settings)
            settings.eccCurves = [*settings.eccCurves, "BRAINPOOLP320r1"]
        yield from super()._check_certchain_with_settings(cert_chain, settings)

    def _clientKeyExchange(
        self,
        settings,
        cipherSuite,
        clientCertChain,
        privateKey,
        certificateType,
        tackExt,
        clientRandom,
        serverRandom,
        keyExchange,
    ):
        # MDG calls BrainpoolP320r1 group 29, not X25519. Advertise it for
        # certificate compatibility only; ephemeral ECDHE must use P-256.
        keyExchange.acceptedCurves = [23]
        yield from super()._clientKeyExchange(
            settings,
            cipherSuite,
            clientCertChain,
            privateKey,
            certificateType,
            tackExt,
            clientRandom,
            serverRandom,
            keyExchange,
        )


class TLSChannel:
    def __init__(
        self,
        sock: DeadlineSocket,
        certificate: X509,
        private_key,
        authenticate,
    ) -> None:
        self.connection = MDGConnection(sock)
        settings = HandshakeSettings()
        settings.minVersion = settings.maxVersion = (3, 3)
        settings.cipherNames = ["aes256gcm"]
        settings.keyExchangeNames = ["ecdhe_ecdsa"]
        settings.eccCurves = ["secp256r1", "x25519"]
        settings.keyShares = ["secp256r1"]
        settings.ecdsaSigHashes = ["sha512", "sha384", "sha256"]
        self.connection.handshakeClientCert(
            certChain=X509CertChain([certificate]),
            privateKey=private_key,
            settings=settings,
        )
        chain = self.connection.session.serverCertChain
        if not chain or not chain.x509List:
            raise AuthenticationError("Missing server certificate")
        self.certificate_der = bytes(chain.x509List[0].bytes)
        authenticate(self.certificate_der)

    def recv(self, size: int) -> bytes:
        return self.connection.recv(size)

    def sendall(self, data: bytes) -> None:
        self.connection.sendall(data)


def check_client_key(certificate: X509, private_key) -> None:
    try:
        public_identity(bytes(certificate.bytes))
        if not hmac.compare_digest(
            certificate.publicKey.public_key.to_string(),
            private_key.public_key.to_string(),
        ):
            raise ValueError("Key mismatch")
    except (ValueError, AttributeError) as err:
        raise InvalidIdentityError(
            "Client certificate and private key do not match"
        ) from err
