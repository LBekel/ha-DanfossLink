import socket
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest
from conftest import certificate
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from ecdsa import VerifyingKey
from tlslite import HandshakeSettings, TLSConnection

from custom_components.danfoss_link.protocol import AuthenticationError
from custom_components.danfoss_link.tls import (
    ControlTrust,
    DeadlineSocket,
    MDGConnection,
    public_identity,
    verify_peer,
)


def test_controller_key_is_pinned():
    _, cert = certificate()
    _, other = certificate()
    peer_id, public_key = public_identity(cert)
    verify_peer(cert, peer_id, public_key)
    with pytest.raises(AuthenticationError):
        verify_peer(other, peer_id, public_key)
    with pytest.raises(AuthenticationError):
        verify_peer(b"invalid", peer_id, public_key)


def trust_and_leaf(*, expired=False, wrong_signer=False):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic MDG CA")])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=3))
    )
    root = builder.not_valid_after(now + timedelta(days=10)).sign(key, hashes.SHA256())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic server")])
        )
        .issuer_name(name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(leaf_key if wrong_signer else key, hashes.SHA256())
    )
    trust = object.__new__(ControlTrust)
    trust.root = root
    trust.key = VerifyingKey.from_der(
        key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return trust, leaf.public_bytes(serialization.Encoding.DER)


def test_control_ca_signature_and_validity():
    trust, cert = trust_and_leaf()
    trust.verify(cert)
    for kwargs in ({"expired": True}, {"wrong_signer": True}):
        trust, cert = trust_and_leaf(**kwargs)
        with pytest.raises(AuthenticationError):
            trust.verify(cert)


def test_group_29_is_not_accepted_as_ephemeral_x25519():
    connection = object.__new__(MDGConnection)
    exchange = Mock(acceptedCurves=[23, 29])
    with patch.object(TLSConnection, "_clientKeyExchange", return_value=iter(())):
        list(
            connection._clientKeyExchange(
                None, None, None, None, None, None, None, None, exchange
            )
        )
    assert exchange.acceptedCurves == [23]


def test_curve_exception_is_local_and_preserves_settings():
    connection = MDGConnection(Mock(spec=socket.socket))
    connection.version = (3, 3)
    key = Mock(curve_name="BRAINPOOLP320r1")
    chain = Mock()
    chain.getEndEntityPublicKey.return_value = key
    settings = HandshakeSettings()
    original = list(settings.eccCurves)
    with patch.object(
        TLSConnection, "_check_certchain_with_settings", return_value=iter([key])
    ) as check:
        assert list(connection._check_certchain_with_settings(chain, settings)) == [key]
    assert settings.eccCurves == original
    assert "BRAINPOOLP320r1" in check.call_args.args[1].eccCurves


def test_total_transaction_deadline():
    sock = Mock(spec=socket.socket)
    stream = DeadlineSocket(sock, time.monotonic() - 1)
    with pytest.raises(TimeoutError):
        stream.recv(1)
    sock.recv.assert_not_called()
