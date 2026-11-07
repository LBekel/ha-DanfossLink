"""Synthetic identities and a real, isolated Home Assistant core."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from asn1crypto import algos, core, keys, pem, x509
from ecdsa import SigningKey
from ecdsa.curves import BRAINPOOLP320r1
from ecdsa.util import sigencode_der
from homeassistant import loader
from homeassistant.config_entries import ConfigEntries
from homeassistant.core import HomeAssistant
from homeassistant.helpers import (
    area_registry,
    device_registry,
    entity_registry,
    floor_registry,
    frame,
    label_registry,
)


@pytest.fixture
def room_data():
    return {
        "id": 7,
        "name": "Test room",
        "ambientTemperature": 20.5,
        "minSetpoint": 5,
        "maxSetpoint": 28,
        "setpoint": {"temperature": 19.5, "type": "Adjustable"},
        "regulationState": "Heating",
        "hasTemperatureSensor": True,
    }


def certificate():
    key = SigningKey.generate(curve=BRAINPOOLP320r1)
    public = keys.PublicKeyInfo.load(
        key.verifying_key.to_der(curve_parameters_encoding="explicit")
    )
    digest = hashlib.sha1(public["public_key"].native).digest()
    name = x509.Name.build({"common_name": "Synthetic test identity"})
    signature = algos.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"})
    now = datetime.now(UTC)
    tbs = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": 1,
            "signature": signature,
            "issuer": name,
            "subject": name,
            "subject_public_key_info": public,
            "validity": {
                "not_before": x509.Time(
                    {"utc_time": core.UTCTime(now - timedelta(days=1))}
                ),
                "not_after": x509.Time(
                    {"utc_time": core.UTCTime(now + timedelta(days=30))}
                ),
            },
            "extensions": [{"extn_id": "key_identifier", "extn_value": digest}],
        }
    )
    cert = x509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": signature,
            "signature_value": key.sign_deterministic(
                tbs.dump(),
                hashfunc=hashlib.sha256,
                sigencode=sigencode_der,
            ),
        }
    ).dump()
    return key, cert


@pytest.fixture
def identity_directory(tmp_path):
    import base64

    key, cert = certificate()
    _, peer = certificate()
    from custom_components.danfoss_link.tls import public_identity

    directory = tmp_path / "identity"
    directory.mkdir()
    (directory / "client.pem").write_bytes(pem.armor("CERTIFICATE", cert))
    (directory / "client-key.pem").write_bytes(
        key.to_pem(format="ssleay", curve_parameters_encoding="explicit")
    )
    (directory / "pairing-test.json").write_text(
        json.dumps(
            {
                "peer_id": public_identity(peer)[0],
                "authenticated_by": "PACE",
                "certificate_der_base64": base64.b64encode(peer).decode("ascii"),
            }
        )
    )
    return directory


@pytest.fixture
async def hass(tmp_path):
    (tmp_path / "custom_components").symlink_to(
        Path(__file__).parents[1] / "custom_components", target_is_directory=True
    )
    instance = HomeAssistant(str(tmp_path))
    loader.async_setup(instance)
    frame.async_setup(instance)
    device_registry.async_setup(instance)
    instance.config_entries = ConfigEntries(instance, {})
    await instance.config_entries.async_initialize()
    await asyncio.gather(
        *(
            module.async_load(instance)
            for module in (
                area_registry,
                device_registry,
                entity_registry,
                floor_registry,
                label_registry,
            )
        )
    )
    yield instance
    await instance.async_stop(force=True)
