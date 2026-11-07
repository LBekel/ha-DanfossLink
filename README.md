# Danfoss Link for Home Assistant

Experimental custom integration that creates **one `climate` entity per
room**. It connects Home Assistant directly to the paired Link CC through
Danfoss MDG servers. No gateway service, MQTT broker, WSL installation on the
Home Assistant host, or modified OpenSSL installation is required.

## Requirements

- **Home Assistant Core 2026.11.0 or later**, running Python 3.14.2 or later.
  The integration uses native temperature attributes and Probatio. Older Home
  Assistant versions are not supported.
- An internet-connected Danfoss Link CC, with outbound access to the MDG
  control servers and the routing endpoint assigned by the server.
- For a new pairing, access to the Link CC to read its short-lived **remote
  connection code**. Alternatively, you can import an existing pairing using
  `client.pem`, `client-key.pem`, and exactly one `pairing-*.json` file.

## Installation

### HACS

After this integration is published in HACS, find **Danfoss Link** under
**Settings > Devices & services > Add integration**, or install it from the
HACS integration store. If it is not listed yet, add the GitHub repository
[`LBekel/ha-DanfossLink`](https://github.com/LBekel/ha-DanfossLink) as a
custom repository in HACS and select the **Integration** category. Restart
Home Assistant after installation.

### Manual installation

1. Copy `custom_components/danfoss_link` from this project to
   `/config/custom_components/danfoss_link` on the Home Assistant server.
   Here, `/config` is the server's Home Assistant configuration directory,
   not a path on your development computer.
2. Restart Home Assistant. Dependencies declared in `manifest.json` are
   installed automatically.
3. Go to **Settings > Devices & services > Add integration**, select
   **Danfoss Link**, and choose **Pair using a connection code** or
   **Import an existing pairing**.

Keep the `brand` subdirectory, including `icon.png` and `dark_icon.png`, when
copying the integration. It contains the integration icons for light and dark
themes. Room thermostats use `mdi:heating-coil`.

### Pairing a new controller in the setup flow

1. Choose **Pair using a connection code** and start preparation. The
   integration creates a dedicated identity and verifies the authenticated
   MDG connection. **Do not activate pairing on the controller yet.**
2. When the connection-code field appears, activate pairing on the Link CC and
   enter the **complete connection code within one minute**. Spaces and
   hyphens are ignored; leading zeroes in the password portion are preserved.
   The field is masked.
3. Home Assistant performs PACE and the contact exchange, saves the
   authenticated pairing, and reads the rooms. No manually copied key files
   are needed.

An incorrect or expired code is never resent automatically. After a failed
attempt, request a **fresh code** from the controller and explicitly retry.
Codes starting with `0000` use the local-LAN method, which is not supported;
you need a remote connection code.

If pairing succeeds but saving the pairing locally or reading the rooms fails,
the flow remains at **Finish the authenticated pairing**. Fix the reported
problem and retry there; no new PACE pairing or connection code is needed.
Reauthentication can also pair or import again, but only the original
controller is accepted.

### Importing an existing pairing

Create a private directory such as `/config/danfoss_link` on the Home
Assistant server and copy the matching `client.pem`, `client-key.pem`, and
exactly one `pairing-*.json` file into it. On Linux, use directory permissions
`0700` and file permissions `0600`; the Home Assistant process must be able to
read the files. In the setup flow, choose **Import an existing pairing** and
enter either the relative path `danfoss_link` or the absolute path
`/config/danfoss_link`.

The setup verifies the identity, authenticates the peers, and reads the room
list. **It does not change any heating settings.** All rooms appear under one
**Danfoss Link** device. Setting up the same controller more than once is
prevented.

### Private data and recovery

New identities are stored below
`/config/.storage/danfoss_link/identity-*`. On Linux, directories have
permissions `0700` and files `0600`. The Home Assistant config entry stores
only the identity directory path; the connection code and router token are
not stored there or in the pairing files. A pairing file is written
atomically only after a successful PACE proof and complete contact exchange.
Existing identities are never overwritten, including during reauthentication.

Client keys are persisted before the first network pairing attempt. If an
attempt is interrupted, they are retained for recovery: the controller may
already know the client even if its final response was lost. Directories
without a `pairing-*.json` file are not yet importable pairings. While the
setup flow remains open, an explicit retry reuses the same client identity.
After a Home Assistant restart, a result not yet saved locally is lost; pairing
again may be necessary, and old contacts may need to be managed manually on
the controller. Once the contact exchange has been saved successfully, the
three files can also be loaded through the import flow.

Do not include private files in this project, public shares, support logs, or
unencrypted backups. They are intentionally excluded from the source code and
installation archive. When moving to another Home Assistant installation,
transfer them securely or pair again there.

## Entities and behavior

| Property | Behavior |
|---|---|
| Room name | Name reported by the controller; renaming does not change the unique ID |
| Unique ID | Controller key ID and numeric room ID |
| Current temperature | `ambientTemperature`, when a temperature sensor is present |
| Target temperature | Current `setpoint.temperature`, not the stored manual setpoint |
| Limits | The room's `minSetpoint` and `maxSetpoint` |
| Heating activity | `Heating` means heating; `Deadband` means inactive; unknown values remain unknown |
| HVAC mode | `heat` only; does not change the regulation mode or schedules |
| Refresh | Every 60 seconds; read back immediately after a successful write |
| Added/removed rooms | New rooms are added automatically; missing rooms become unavailable |
| Failures | Communication errors make entities unavailable; certificate errors require reauthentication |

Values such as `777`, invalid numbers, and missing measurements are not shown
as real temperatures. Rooms without an adjustable setpoint remain readable but
do not offer temperature control. Invalid setpoint limits disable control.

`climate.set_temperature` first reads the current room and its limits, sends
exactly one room-specific PATCH, and then reads the room list again. If the
write result is ambiguous, **no automatic retry is attempted**; the service
reports an error. Check the current controller state before manually retrying.

Example using a placeholder entity ID that must be replaced with the one in
your Home Assistant instance:

```yaml
action: climate.set_temperature
target:
  entity_id: climate.danfoss_link_test_room
data:
  temperature: 20
```

Controller schedules and stored comfort, away, and manual temperatures are not
changed. How long a current setpoint remains in effect while a schedule is
active is determined by the controller. Turning the system off, pausing it
globally, vacation mode, schedules, local-LAN pairing, and discovery of
individual radiator valves are not supported.

## Transport and trust model

The integration uses `tlslite-ng==0.8.2`, `ecdsa`, and `asn1crypto`. It enforces
TLS 1.2 with ECDHE-ECDSA and AES-256-GCM. MDG-specific BrainpoolP320r1
certificate support is scoped to these connections; global TLS settings and
Home Assistant's OpenSSL configuration are unchanged.

MDG interprets TLS group 29 differently from modern X25519. The integration
advertises it only for certificate compatibility; ephemeral ECDHE key
exchange is restricted to P-256. A small version-pinned subclass adapts two
internal tlslite-ng hooks, so do not update the library without rerunning the
protocol tests.

Control certificates must be signed directly by the bundled public MDG CA
extracted from the app and must be valid. As in the app, a conventional DNS
hostname is not checked for these fixed IP endpoints. Before sending an API
message, the controller key and ID are compared with the PACE-authenticated
pairing. There is no option to disable these checks.

Every read or write uses a new authenticated connection, after which all
sockets are closed. There is no permanently unattended control connection;
the next poll reconnects after a failure. Each operation has a 45-second
overall limit, with shorter timeouts for individual network operations.
Requests are serialized and run outside the Home Assistant event loop.

This is not an official Danfoss integration and is not guaranteed to work
with every firmware version or future cloud change. The specialized
cryptography and undocumented protocol remain compatibility risks.

## Development

In a separate Python 3.14 environment:

```sh
python -m pip install -r requirements-test.txt
python -m pytest -q
ruff check custom_components tests
```

Tests use synthetic room data and newly generated test keys. They do not
connect to a real controller or write real heating values. They cover framing,
certificate trust, pinning, write protection, error handling, setup, room
discovery, and unloading in a real Home Assistant Core instance. Simulated
controllers test PACE, including an incorrect code, a tampered proof, a lost
contact exchange, and storage failures. Setup-flow pairing, retries, import,
and reauthentication are also covered.

Further technical details: [API.md](API.md) and
[MDG-PROTOCOL.md](MDG-PROTOCOL.md).
