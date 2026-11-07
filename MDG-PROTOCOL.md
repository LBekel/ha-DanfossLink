# Danfoss Link: MDG Transport and Pairing

Supplement to [API.md](API.md), for the same APK with SHA-256
`324c22e5b3eaa7bb72f208cfcac86fe8416942a38a41639adf7d746ad347232b`.
This description combines static analysis with a successful remote pairing
test on 2026-11-05. The test confirms this specific pairing flow but is not a
complete substitute for the MDG runtime.

## 1. Identity and trust model

At startup, the Android app initializes a native Lua VM. Its file directories
are named `luavm-inputs` and `luadata`. The Android configuration refers to:

```text
luadata/app_key.pem
luadata/app_cert.pem
luadata/pairings/
```

A key and self-signed certificate are generated when needed. The
configuration specifies the `brainpoolP320r1` elliptic curve and
`trusted-CAs.pem` as the CA file. This bundled CA file is not user
authorization and does not replace pairing.

A peer is identified by its certificate identity and its saved public-key
mapping. For normal incoming calls, `mdg_peer_comm.check_socket` verifies:

1. A peer certificate is present.
2. Its Subject Key Identifier matches the peer identifier derived from its
   public key.
3. The identifier and public key match a saved pairing.

The identifier is derived from `pubkey_digest()` and formatted as a
**lowercase**, colon-separated sequence of hexadecimal bytes. Preserve this
format for `set_peer_whitelist` and `place_call`; uppercase caused
`PEER_NOT_AVAILABLE` in the live test. The native implementation uses
**SHA-1 over the SubjectPublicKey BIT STRING** by default, not over the full
certificate or the complete SubjectPublicKeyInfo DER block. This matches
`subjectKeyIdentifier=hash` in the generated certificate.
`meth_pubkey()` returns the public key as PEM SubjectPublicKeyInfo; these PEM
bytes are used in PACE.

The `<pairing>` protocol has a separate trust establishment procedure. It is
not initially checked against the normal pairing whitelist; instead, the
one-time password is cryptographically proven afterward.

TLS is **TLS 1.2** in the examined configurations. The cipher list is:

```text
ECDHE-ECDSA-AES128-GCM-SHA256
ECDHE-ECDSA-AES128-SHA256
ECDHE-ECDSA-AES128-SHA
ECDHE-ECDSA-AES256-GCM-SHA384
ECDHE-ECDSA-AES256-SHA384
ECDHE-ECDSA-AES256-SHA
```

Despite the AES128 entries, `mdg_routing_connection` checks after peer TLS
that there are at least **256 cipher bits**, ECDH(E), ECDSA, and TLS 1.2.
The native `meth_info` function reads the bit count using
`SSL_CIPHER_get_bits`. The successful test offered only the three AES256
suites above on the peer channel and used
`ECDHE-ECDSA-AES256-GCM-SHA384`.

### Non-standard TLS curve mapping

The APK's native library contains **modified OpenSSL 1.0.2s**: TLS group ID
**29 / `0x001d`** is mapped to BrainpoolP320r1. In current standard TLS
implementations, the same number denotes **X25519**. They are therefore not
directly compatible. The APK also creates certificates with explicit EC
parameters.

In the live test, unmodified OpenSSL 3.0.2 failed with
`Certificate public key has explicit ECC parameters`; OpenSSL 1.1.1l and
unmodified 1.0.2u failed with `wrong curve`. Only an isolated 1.0.2u test
library with the reconstructed MDG group mapping enabled the successful
control and peer TLS handshakes. The test maps explicit parameters only after
a complete curve comparison against BrainpoolP320r1.

This obsolete, specially modified runtime is a **test tool**, not a
recommendation to modify global OpenSSL or downgrade production TLS. CA
verification on the control connection remained enabled.

LAN and routing upgrades use the LuaSec extension `verifyext =
"lsec_continue"`. This is not a recommendation to disable certificate
verification in a new client. Pairing, public-key, and peer-ID checks must
remain in place. The native callback details have not been fully reconstructed.

Evidence: `R1/g.java:24-35`, `android_main.lua`,
`common_peer_config.lua:145-225`, `mdg_peer_comm.lua:165-294`,
`mdg_lan_comm.lua:372-413`. Native evidence:
`meth_pubkey_digest` at `0xa5ee4`, `meth_pubkey` at `0xa6038`,
`Ggenerate_self_signed` at `0x15ae2c`, `tls1_ec_nid2curve_id` at
`0x13f328`, and `tls1_set_ec_id` at `0x13f4d4` in the ARM64 library.
Peer TLS checks: `mdg_routing_connection.lua:391-435`, `meth_info` at
`0xa2eb4`.

## 2. LAN discovery and connection

The Android app searches through mDNS/JmDNS for:

```text
_danfoss-mdg._tcp.local.
```

Discovered service names are used as peer IDs. The Android code copies the
IPv4 address and service port into a discovery object. However, the Java MDG
binding does not pass the port to its local request, and
`mdg_lan_comm.connect` uses fixed **TCP port 14641**.

The shared Lua configuration sets `enable_lan_comm = false` and
`enable_mdns = false`. This does not contradict the local Android client:
these flags control Lua services started there, while the Android app has a
separate discovery implementation and can initiate outgoing LAN connections.

### Framing

After the TLS handshake, messages are transported as a **2-byte unsigned
big-endian length**, followed by exactly that number of payload bytes:

```text
uint16_be(payload_length) || payload
```

The length field counts only the payload. There is no HTTP header, WebSocket
handshake, or newline message delimiter here. The field can represent up to
65,535 payload bytes; actual server limits and possible fragmentation
behavior have not been determined live.

### LAN protocol handshake

The first framed client message sent over the TLS socket is:

```text
E4 B7 A4 01 || uint8(protocol_name_length) || protocol_name
```

For `cc_json`, the complete message including the length is:

```text
00 0C E4 B7 A4 01 07 63 63 5F 6A 73 6F 6E
```

The expected framed server response is:

```text
00 04 E4 B7 A4 81
```

After that, the `cc_json` channel carries the UTF-8 JSON documents from
[API.md](API.md), each with its own 2-byte length field. Pairing uses the
nine-byte protocol name `<pairing>` instead of `cc_json`.

Evidence: `U/c.java:145-184`, `R1/a.java:q()`, `R1/h.java:b(),h()`,
`mdg_lan_comm.lua:38-40,72-150,415-499`,
`cotcp.lua:960-970,1040-1062`, `cc_json.lua:528-547`.

## 3. One-time code and pairing flow

The app normalizes entered codes by removing `-`, spaces, `.`, and `,`.
Codes with the **`0000` prefix** are tried against locally discovered
controllers; other codes use the remote pairing path.

The Lua pairing routine splits the normalized code into:

```text
pair_id = all characters before the last five characters
otp     = the last five characters
```

The routine requires more than five characters. Preserve leading zeroes. The
LAN pairing server in the bundled module uses `0000` as its pairing ID. For
remote pairing, the pairing ID is passed to the MDG control service; the last
five characters are used for the PACE proof.

### Flow

1. Start pairing normally on the controller and use the displayed code. The
   APK alone does not grant authorization for an arbitrary device.
2. LAN: establish TLS to port 14641, then perform the LAN handshake for
   `<pairing>`. Remote: call `place_pairing_call` over MDG control and
   establish the relayed routing channel.
3. Negotiate PACE version 1.0 and exchange the messages described below.
4. After a successful proof, exchange `contact_info` with the peer name in
   both directions.
5. Persist the peer certificate/identity and contact information as a
   pairing. Close the pairing connection.
6. Open a new authorized `cc_json` channel for domain operations.

The OTP is therefore not a long-lived password for later API requests.
Persistent identity and saved pairings are the important state.

### Pairing messages

Inside the 2-byte framing, messages have this format:

```text
uint8(message_tag) || protobuf_message
```

Field numbers and types come from `mdg_pairing_pb`. `required`/`optional`
are Proto2 field labels.

| Tag | Message | Fields |
|---|---|---|
| 1 | `pace_client_hello` | `1 magic: fixed32 required`, `2 version_major: uint32 required`, `3 version_minor: uint32 required` |
| 2 | `pace_server_hello` | `1 version_major: uint32 required`, `2 version_minor: uint32 required`, `3 salt: bytes required`, `4 iv: bytes required`, `5 z: bytes required` |
| 3 | `pace_xy` | `1 xy: bytes required` |
| 4 | `pace_pk` | `1 pk: bytes required` |
| 5 | `pace_proof` | `1 token: bytes required` |
| 6 | `contact_info` | `1 name: string optional` |

Client-Hello magic: **4036856999**, version: **1.0**. The message sequence is
ClientHello, ServerHello, XY in both directions, PK in both directions, Proof
in both directions, and ContactInfo in both directions on success.

### What is established about PACE

The Lua module uses BrainpoolP320r1, two EC exchange steps, a
password-dependent encrypted scalar, SHA-256, and HMAC-SHA-256. Password
preprocessing uses these values in order:

```text
otp, server_public_key, client_public_key
```

Each byte string is prefixed by a 2-byte big-endian length; `FF` is appended
at the end. The KDF call is PBKDF2 with SHA-256, 1,024 iterations, and a
32-byte output; the Lua module continues with the first 16 bytes. The
encryption call, however, specifies **`aes-256-cbc`**.

Native analysis and the successful pairing test resolved the previously
unknown encoding rules:

- The AES key consists of those 16 KDF bytes followed by 16 zero bytes. The
  wrapper copies the short key into a buffer that was zeroed beforehand.
- In Lua, the supplied IV is `lbn` userdata. `lua_tolstring` does not convert
  it to bytes, so the native AES IV remains **16 zero bytes**. In this
  APK-compatible flow, the received IV bytes are not used directly as the
  CBC IV.
- AES padding is disabled. The encrypted block is 64 bytes: a 40-byte
  big-endian scalar, left-padded with zeroes, and 24 random bytes. The client
  uses the first 40 bytes after decryption.
- EC points are sent uncompressed as `04 || X[40] || Y[40]`. The first round
  yields `H = x * Y`; the second uses the generator `G' = s * G + H` and
  derives another shared point.
- The MAC key is the **binary SHA-256 digest** of this second shared point.
  The empty-string argument to the Lua digest call is truthy in Lua and
  enables binary output in the native wrapper.
- The proof, by contrast, is the **64-character lowercase hexadecimal
  string** of HMAC-SHA-256 over the peer's PK point. The expected received
  proof uses the local PK point.

These details describe compatibility with the existing protocol, not a
recommendation for a new cryptographic design.

Native evidence: `Gpoint2text` at `0x15ad68`, `pbkdf2` at `0x15c89c`,
`init_encryptor_decryptor` at `0xaa490`, `decrypt_fdecrypt` at `0xaa600`,
`digest_fdigest` at `0xa9858`, `hmac_fdigest` at `0xa72d0`, `Btext` at
`0x15b768`, and `luaV_tostring` at `0x15dc88`.

If PACE fails, the pairing routine returns `invalid password`; other
evidenced errors are `peer not available`, `recv timeout`, and
`protocol error`. In the successful live test, the received PACE proof was
verified, `contact_info` was exchanged in both directions, and only then was
the authenticated peer certificate saved.

During pairing, do not blindly equate the name in `routing_info.peer_name`
with the certificate ID. The original app does not make this comparison
there; the test client initially failed because it added such a condition.
Trust is established through PACE using the two actual TLS public keys, not
this name.

Evidence: `S/j.java:740`, `S/n.java:294-339`,
`pairing_procedure.lua:161-259,268-400`,
`mdg_comm_strategy.lua:396-535`,
`mdg_pairing_protocol.lua:33-35,107-176`,
`mdg_pairing_pb.lua:58-281`, `pace.lua:20-27,86-119,413-561`.

## 4. Remote connection: control and routing

**Port 443 does not mean HTTPS here.** The app uses TLS with a custom binary
MDG control protocol.

### Embedded control addresses

IPv4, each on port 443:

```text
77.66.11.90
77.66.11.92
5.179.92.180
5.179.92.182
```

IPv6, also on port 443:

```text
2001:1448:248:2ea::234:18
2a02:188:3f03:1ea::234:18
2001:1448:248:2ea::234:20
2a02:188:3f03:1ea::234:20
```

The configuration groups these targets into two endpoint sets.
`mdg-danfoss.hosted.trifork.com` appears in the bundled controller/sandbox
configuration but is not set as a separate DNS override by the examined
`android_main.lua`. On 2026-11-05, all four IPv4 addresses were reachable on
TCP port 443. A TLS connection to `77.66.11.90` was additionally established
with the APK CA verified, followed by a successful MDG handshake and ping
response. IPv6 was not tested live.

### Control connection

TCP connection, then TLS, then framed messages:

```text
uint16_be(length) || uint8(tag) || protobuf
```

The Control-Hello contains magic **4036857000**, version **1.0**, and
repeated string properties. The Android app supplies, among other things,
the package name, app version, build time, and device information. The
configured control ping interval is 120 seconds.

| Tag | Message |
|---|---|
| 1 | `handshake` |
| 2 | `bye` |
| 3 | `reconnect` |
| 4 / 5 | `ping` / `ping_reply` |
| 10 / 11 | `place_call` / `place_call_reply` |
| 12 / 13 | `incoming_call` / `incoming_call_reply` |
| 20 / 21 | `set_peer_whitelist` / `set_peer_whitelist_reply` |
| 30 / 31 | `allocate_pairing_channel` / `allocate_pairing_channel_reply` |
| 32 / 33 | `place_pairing_call` / `place_pairing_call_reply` |

Important field assignments:

| Message | Fields; `?` optional, `[]` repeated, otherwise required |
|---|---|
| `handshake` | `1 magic:fixed32`, `2 version_major:uint32`, `3 version_minor:uint32`, `4 property:property[]` |
| `property` | `1 key:string`, `2 value:string` |
| `ping` | `1 req_id:uint32`, `2 perceived_qos:uint32?` |
| `ping_reply` | `1 req_id:uint32` |
| `place_call` | `1 req_id:uint32`, `2 peer_name:string`, `3 protocol:string?`, `4 ticket:string?` |
| `place_call_reply` | `1 req_id:uint32`, `2 result:enum`, `3 routing:routing_info?`, `4 result_text:string?` |
| `place_pairing_call` | `1 req_id:uint32`, `2 pair_id:string` |
| `place_pairing_call_reply` | Same as `place_call_reply` |
| `routing_info` | `3 peer_name:string`, `4 router:endpoint[]`, `5 token:bytes` |
| `endpoint` | `1 host:bytes`, `2 port:uint32` |
| `set_peer_whitelist` | `1 req_id:uint32`, `2 peer_name:string[]` |
| `set_peer_whitelist_reply` | `1 req_id:uint32` |
| `allocate_pairing_channel` | `1 req_id:uint32` |
| `allocate_pairing_channel_reply` | `1 req_id:uint32`, `2 result:enum`, `3 pair_id:string?`, `4 end_of_validity:uint64?` |
| `incoming_call` | `1 req_id:uint32`, `2 routing:routing_info`, `3 protocol:string?`, `4 ticket:string?` |
| `incoming_call_reply` | `1 req_id:uint32`, `2 will_accept_call:bool` |
| `reconnect` | `1 new_host:endpoint?`, `2 suggested_delay:uint32?` |
| `bye` | `1 reason:enum`, `2 reason_text:string?` |

`place_call_result`: `OK=0`, `PEER_NOT_AVAILABLE=1`, `SERVER_ERROR=2`.
`allocate_pairing_channel_result`: `APC_OK=0`, `APC_DENIED=1`,
`APC_SERVER_ERROR=2`.

`bye_reason`: `NO_ERROR=0`, `INTERNAL_ERROR=1`, `SYNTAX_ERROR=2`,
`DENIED=3`, `TEMP_DENIED=4`, `PROTOCOL_ERROR=5`, `TIMEOUT=6`,
`UNSUPPORTED_VERSION=7`.

The descriptor file also contains `incoming_pairing_call` and
`incoming_pairing_call_reply`, but the examined tag table assigns them no
separate message tags. Do not guess tags for them.

### Routing connection

The call response returns `routing_info` with a router target and token. The
client takes the first router entry in `mdg_comm_strategy.connect_via_routing`.
Then it:

1. Opens a separate TCP connection to the supplied router.
2. Sends a framed routing handshake before the peer TLS upgrade.
3. Processes `PleaseHold`, `GoAhead`, or `RoutingError`.
4. After `GoAhead`, upgrades the relayed stream to peer TLS 1.2.
5. Uses the agreed peer data stream, which is `cc_json` for domain requests.

This is **not** the same flow as the direct LAN protocol handshake. For the
remote path, `cc_json` was already specified in `place_call`.

| Tag | Message | Fields |
|---|---|---|
| 0 | `Handshake` | `1 magic:fixed32`, `2 version_major:uint32`, `3 version_minor:uint32`, `4 token:bytes`, `5 supported_protocols:string[]` |
| 1 | `PleaseHold` | No fields |
| 2 | `GoAhead` | `1 selected_protocol:string?` |
| 3 | `RoutingError` | `1 error:enum` |

Routing magic: **4036856981**, version **1.0**. Without a configuration
override, the client advertises `tlsv1_2` as the supported peer protocol. The
upgrade function explicitly sets TLS 1.2.

Routing error values: `NO_ERROR=0`, `SERVER_ERROR=1`, `SYNTAX_ERROR=2`,
`INVALID_TOKEN=3`, `PEER_TIMEOUT=4`, `UNSUPPORTED_VERSION=5`.

Evidence: `common_peer_config.lua:45-134`, `cc_main.lua:13`,
`mdg_control_connection.lua:797-848`,
`mdg_control_protocol.lua:10-155`, `mdg_control_pb.lua`,
`mdg_comm_strategy.lua:270-391`,
`mdg_routing_connection.lua:75-165,342-385`,
`mdg_routing_protocol.lua:10-157`, `mdg_routing_pb.lua`.

## 5. Java-Lua IPC: do not confuse it with the network protocol

`LuaVM` starts the native `luavm-java` library and receives two file
descriptors. Java uses them as input/output streams. Local multiplexing
framing differs from network framing:

```text
header = uint16_be(payload_length + 6) || int16_be(channel)
frame  = header || payload || header
```

The four-byte header is repeated identically at the end. Positive channels
carry data; negative channel numbers control the corresponding channels.
Control payloads begin with:

| Value | Meaning |
|---|---|
| 1 | OPEN, followed by UTF-8 protocol/channel description |
| 2 | ACK |
| 3 | CLOSE, followed by UTF-8 reason |

Java reserves even channel numbers for outgoing channels; the other side
opens odd channels. The main channel serves the local MDG library API.

Its payload also uses `uint8(tag) || protobuf`:

| Tag | Message | Proto2 fields |
|---|---|---|
| 1 | `Request` | `1 request_id:uint32 required`, `2 operation:string required`, `3 parameters:Property repeated` |
| 2 | `PosResponse` | `1 request_id:uint32 required`, `2 response:string required` |
| 3 | `NegResponse` | `1 request_id:uint32 required`, `2 error_text:string required` |
| 4 | `Notification` | `1 event:string required`, `2 parameters:Property repeated` |

`Property`: `1 key:string required`, `2 value:string required`. A successful
`response` is interpreted as a JSON string on the Java side. This is distinct
from domain JSON on an opened `cc_json` data channel.

### Local operations used by Java

| Operation | Parameters / function |
|---|---|
| `connect` | Properties prefixed with `p_`; enable control connection |
| `disconnect` | Disable control connection |
| `whoami` | Read own `device_id` |
| `pairings` | List saved pairings |
| `status` | Read connection/pairing status |
| `pair-local` | `ip`, `otp` |
| `pair-remote` | `otp` |
| `place-call` | `device_id`, `protocol`, optional `ticket`, `comm_channel` |
| `place-call-local` | `ip`, `device_id`, `protocol`, optional `ticket`, `comm_channel` |
| `revoke-pairing` | `device_id` |

A successful pairing response contains `result: "ok"` and `pairing` with
`device_id`, `description`, and `pairing_time`. Java reads `pairing_time` as
a Long and passes it directly to `java.util.Date`, so it is in milliseconds.

`status` is used to read, among other fields, `connected_to_mdg`,
`connect_switch`, `pairing_mode`, `remote_logging_enabled`, and
`connected_devices[].device_id`. These are not `/api/system/status` fields.

The local synchronous Java library request waits at most 10 seconds. This is
separate from domain request timeouts and network ping intervals.

Other operations exist in the Lua library, such as `enable-pairing-mode`,
`disable-pairing-mode`, `open-for-calls`, and `revoke-all-pairings`. They are
not HTTP endpoints automatically exposed by the controller.

Evidence: `com/trifork/mdg/LuaVM.java:23-45`,
`R1/l.java:25-111`, `R1/d.java`, `R1/o.java:82-153`,
`R1/a.java:98-220,r()`, `R1/h.java:33-145`,
`mdg_library_pb.lua`, `mdg.lua:1420-1687`.

## 6. Implementation status and open verification

A dedicated, bounded test client completed **full remote pairing**, including
peer proof and contact exchange. The result and its identity were stored
outside the project with restricted file permissions; see
[API.md, section 12](API.md). Afterward, a `cc_json` channel was opened
without pairing again. `GET /api/rooms` returned status 200. Before the
request, the peer ID and current TLS public key were checked against the
saved PACE-authenticated pairing. See [API.md, section 13](API.md). A bounded
setpoint change was also validated and confirmed by a separate GET; see
[API.md, section 14](API.md).

The session included `pairing_probe.py`, `legacy_tls.py`,
`test_pairing_probe.py`, and `build-legacy-tls.py`; the TLS adaptation was
kept in `apk-analysis/tools/mdg-brainpool-tls.patch`. `query_rooms.py` and
`test_query_rooms.py` cover read access. Eight offline tests check framing,
Protobuf, point validation, and simulated PACE, including an incorrect code
and incorrect peer proof. Five additional tests check room responses, error
responses, rejection of a mismatched saved peer key, and the bounded setpoint
PATCH with its room/temperature checks. These tests are not an independent
cryptography audit.

The Home Assistant integration in `custom_components/danfoss_link` now uses
**tlslite-ng 0.8.2 instead of the legacy OpenSSL runtime**. Direct access
with it also returned the room list after checking the control CA signature
and saved controller key. No heating values were written during this
validation.

Two connection-local hooks allow BrainpoolP320r1 certificates and restrict
ephemeral ECDHE exchange to P-256. Private group number 29 is advertised only
for compatibility; it is not accepted as X25519 for key exchange.
System-wide TLS settings remain unchanged. The integration connects anew
for each operation, closes all sockets afterward, and serializes requests
with an overall 45-second deadline. For this polling use case, this replaces
a persistent control session.

Starting with version 0.2.0, the HA setup flow also performs remote PACE.
Client identity and the MDG control connection are prepared before code
entry. The native PEM public-key encoding and the KDF/AES/HMAC rules
described above are preserved. After an incorrect or expired code, pairing
is retried only when explicitly requested with a fresh code. The pairing is
saved only after peer proof and contact exchange. Storage or room-read errors
after that point have a separate completion step that does not repeat PACE.
Installation, limitations, recovery, and import are documented in
[README.md](README.md).

For a production client, the following remain open:

- Other domain endpoints and their error cases; live confirmation currently
  covers the room list, one room, and a current temperature setpoint PATCH.
- Current firmware and cloud differences.
- A new live pairing through the fully integrated HA flow. PACE and its
  failure paths were tested with simulated peers, and the newly generated
  client tested the real control connection; no fresh controller code was
  used for this extension.
- Local-LAN pairing and device-specific pairing differences.
- Real error/success responses and size/time limits.
- Long-term operation and independent review of the TLS compatibility hooks;
  the obsolete test library is not needed by the integration.

Keys, private certificate keys, one-time codes, router tokens, and FCM
tokens must not be included in source code, documentation examples, or
public logs. No existing user identity was extracted from the app. The test
created a dedicated identity and used only controller codes freshly provided
by the user.
