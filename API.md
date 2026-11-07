# Danfoss Link: Reconstructed App API

Status: 2026-11-05. Analysis of the locally supplied `Danfoss.apk`, followed
by successful remote pairing, room retrieval, and an authorized setpoint
change. This is an interface description reconstructed from the client, not
an official Danfoss specification. The transport, pairing, `GET /api/rooms`,
`GET /api/rooms/{id}`, and a `PATCH /api/rooms/{id}` changing
`setpoint.temperature` have been confirmed live. The remaining endpoints are
supported by client-side evidence only.

## 1. Findings and scope

**The app does not use a conventional public REST API with a username,
password, and bearer token.** It pairs a cryptographic app identity with a
Danfoss Link Central Controller (CC). Over a local or relayed MDG channel, it
transports JSON messages using the `cc_json` protocol. Those messages contain
REST-like methods and paths such as `GET /api/rooms`.

The three layers should be considered separately:

```text
Android UI
  -> JsonWebRequest: method, URI, headers, JSON content
  -> MDG / cc_json: pairing, TLS, message framing
  -> Central Controller
  -> internal HTTP API
```

The bundled controller code forwards `cc_json` to `http://127.0.0.1:8000`.
This does **not** prove that this HTTP port is externally reachable or
configured the same way on a particular controller firmware. In particular,
`curl http://<controller>:14641/api/rooms` is not an appropriate client.

Network and pairing details are documented in [MDG-PROTOCOL.md](MDG-PROTOCOL.md).
This document covers the app's domain operations. After static analysis,
local connection attempts and remote pairing with a fresh code shown by the
controller were performed at the user's request; see sections 12 and 13.
The room list was then read using the saved pairing (section 13). Pairing and
the list request did not change heating parameters. A setpoint change was
performed only after it was explicitly requested (section 14).

### Identifying the analyzed file

| Property | Value |
|---|---|
| Package | `com.danfoss.linkapp` |
| Version / versionCode | `1.3.10` / `11565` |
| File size | 6,523,828 bytes |
| SHA-256 | `324c22e5b3eaa7bb72f208cfcac86fe8416942a38a41639adf7d746ad347232b` |
| minSdk / targetSdk | 24 / 36 |
| Build time from client property | `2026-01-29T12:31Z` |
| App commit from client property | `022352f5151e00e3b2ed95fa71e4b8e1aca6fd4e` |
| Implementation | Java/Kotlin, Lua 5.1 with a custom format, native ARM library |
| Native ABIs | `arm64-v8a`, `armeabi-v7a` |

### Evidence levels

- **Client evidence:** the path, method, serializer, parser, or control flow is
  present in this APK.
- **Library evidence:** a bundled module implements the feature; its presence
  does not prove that the Android app actively uses it.
- **Unknown:** behavior of the real controller, firmware differences,
  reachability, and server-side rules have not been investigated live.

All JSON examples below are constructed examples, not captured responses.
Parser defaults are not guaranteed server values.

## 2. Message format

After an authorized `cc_json` channel is established, each JSON document is
sent as a UTF-8 message. Network framing is described in the protocol
document. These are not HTTP requests sent directly over the socket.

### Request

```json
{
  "id": 1,
  "data": {
    "type": "JsonWebRequest",
    "data": {
      "method": "GET",
      "uri": "/api/rooms",
      "headers": ["Accept: application/json; charset=utf-8"]
    }
  }
}
```

`id` is a sequential request ID used to associate the response. Write requests
also include a JSON object under `data.data.content`. The app sends this as an
object, not as a JSON-encoded string. `GET` has no `content` field. This
request builder does not add an Authorization header: authorization is
established by the MDG connection.

### Response

```json
{
  "id": 1,
  "cc_time": 12,
  "data": {
    "type": "JsonWebResponse",
    "data": {
      "headers": [],
      "status": 200,
      "statusDescription": "OK",
      "content": []
    }
  }
}
```

The client reads `id`, optional `cc_time`, and `data.data.status` and
`data.data.content`. In the bundled proxy, `cc_time` is the duration of the
internal HTTP call in milliseconds. The shown headers and `statusDescription`
come from the Lua proxy; the Android parser does not use them.

`200 <= status < 300` is considered successful. The app alone does not
establish a general error object or guarantee a particular success status
such as 200, 201, or 204 for every operation.

Evidence: `S/i.java:49-68`, `S/g.java:382-424`,
`cc_json.lua:107-219,223-270`.

## 3. Endpoint catalog

All paths are used inside the envelope above. The API version is a capability
returned by the CC, not a `/v1` prefix or HTTP header. **Gate** is the minimum
value checked by the corresponding app request; it is not an independent
claim about when the feature was introduced in firmware. Some PATCH
counterparts notably have no higher gate of their own.

| Method | Path | Request content | Success content according to client | Gate |
|---|---|---|---|---|
| GET | `/api/world` | none | Aggregate object; see section 4 | 1 |
| GET | `/api/system/apiversions` | none | Object with `versions: integer[]` | 1 |
| GET | `/api/system/info` | none | SystemInfo | 1 |
| PATCH | `/api/system/info` | `{"name":"..."}` | SystemInfo | 1 |
| GET | `/api/system/status` | none | SystemStatus | 1 |
| POST | `/api/system/updatesoftware` | `{}` | Object, optional `version` | 1 |
| GET | `/api/rooms` | none | Room[] | 1 |
| GET | `/api/rooms/{id}` | none | Room | 1 |
| PATCH | `/api/rooms/{id}` | `id` and changed fields | Room | 1 |
| PATCH | `/api/zones/living` | `name` and changed fields | Not further processed | 1 |
| GET | `/api/modes` | none | Mode[] | 1 |
| PUT | `/api/modes/athome` | Mode with `type: "AtHome"` | Mode | 1 |
| PUT | `/api/modes/vacation` | Mode with `type: "Vacation"` | Mode | 1 |
| PUT | `/api/modes/pause` | Mode with `type: "Pause"` | Mode | 1 |
| PUT | `/api/modes/boost` | Mode with `type: "Boost"` | Mode | 1 |
| GET | `/api/settings/temperature` | none | TemperatureSettings | 1 |
| PATCH | `/api/settings/temperature` | `vacationTemperature.setpoint` | Not further processed | 1 |
| GET | `/api/onoffdevices` | none | OnOffDevice[] | 2 |
| GET | `/api/onoffdevices/{id}` | none | OnOffDevice | 2 |
| PATCH | `/api/onoffdevices/{id}` | `id` and changed fields | OnOffDevice | 1 |
| GET | `/api/alarms` | none | Alarm[] | 3 |
| PATCH | `/api/alarms/{id}` | `{"id":1,"isRead":true}` | Alarm | 1 |
| PUT | `/api/notification/register` | `pairing`, `platform`, `token`, `level` | Not further processed | 3 |
| DELETE | `/api/remote/pairings/{pairing}` | Empty JSON object in Java request | Not further processed | 3 |

Evidence: the 20 `*Request` classes in
`com/danfoss/cumulus/comm/req`; `PatchRoomRequest` has two target paths and
`PutModesRequest` has four. Base gate: `S/e.java:g()`. The Lua HTTP proxy
creates an HTTP body only for POST, PUT, and PATCH, so `content: {}` in the
DELETE envelope does not create an HTTP body there.

**Important limitations:** No GET for a zone, room creation or deletion, or
PATCH setter for the pause temperature is evidenced by these request classes.
Do not infer such operations from naming conventions.

## 4. Initialization, aggregate request, and refresh

`GET /api/world` is the preferred aggregate request. The response object
contains the following keys consumed by the client:

| Key | Content |
|---|---|
| `allRooms` | Room[] |
| `modes` | Mode[] |
| `systemInfo` | SystemInfo |
| `systemStatus` | SystemStatus |
| `temperatureSettings` | TemperatureSettings |
| `supportedApiVersions` | `{"versions":[1,2,3]}`; values are examples only |
| `onOffDevices` | OnOffDevice[] |
| `allUnresolvedAlarms` | Alarm[] |

Observe the capitalization: the path is `onoffdevices`, while the aggregate
object key is `onOffDevices`.

Only a status **400 specifically for GetWorldRequest** makes the app fall back
to individual requests. These retrieve API versions, system info, system
status, modes, and the other requested data. Other errors do not automatically
mean that `/api/world` is generally unavailable.

The app has a synchronization thread with a five-second wait. Depending on
connection state and queue progress, it starts registered refreshes; write
actions can wake it earlier. This is not a guaranteed fixed request interval
or a server-side rate limit. A separate client should serialize writes, read
back after writes, and use a bounded, configurable polling interval.

Evidence: `GetWorldResponse.java:13-78`, `S/g.java:406-414`,
`X/d.java:d0(),e0()`, `S/c.java:25-45`.

## 5. Rooms and temperatures

### Room

| Field | Type / observed meaning |
|---|---|
| `id` | Integer; required by the parser |
| `name` | String |
| `ambientTemperature` | Number; may be missing or null |
| `minSetpoint`, `maxSetpoint` | Numbers; parser defaults are 6.0 and 35.0 |
| `setpoint.temperature` | Number; current target temperature |
| `setpoint.type` | `Adjustable`, `Fixed`, `Off`, `Invalid` |
| `regulationState` | `Cooling`, `Deadband`, `ForecastHeating`, `Heating`, `Invalid` |
| `state` | System state; values in section 7; parser default is `Normal` |
| `sortOrder` | Integer; parser default is the room ID |
| `zone` | String; client uses `Living` or `None` |
| `regulation.type` | String; UI writes `Manual` or `Schedule` |
| `regulation.atHomeSetpoint` | Number |
| `regulation.awaySetpoint` | Number |
| `regulation.manualSetpoint` | Number |
| `schedule` | Object with weekdays and time intervals |
| `floorSetpoint.state` | String; client treats exactly `Enabled` as enabled |
| `floorSetpoint.temperature` | Number; read-only in the discovered requests |
| `mode` | String; additionally observed in the live room response as `Manual` |
| `hasTemperatureSensor` | Boolean; additionally observed in the live room response |

Temperature values are serialized as numbers without scaling by 10 or 100.
The app treats them as Celsius. Use the device limits from
`minSetpoint`/`maxSetpoint` rather than hard-coding the parser defaults. The
server-side step size has not been established.

Some temperature parsers use **777.0 as an error value**; others return NaN
for missing fields. These are not real temperatures. A client should show
missing or non-finite values as unavailable.

Evidence: `GetRoomsResponse.java:57-102`, `X/j.java`, `X/l.java`, `X/n.java`,
`IndividualRoomActivity.java:83`.

### Changing the setpoint

Example request content for `PATCH /api/rooms/1`:

```json
{
  "id": 1,
  "setpoint": {
    "temperature": 21.5
  }
}
```

This is different from the controller's stored regulation setpoints:

```json
{
  "id": 1,
  "regulation": {
    "manualSetpoint": 21.5
  }
}
```

For the other actions, the app uses `atHomeSetpoint` or `awaySetpoint`
instead of `manualSetpoint`. The exact duration of an override created by
`setpoint.temperature` is not guaranteed by the client alone.

### Changing the regulation mode

```json
{
  "id": 1,
  "regulation": {
    "type": "Manual"
  }
}
```

Use `Schedule` for schedule operation. A room PATCH can also include
`sortOrder` and `zone`.

The Java setters for individual `regulation` properties each create a new
nested object. Multiple setters on the same request would overwrite each
other; the discovered callers send separate actions. A combined PATCH is
therefore not confirmed by these callers.

### Living zone

For a room where `zone == "Living"`, the app writes the regulation mode and
schedule to the shared zone:

```text
PATCH /api/zones/living
```

```json
{
  "name": "Living",
  "regulationType": "Schedule"
}
```

Here the field is **`regulationType`**, not `regulation.type`. The path is
hard-coded to `living`; this does not establish a general API for arbitrary
zone names. The shown temperature actions still target the individual room.

Evidence: `PatchRoomRequest.java:21-118`, `S/k.java:n(),o(),p(),q(),s(),u()`.

## 6. Weekly schedules

Weekday keys, in order:
`monday`, `tuesday`, `wednesday`, `thursday`, `friday`, `saturday`, `sunday`.

A day is an array containing:

| Field | Format |
|---|---|
| `startTimeFromMidnight` | Duration as `HH:mm:ss` or `d.HH:mm:ss` |
| `endTimeFromMidnight` | Same format |
| `state` | State name, for example `AtHome` or `Away` |

Example of a complete Monday:

```json
{
  "id": 1,
  "schedule": {
    "monday": [
      {
        "startTimeFromMidnight": "00:00:00",
        "endTimeFromMidnight": "06:00:00",
        "state": "Away"
      },
      {
        "startTimeFromMidnight": "06:00:00",
        "endTimeFromMidnight": "22:00:00",
        "state": "AtHome"
      },
      {
        "startTimeFromMidnight": "22:00:00",
        "endTimeFromMidnight": "1.00:00:00",
        "state": "Away"
      }
    ]
  }
}
```

**End of day is `1.00:00:00`, not `24:00:00`.** The client sorts
intervals and fills gaps with `Away` in room schedules and `Off` for
switchable devices. Its parser rounds starts down and ends up to the previous
or next quarter-hour. This is client behavior, not proof that the server
accepts only quarter-hour increments.

The app can PATCH a single day. For the Living zone, replace room addressing
with `/api/zones/living` and the body identifier `id` with `name: "Living"`.
For a switchable device, use `/api/onoffdevices/{id}` and states `On`/`Off`.

Evidence: `S/e.java:25,48-93,117-140`, `S/f.java:31-70`,
`PatchRoomRequest.java:y()`, `PatchOnOffDeviceRequest.java:t()`.

## 7. Modes and times

### Mode

| Field | Type / values |
|---|---|
| `type` | For PUT: `AtHome`, `Vacation`, `Pause`, `Boost` |
| `state` | `Active`, `Inactive`, `Planned` in the enum |
| `startTime`, `endTime` | Optional times; see response parser below |
| `rooms` | Optional integer array of room IDs |

The writer sends `rooms` only with `AtHome` and `Active`. The discovered
comfort actions activate/deactivate using `Active` and `Inactive`; a
scheduled vacation is also written with `Active` and start/end times.
`Planned` is a readable enum value, but that does not mean it should be sent
for a scheduled vacation.

Example for `PUT /api/modes/athome`:

```json
{"type":"AtHome","state":"Active","rooms":[1,2]}
```

Example for ending a pause:

```json
{"type":"Pause","state":"Inactive"}
```

For a time-limited pause, the app sets `endTime`, calculated from controller
time plus the selected duration. A start date is not required. The meaning
and availability of `Boost` are evidenced only by the generic writer, not by
a UI caller shown here.

### Controller time mode

Before time-related operations, inspect `systemInfo.systemTime`:

- If the time ends in `Z`, UTC mode is expected. Mode responses are then read
  from `startTimeUtc` and `endTimeUtc`.
- With an offset such as `+01:00`, the app uses that fixed offset and reads
  `startTime` and `endTime`.
- The writer calls the fields `startTime` and `endTime` in both cases. In UTC
  mode it sends `yyyy-MM-dd'T'HH:mm:ssZ` with a **literal `Z`**. In local
  mode it sends `yyyy-MM-dd'T'HH:mm:ss` **without an offset suffix**.

Do not blindly use the integration host's time zone. A fixed offset also does
not automatically describe future daylight-saving changes. Null dates are
omitted by the writer.

The Java implementation initializes its formatter with the host time zone,
while the mode flags already default to UTC/`Z`. Its switch function returns
early when flags have not changed. A new client should initialize the time
zone explicitly rather than reproducing this state-dependent formatter code.

The shared system-state enum is:
`AtHome`, `Away`, `Asleep`, `Vacation`, `Pause`, `Boost`, `Normal`, `Manual`,
`Off`, `On`, `Invalid`. **Not all of these are writable modes.**

Evidence: `PutModesRequest.java:51-97`, `GetModesResponse.java:38-59`,
`S/e.java:95-115,143-161,188-197`, `S/f.java:97-111`, `S/k.java:m(),z(),A()`.

## 8. Other data models

### SystemInfo

| Field | Type / parser meaning |
|---|---|
| `name` | Required string |
| `brandingType` | String |
| `version` | String; controller software |
| `serialNo` | String |
| `systemTime` | Time string; also controls time mode |
| `uptime` | Duration string `HH:mm:ss` or `d.HH:mm:ss` |
| `limitPauseDuration` | Boolean; parser default `true` |
| `autoUpdateSoftware` | Boolean |
| `cpuLoadPercentage` | Number |
| `memoryLoadPercentage` | Integer |
| `pingCallTime` | Number; unit not established here |
| `wifiSignalStrengthDb` | Integer |

The only evidenced PATCH content is `name`. A readable field is not
necessarily writable, especially `autoUpdateSoftware`.

### SystemStatus

`currentState` is a string and `outdoorTemperature` is an optional number.
`schedule` and `normalSchedule` are arrays using the interval format in
section 6. The app parser accepts comma-separated `currentState` values and
uses the first component for display. The meaning of any additional
components has not been reconstructed.

### TemperatureSettings

```json
{
  "pauseTemperature": {
    "minSetpoint": 6.0,
    "maxSetpoint": 35.0,
    "setpoint": 6.0
  },
  "vacationTemperature": {
    "minSetpoint": 6.0,
    "maxSetpoint": 35.0,
    "setpoint": 15.0
  }
}
```

The numbers are examples only. The evidenced write content is:

```json
{"vacationTemperature":{"setpoint":15.0}}
```

The available writer has no setter for `pauseTemperature`.

### OnOffDevice

`id` is an integer ID. Other fields are `name`,
`activitySimulationEnabled` (Boolean), `state` (`On`/`Off`),
`regulation` (`Schedule`/`Manual`), and `schedule`.

Example for `PATCH /api/onoffdevices/2`:

```json
{
  "id": 2,
  "regulation": "Manual",
  "state": "On",
  "activitySimulationEnabled": false
}
```

Unlike a room, `regulation` here is a string, not a nested object.

### Alarm

Required fields: `id` (integer), `isRead` (Boolean). Other fields read by the
app: `createdDate`, `level`, `room`, `node`, `descriptionTextId`,
`titleTextId`. `room` and `node` are read as strings, not numeric foreign
keys. Alarm levels in the client are `Error`, `Warning`, `Notice`, and
`Debug`.

`createdDate` is parsed as `yyyy-MM-dd'T'HH:mm:ss`. The app may replace an
invalid time value with the current time; this is not a server contract and
should not be treated as the actual alarm time. Text IDs are localization
keys, not necessarily complete description text.

Evidence: the respective `Get*Response` classes, `PatchSettingsTemperatureRequest`,
`PatchOnOffDeviceRequest`, `X/b.java:53-58`, `X/g.java:26-34`.

## 9. Notifications, pairings, and updates

### FCM registration

`PUT /api/notification/register`:

```json
{
  "pairing": "<app-device-id>",
  "platform": "fcm",
  "token": "<fcm-registration-token>",
  "level": "all"
}
```

`pairing` is the app's **own device ID** from MDG `whoami`, not the one-time
pairing code and not necessarily the CC ID. `RegistrationIntentService`
defaults `level` to `all`. A full list of server-accepted filter values
cannot be inferred from this default.

The FCM token is a push-delivery token, not an authentication token for the
heating API. Registration responses are not further parsed.

### Removal

The `DeleteNotificationRequest` class actually targets
`DELETE /api/remote/pairings/{pairing}`. Given this path, the operation must
not be treated as a harmless push-only unsubscribe. The controller's
side-effects need to be understood before using it. Separately, the local MDG
library has `revoke-pairing`.

### Software update

The client includes `POST /api/system/updatesoftware` with `{}`. The response
is checked only for an optional `version` field. Restart behavior, progress,
duration, and failure cases are not established. Do not use this as a
connectivity or API test.

Evidence: `PutNotificationRegisterRequest.java:15-46`,
`RegistrationIntentService.java:35-49`, `S/n.java:B()`,
`DeleteNotificationRequest.java:18-40`,
`PostUpgradeSoftwareRequest.java`, `PostUpgradeSoftwareResponse.java`.

## 10. Error handling and integration notes

The app distinguishes transport errors, unsuccessful status codes, and
parser errors. It uses a queue of 30 requests and an adaptive timeout monitor.
The monitor's baseline threshold ranges from 3 to 30 seconds and is extended
for write requests in code. These implementation values are not a server SLA.

For a Home Assistant client, the following constraints apply:

1. Implement a dedicated, persistent app identity and normal pairing first;
   never log private keys or pairing data.
2. Develop LAN discovery and the authorized `cc_json` transport separately
   from the data models. An HTTP client alone is insufficient.
3. Read API capabilities and `systemTime`, then use `/api/world`, with a
   targeted fallback when its status is 400.
4. Do not conflate a room setpoint, stored manual setpoint, and regulation
   mode. A displayed state of `Off` does not prove a general room-off action.
5. Account for Living zones when changing schedules or regulation mode; one
   action may affect multiple rooms.
6. Read state back after writes. On timeout, do not blindly retry updates,
   pairing deletions, or other requests with side effects.

`POST /api/system/notify` appears only in a bundled Lua test function with a
2014 date. This is **not evidence of an actively used event subscription**.
The evidenced Android data path uses polling; FCM is separate.

## 11. Origin and reproducibility

Analysis was performed locally in WSL Ubuntu 22.04. Files and Python
environments belonging to other projects were not changed. Java 17, JADX
1.5.6, and unluac were used in an isolated analysis environment. The APK was
not uploaded to a decompiler service.

The APK contains:

- `classes.dex`: request/response classes and the MDG Java binding.
- `luafiles/mdg-c.zip`: 57 compiled application/MDG modules.
- `luafiles/modules-c.zip`: 21 compiled helper modules.
- `lib/arm64-v8a/libluavm-java.so`: includes the modified Lua loader.
- `luafiles/android_main.lua`: readable Android startup configuration.

All **78 Lua chunks** could be read structurally, converted to standard Lua
5.1 bytecode, and decompiled with unluac. The custom `0xCC` format uses
big-endian 7-bit varint encoding for structural integers and string lengths,
instead of fixed 32-bit integers. Replacing only the format byte is not
sufficient.

JADX reported eight decompilation errors. The affected files are outside the
Danfoss request/response and MDG transport classes used as primary evidence
here. Successfully decompiled code may also contain artifacts. Native crypto
wrappers and TLS-specific rules needed for the pairing test were additionally
disassembled. Successful remote pairing confirms this specific flow, not
every cryptographic feature in the APK.

Analysis artifacts were kept locally and are not included in this repository.
Java references in this document are relative to the generated `jadx\sources`
tree; Lua references are relative to the generated `lua` tree. Line numbers
refer to generated files from that analysis; class names, method names, and
the APK hash are more stable references for a repeat analysis. This document
describes protocol facts and original examples, not decompiled source code.

**Still unknown:** specific CC firmware behavior, complete server-side
validation, temperature step sizes, override durations, and complete error
responses. The documented endpoints have client-side evidence; the room list,
a single room, and its current temperature setpoint PATCH have additionally
been confirmed against a real controller.

## 12. Remote pairing validation

A dedicated test client completed pairing through the Danfoss MDG service
using a fresh, short-lived code displayed by the controller.

| Step | Observed result |
|---|---|
| Reachability | All four embedded IPv4 control addresses accepted TCP connections on port 443 |
| Control connection | TLS 1.2 to `77.66.11.90`; server certificate checked against the APK CA |
| Control protocol | MDG handshake and correlated ping response succeeded |
| Routing | `place_pairing_call`, router handshake, and peer TLS succeeded |
| Peer encryption | `ECDHE-ECDSA-AES256-GCM-SHA384` |
| PACE | ServerHello, XY, PK, and cryptographically verified peer proof succeeded |
| Completion | Bidirectional contact exchange; authenticated controller certificate saved |

The test identity and authenticated pairing record were stored outside the
project with restricted file permissions. Connection codes and router tokens
were not written to these files. The successful attempt used the 256-bit peer
encryption required by the app code.

**Compatibility note:** The APK uses a modified OpenSSL 1.0.2 runtime with a
private TLS curve mapping for BrainpoolP320r1. An unmodified modern TLS
module is insufficient. The test used only locally stored compatibility
libraries; system OpenSSL and unrelated Python environments were not replaced.
Details are in [MDG-PROTOCOL.md](MDG-PROTOCOL.md).

No **heating API requests** were sent during pairing. Successful pairing
alone does not confirm a tested Home Assistant adapter or production-grade
continuous operation.

## 13. Read-only room-list validation

`GET /api/rooms` returned **status 200** in a live read-only test. No new
connection code was needed. The client used its saved identity, registered
the saved peer with the MDG whitelist, and opened a new `cc_json` channel
with `place_call`. Before the JSON request, the peer ID and TLS public key
were checked against the PACE-authenticated saved certificate.

As in the app, the MDG peer ID must use **lowercase, colon-separated
hexadecimal bytes**. An initial call using an uppercase ID returned
`PEER_NOT_AVAILABLE`; retrieval succeeded with the native format.

The response contains room names, temperatures, setpoints, limits, regulation
states, and other room settings. In addition to the parser fields documented
statically, `mode` and `hasTemperatureSensor` were returned. This list
represents **rooms or heating zones**, not necessarily individual physical
radiator thermostats. A separate hardware inventory or mapping of multiple
valves to one room has not been established. No room names or live measurements
are included here.

## 14. Setpoint write validation

A bounded setpoint write was validated against a live controller. Before
writing, the room and its current limits were read and checked, and the
setpoint was confirmed to be adjustable. The request used the room-specific
`setpoint.temperature` PATCH shape shown in section 5.

The controller returned **status 200** and a separate subsequent GET
confirmed the updated setpoint. No other settings were included in the PATCH.
Room identifiers and live temperature values are intentionally omitted. The
long-term duration of an override during schedule operation remains unknown.

## 15. Home Assistant integration

`custom_components/danfoss_link` contains a direct custom integration for
Home Assistant Core 2026.11.0 and later. Each room is created as a `climate`
entity with a stable controller/room ID, current temperature, current
setpoint, and controller-provided limits. Polling occurs every 60 seconds.
New rooms are added; missing rooms and connection failures are shown as
unavailable.

The integration can import an existing PACE-authenticated identity or pair
directly in the setup flow starting with version 0.2.0. It uses tlslite-ng
with narrowly scoped MDG certificate compatibility, not the test client's
special OpenSSL version. The integration client successfully read the room list, with the control
certificate checked against the MDG CA and the controller key pinned to the
saved pairing.

An end-to-end read in an isolated Home Assistant Core 2026.11.0 instance
created available climate entities with current and target temperatures. The
integration was then unloaded and the temporary Home
Assistant configuration removed. This was not an installation in the user's
production Home Assistant instance.

Temperature services read the room and limits first, send only
`{"id": <room-id>, "setpoint": {"temperature": <value>}}`, and verify by
reading back. An ambiguous write result is reported as an error and is not
retried automatically. Integration validation did not perform additional
real setpoint changes.

New pairing prepares a dedicated explicit Brainpool identity and the MDG
connection before the user activates the one-minute remote code. The pairing
file is saved only after PACE proof and contact exchange. Keys are stored
with restricted permissions below `.storage/danfoss_link`; the Home
Assistant config entry contains only the path. Codes are not stored or
resent automatically. After successful pairing, storage or room-read errors
can be retried at the completion step without pairing again.

PACE and the new setup steps were tested against synthetic peers. The new
identity also completed a real MDG control handshake; its PEM public-key
encoding matches OpenSSL. The existing pairing still reads the room list. A new live pairing using a
fresh controller code was not performed for this
extension.

Local-LAN pairing, schedules, global pause, turning the system off, and other
domain endpoints are not implemented. The HVAC mode `heat` describes the
heating function; it does not switch the controller to another regulation
mode. Installation, limitations, recovery, and import of the three identity
files are described in [README.md](README.md).
