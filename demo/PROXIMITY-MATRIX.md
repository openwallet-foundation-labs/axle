# Proximity interop matrix (ISO 18013-5)

The device runbook for phone-to-phone proximity. Proximity is the one part of the stack that unit tests cannot
prove: the failures live in what a *peer* puts on the wire (BLE role flags, which UUID pairs with which mode,
when NFC reader mode is dropped), and each of those has already cost us a shipped bug. Run this matrix before
tagging a release, and after any change under `kotlin/proximity`, `android/proximity`, or the demo's
`ProximityScreens.kt`.

Each row is one tap. Record the outcome in [Results](#results) with the date and build.

## Rig

| | |
| --- | --- |
| Devices | two Android phones, both with the demo installed (`com.hopae.axle.wallet`) |
| Partner wallet/reader | **Multipaz test app** (`org.multipaz.testapp`) — plays both roles, see [Where the switches are](#where-the-switches-are) |
| Partner holder | **Google Wallet** with a presentable ID pass, for the one case only it exercises |
| Credential | an mDL (`org.iso.18013.5.1.mDL`) in the demo wallet — the reader rows request Driving Licence |
| Logs | `adb -s <serial> logcat -d -b main -v time -t '<HH:MM:SS.000>' \| grep EudiDemo` |

Streamed `adb logcat` into a file dies when the shell that started it goes away; dump the device ring buffer
with `-d -t` after each tap instead.

### Where the switches are

**Our demo** — Settings tab → *Proximity sharing*: **Bluetooth role** (Peripheral / Central, used by the QR
rows) and **NFC handover** (Static / Negotiated). The holder screen is Home → **Proximity**; the reader screen
is Home → **Reader** (pick the document kind, then *Scan holder's QR* or *Tap over NFC*).

**Multipaz** — main list → **ISO mdoc Proximity Sharing** (it as holder, QR) or **ISO mdoc Proximity Reading**
(it as reader). Its gear icon holds *ISO mdoc NFC Engagement Settings* (Static vs Negotiated), *ISO mdoc
Transports* (which BLE modes its holder offers over QR + static handover) and *Negotiated Handover Preferred
Order*. Its holder over NFC needs no screen at all — `TestAppCombinedNfcService` is an always-on HCE service;
just keep the app foregrounded so it wins AID routing.

## The matrix

`mdoc peripheral server` = the wallet is the GATT server and the reader connects to it.
`mdoc central client` = the reader is the GATT server and the wallet connects to it.

**Which one you should expect.** In negotiated handover the reader states a preference two ways: by the order
it lists its carriers, and — for a carrier that supports both roles — by the LE Role preference bit (`0x02` the
reader would rather be the Peripheral ⇒ mdoc central client; `0x03` it would rather be the Central ⇒ mdoc
peripheral server). `NfcHandoverRequest.selectCarrier()` follows both, so an expected mode below is really a
prediction about what the *partner* offers and whether it honours what we asked for.

Everything here defaults to **mdoc central client mode** — the reader advertises, the wallet only scans.
§8.3.3.1.1.1 says a reader should select it when the mdoc supports both, Google Wallet always picks it, and it
keeps the wallet from broadcasting a UUID of its own. Our reader asks for it with one BLE carrier at LE Role
`0x02`; **holders differ in whether they honour that bit** (measured below), and one that ignores it answers
with peripheral server, which completes just as well.

### Our wallet as the mdoc (holder)

| ID | Reader | Engagement | Our BLE role setting | Expected mode |
| --- | --- | --- | --- | --- |
| H1 | Multipaz | NFC static | — | mdoc peripheral server |
| H2 | Multipaz | NFC negotiated | — | mdoc peripheral server¹ |
| H3 | Multipaz | QR | Peripheral | mdoc peripheral server |
| H4 | Multipaz | QR | Central | mdoc central client |
| H5 | our reader | NFC negotiated | — | **mdoc central client** — the holder drops its GATT server and dials |
| H6 | our reader (**probe build**²) | NFC negotiated | — | mdoc peripheral server |
| H7 | our reader | NFC static | — | mdoc peripheral server |
| H8 | our reader | QR | Peripheral | mdoc peripheral server |
| H9 | our reader | QR | Central | mdoc central client |

¹ Multipaz's Handover Request offers **one** BLE carrier with LE Role `0x03` — "both roles supported,
**Central** preferred", i.e. the reader would rather be the Central, which is mdoc peripheral server mode. The
holder honours that and keeps its pre-warmed GATT server.

² H5 and H6 are the same exchange with our reader's two carriers in either order, which is the whole point:
the mdoc takes the first carrier it supports, so the reader's ordering decides the mode. H5 is the default
(mdoc central client first, `NFC negotiated: taking mdoc central client mode — connecting to <uuid>` in the
holder log); H6 needs a probe build that swaps the two `bleOobRecord(...)` lines in
`MdocNfcEngagement.buildHandoverRequest`, installed **on the reader phone only**, then reverted.

### Our wallet as the mdoc reader

| ID | Holder | Engagement | Partner setting | Expected mode |
| --- | --- | --- | --- | --- |
| R1 | Multipaz | NFC static | Transports: BLE peripheral server | mdoc peripheral server |
| R2 | Multipaz | NFC static | Transports: BLE central client | mdoc central client |
| R3 | Multipaz | NFC negotiated | *(any)* | mdoc peripheral server⁴ |
| R4 | Multipaz | NFC negotiated | our reader sends **two** carriers, central client first (**probe build**⁵) | mdoc central client |
| R5 | Multipaz | QR | Transports: BLE peripheral server | mdoc peripheral server |
| R6 | Multipaz | QR | Transports: BLE central client | mdoc central client |
| R7 | **Google Wallet** | NFC negotiated | — | mdoc central client³ |

³ Google Wallet always selects mdoc central client mode, so the reader must advertise and hold NFC reader mode
for the *whole* exchange — dropping it at the tap hands the still-coupled phone to the platform tag dispatcher
and kills the session (fixed in #68).

⁴ Nothing in Multipaz's settings steers this. Its *Negotiated Handover Preferred Order* applies to its
**reader** side, and its **holder** ignores the LE Role preference bit outright: given our one carrier that
supports both roles it answers with mdoc peripheral server whether we send `0x02` or `0x03` (both measured).
Google Wallet, on the same Request, honours the bit and takes mdoc central client. Either completes.

⁵ The alternative encoding, kept behind `alsoOfferMdocPeripheralServer`: one carrier record per BLE mode,
central client first. That is what our reader sent until 2026-08-22, and it steers *every* holder — carrier
order is the preference channel even implementations that ignore the LE Role bit follow. It costs a duplicated
UUID (a Request's UUID is defined for mdoc central client mode alone), which is why the single carrier is the
default now. Flip `singleCarrierBothRoles` off in `NfcReader.negotiatedHandoverRequest` to run this row.

## What to check, beyond "it worked"

The demo logs both negotiated messages verbatim, which is the only way to see what a peer actually offered:

```
NFC Hr(176B) …1c03 1107 <uuid-le>…   ← LE Role 0x03: reader supports both roles
NFC Hs(204B) …1c00 1107 <uuid-le>…   ← LE Role 0x00: we chose mdoc peripheral server, naming our UUID
```

Decode a dump with `python3 tools/ndef-dump.py Hr=<hex>` (or by hand: `02 1C rr` is the LE Role, `11 07` the
128-bit UUID, little-endian). Things worth confirming per row:

- the mode the reader reports matches the **Expected mode** column — a wrong pairing of UUID and mode is the
  failure that looks like a hang, not an error;
- the reader-side line `NFC handover <static|negotiated>: mdoc <mode> mode, uuid=…`;
- `BLE Ident verified` on any row where our side is the GATT client (§8.3.3.1.1.4);
- the response actually decrypts — a matching `SessionTranscript` is what proves both sides bound the same
  `[Hs, Hr]`.

## Results

### 2026-08-22 — LE Role "both" + holder carrier selection

Devices `R3KL1044XHZ` (SM-S931N, holder + reader) and `R3CW70VFWMR` (SM-F731N, Multipaz + our reader),
Multipaz `0.101.0-pre.38.3fd9b168`, demo built from the LE-Role work (`NfcBleCarrier`, holder-side carrier
selection, `BleGattClientTransport.nfcCarrier`).

| Row | Result | Observed |
| --- | --- | --- |
| H1 | ✅ | static → mdoc peripheral server, 5545 B response |
| H2 | ✅ | `Hr …1c03` (LE Role 0x03) → we keep peripheral server, `Hs …1c00` |
| H3 | ✅ | QR → `ble:peripheral_server_mode`, 5520 B |
| H4 | ✅ | QR → BLE client, `BLE Ident verified` |
| H5 | ✅ | `taking mdoc central client mode — connecting to …`, `Hs …1c01` on the reader's UUID, `BLE Ident verified` |
| H6 | ✅ | probe with the carriers reversed → peripheral server |
| H7 | ✅ | static, our reader as BLE client |
| H8 | ✅ | QR peripheral, our reader as BLE client |
| H9 | ✅ | QR central, our reader as BLE server + Ident served |
| R1 | ✅ | `NFC handover static: mdoc peripheral server mode` |
| R2 | ✅ | `NFC handover static: mdoc central client mode` |
| R3 | ✅ | single carrier `0x02` → `negotiated: mdoc peripheral server mode`; the Multipaz holder ignores the bit. `0x03` measured too — same answer |
| R4 | ✅ | two-carrier probe, central client first → `negotiated: mdoc central client mode`, flipping R3's outcome |
| R5 | ✅ | QR → BLE client |
| R6 | ✅ | QR → BLE server + Ident served |
| R7 | ✅ | single carrier `0x02` → `negotiated: mdoc central client mode`, on our UUID, Ident served — Google Wallet reads the preference bit |

What this pass changed, and why. **The reader decides the BLE mode** — R4 reversed our carrier order and
flipped a Multipaz holder's answer, nothing else touched, which turned a reading of the spec into a measured
fact. Our holder was ignoring that signal entirely; it now runs `selectCarrier()`, honouring carrier order and
the LE Role preference bit, so our own reader's stated preference (mdoc central client) is followed too.

The reader then moved to the shape §8.2.2.1 describes: **one** BLE carrier at LE Role `0x02` instead of one
record per mode, dropping a duplicated UUID and 78 bytes. Holders split on it — Google Wallet and our own read
the preference bit and take mdoc central client; the Multipaz holder ignores it and answers peripheral server,
which completes just as well. `0x03` was measured against Multipaz too, in case its holder read the bit
relative to itself: same answer, so it simply does not read it. The two-carrier form stays available
(`alsoOfferMdocPeripheralServer`) for a peer that needs one record per mode.

Defaults now line up behind one preference — the reader on the air, the wallet on scan duty: NFC handover
**negotiated**, QR Bluetooth role **Central**. Both roles buzz on the tap.
