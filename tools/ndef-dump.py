#!/usr/bin/env python3
"""Decode an ISO 18013-5 NFC handover message (NDEF) from a hex dump.

The demo logs the negotiated Handover Request and Select verbatim while presenting
(`NFC Hr(176B) 9102…` / `NFC Hs(204B) 9102…`, see demo/PROXIMITY-MATRIX.md). Paste either here to
see which BLE carriers a peer actually offered — the LE Role and the service UUID of each carrier
are what decide the exchange, and they are invisible in any other log.

    python3 tools/ndef-dump.py 9102154872159102…
    python3 tools/ndef-dump.py Hr=9102… Hs=9102…
"""

import sys

TNF = {0: "EMPTY", 1: "WELL_KNOWN", 2: "MIME", 3: "URI", 4: "EXTERNAL", 5: "UNKNOWN", 6: "UNCHANGED"}

# Bluetooth CSS "LE Role" (0x1C) values. ISO 18013-5 §8.3.3.1.1.1 treats "both" as a first-class
# answer, so 0x02/0x03 are what a peer supporting either mode sends — not a malformed 0x00/0x01.
LE_ROLE = {
    0x00: "Peripheral only",
    0x01: "Central only",
    0x02: "both supported, Peripheral preferred",
    0x03: "both supported, Central preferred",
}


def decode(b):
    """NDEF message → records. Stops at the Message End flag."""
    records, i = [], 0
    while i < len(b):
        header = b[i]
        i += 1
        short, has_id = header & 0x10, header & 0x08
        type_len = b[i]
        i += 1
        if short:
            payload_len = b[i]
            i += 1
        else:
            payload_len = int.from_bytes(b[i:i + 4], "big")
            i += 4
        id_len = b[i] if has_id else 0
        if has_id:
            i += 1
        rtype, i = b[i:i + type_len], i + type_len
        rid, i = b[i:i + id_len], i + id_len
        payload, i = b[i:i + payload_len], i + payload_len
        records.append({"tnf": header & 0x07, "type": rtype, "id": rid, "payload": payload})
        if header & 0x40:  # ME
            break
    return records


def oob(payload):
    """BLE carrier-configuration record → its AD structures (little-endian, per the BT CSS)."""
    out, i = [], 0
    while i < len(payload):
        length = payload[i]
        if length == 0 or i + 1 + length > len(payload):
            break
        ad_type, data = payload[i + 1], payload[i + 2:i + 1 + length]
        if ad_type == 0x1C:
            out.append(("LE Role", f"0x{data[0]:02x} — {LE_ROLE.get(data[0], 'reserved')}"))
        elif ad_type == 0x07:
            u = bytes(reversed(data)).hex()
            out.append(("UUID128", f"{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:]}"))
        elif ad_type == 0x1B:
            out.append(("LE Device Address", data.hex()))
        elif ad_type in (0x08, 0x09):
            out.append(("Local Name", data.decode("utf8", "replace")))
        else:
            out.append((f"AD 0x{ad_type:02x}", data.hex()))
        i += 1 + length
    return out


def alternative_carrier(payload):
    cps = {0: "inactive", 1: "active", 2: "activating", 3: "unknown"}.get(payload[0] & 0x03)
    n = payload[1]
    ref, i = payload[2:2 + n].decode("latin1"), 2 + n
    aux_count, i = payload[i], i + 1
    aux = []
    for _ in range(aux_count):
        length = payload[i]
        aux.append(payload[i + 1:i + 1 + length].decode("latin1"))
        i += 1 + length
    return cps, ref, aux


def show(message, label):
    print(f"\n===== {label} ({len(message)} bytes) =====")
    for r in decode(message):
        rtype = r["type"].decode("latin1")
        print(f"  [{TNF[r['tnf']]}] type={rtype!r} id={r['id'].decode('latin1')!r} payload={len(r['payload'])}B")
        if r["tnf"] == 1 and rtype in ("Hs", "Hr"):
            version = r["payload"][0]
            print(f"      Connection Handover {version >> 4}.{version & 0xF}")
            for inner in decode(r["payload"][1:]):
                itype = inner["type"].decode("latin1")
                if itype == "ac":
                    cps, ref, aux = alternative_carrier(inner["payload"])
                    print(f"      ac: cps={cps} carrier-data-ref={ref!r} aux={aux}")
                elif itype == "cr":
                    print(f"      cr: 0x{inner['payload'].hex()}")
                else:
                    print(f"      {itype!r}: {inner['payload'].hex()}")
        elif r["tnf"] == 2 and b"bluetooth.le.oob" in r["type"]:
            for key, value in oob(r["payload"]):
                print(f"      {key}: {value}")
        elif r["tnf"] == 4:
            print(f"      {r['payload'].hex()}")


def main(argv):
    if not argv:
        print(__doc__)
        return 1
    for arg in argv:
        label, _, hexed = arg.rpartition("=")
        show(bytes.fromhex(hexed), label or "message")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
