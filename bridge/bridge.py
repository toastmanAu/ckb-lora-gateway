#!/usr/bin/env python3
"""
CKB-LoRa MQTT Bridge  (Option B: raw frames + custom decode)

No LoRaWAN stack anywhere. The T-Deck transmits raw CKB-LoRa frames:

    [0xCB][0x01][name 8B][block 4B LE]   (14 bytes)

They arrive over the air at the SenseCAP M1 concentrator, get forwarded by the
Semtech packet forwarder to chirpstack-gateway-bridge, which republishes them on
MQTT as a protobuf event (topic: <region>/gateway/<eui>/event/up).

We do NOT need the full protobuf schema. The raw PHYPayload is a length-delimited
top-level field whose bytes start with the CKB-LoRa magic 0xCB, and rxInfo
(gateway EUI / RSSI / SNR) is a nested message we locate generically.

Outputs:
  * JSONL appended to ~/ckb-lora-bridge/decoded.log
  * republished to MQTT topic  ckblora/decoded

Run:  ~/ckb-lora-bridge/venv/bin/python ~/ckb-lora-bridge/bridge.py
"""
import json
import os
import struct
import time

import paho.mqtt.client as mqtt

BROKER = "localhost"
PORT = 1883
SUB_TOPIC = "au915_1/gateway/+/event/up"
PUB_TOPIC = "ckblora/decoded"
LOG = os.path.expanduser("~/ckb-lora-bridge/decoded.log")

MAGIC = 0xCB
TYPE_BEACON = 0x01     # [CB][01][name8][block4]
TYPE_REQUEST = 0x02    # [CB][02][req_id][op][body..]   (device -> gateway)
TYPE_RESPONSE = 0x03   # [CB][03][req_id][status][body..] (gateway -> device)


# ---------------------------------------------------------------- protobuf bits
def read_varint(b, i):
    v = 0
    s = 0
    while True:
        if i >= len(b):
            raise ValueError("truncated varint")
        c = b[i]
        i += 1
        v |= (c & 0x7F) << s
        if not (c & 0x80):
            break
        s += 7
    return v, i


def pb_fields(b):
    """Yield (field_no, wire_type, value). value is int for varint, bytes otherwise."""
    i = 0
    while i < len(b):
        try:
            k, i = read_varint(b, i)
        except ValueError:
            return
        f = k >> 3
        w = k & 7
        if w == 0:
            v, i = read_varint(b, i)
            yield f, w, v
        elif w == 2:
            l, i = read_varint(b, i)
            yield f, w, b[i:i + l]
            i += l
        elif w == 5:
            yield f, w, b[i:i + 4]
            i += 4
        elif w == 1:
            yield f, w, b[i:i + 8]
            i += 8
        else:
            return


def f32(x):
    try:
        return struct.unpack("<f", x)[0]
    except Exception:
        return None


def as_signed(v):
    """Proto int32 negatives are encoded as 10-byte varints (two's complement)."""
    if v >= 2 ** 31:
        v -= 2 ** 64
    return v


# ---------------------------------------------------------------- CKB-LoRa frame
def decode_frame(payload):
    """Accept ANY CKB-LoRa frame; beacon gets name/block, others carry raw hex."""
    if len(payload) < 2 or payload[0] != MAGIC:
        return None
    t = payload[1]
    rec = {"type": t, "raw": payload.hex()}
    if t == TYPE_BEACON and len(payload) >= 14:
        rec["name"] = payload[2:10].split(b"\x00")[0].decode("ascii", "replace")
        rec["block"] = int.from_bytes(payload[10:14], "little")
    elif t == TYPE_REQUEST and len(payload) >= 4:
        rec["req_id"] = payload[2]
        rec["op"] = payload[3]
        rec["body"] = payload[4:].hex()
    return rec


# ---------------------------------------------------------------- rx metadata
def find_rxinfo(b, depth=0):
    if depth > 4:
        return None
    for _f, w, v in pb_fields(b):
        if w != 2 or not isinstance(v, bytes):
            continue
        sub = list(pb_fields(v))
        if not sub:
            continue
        for f2, w2, v2 in sub:
            if f2 == 1 and w2 == 2 and isinstance(v2, bytes) and 8 <= len(v2) <= 16:
                try:
                    eui = v2.decode("ascii")
                except Exception:
                    continue
                if not eui.isalnum():
                    continue
                rssi = snr = None
                for f3, w3, v3 in sub:
                    if f3 == 6:
                        rssi = as_signed(v3)
                    elif f3 == 7 and isinstance(v3, bytes):
                        s = f32(v3)
                        snr = round(s, 2) if s is not None else None
                return {"gatewayId": eui, "rssi": rssi, "snr": snr}
        r = find_rxinfo(v, depth + 1)
        if r:
            return r
    return None


def extract_phy(data):
    for _f, w, v in pb_fields(data):
        if w == 2 and isinstance(v, bytes) and len(v) >= 2 and v[0] == MAGIC:
            return v
    for f, w, v in pb_fields(data):
        if f == 1 and w == 2 and isinstance(v, bytes):
            return v
    return None


# ---------------------------------------------------------------- MQTT
def on_connect(client, _ud, _flags, rc, _props=None):
    print(f"[bridge] connected rc={rc}; subscribing {SUB_TOPIC}", flush=True)
    client.subscribe(SUB_TOPIC, 0)


def on_message(client, _ud, msg):
    phy = extract_phy(msg.payload)
    if phy is None:
        return
    frame = decode_frame(phy)
    if not frame:
        return
    rx = find_rxinfo(msg.payload) or {}
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "topic": msg.topic, **rx, **frame}
    line = json.dumps(rec)
    print("[CKB-LoRa] " + line, flush=True)
    try:
        with open(LOG, "a") as fp:
            fp.write(line + "\n")
    except Exception as e:  # noqa: BLE001
        print("[bridge] log error:", e, flush=True)
    client.publish(PUB_TOPIC, line, 0)


def main():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.reconnect_delay_set(1, 30)
    client.connect(BROKER, PORT, 60)
    client.loop_forever()


if __name__ == "__main__":
    main()
