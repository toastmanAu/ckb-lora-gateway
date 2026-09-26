#!/usr/bin/env python3
"""
CKB-LoRa ⇄ CKB bridge  (gateway side, runs on the SenseCAP M1)
==============================================================
Turns LoRa requests from a T-Deck wallet into CKB RPC calls, and sends the
results back over LoRa. The device holds the private keys; this bridge only
talks to CKB (balance / tip / cells / broadcast).

Wire protocol (raw LoRa bytes):
  uplink   [CB][02][req_id][op][body...]                 device -> gateway
  downlink [CB][03][req_id][status][body...]             gateway -> device

Ops:
  0x01 PING      -> (empty)
  0x02 BAL       body = code_hash(32)+hash_type(1)+args_len(1)+args(N)  -> capacity u64 LE
  0x03 TIP       -> (empty)                             -> block u32 LE
  0x04 SEND_REQ  body = from_args(20)+to_args(20)+amt u64 -> sighash(32)   [P2]
  0x05 WITNESS   body = der/sig bytes                    -> txhash(32)      [P2]
  0x06 CELLS     body = code_hash(32)+hash_type(1)+args_len(1)+args(N)
                 -> tx_hash(32) + index u32 LE + capacity u64 LE   (largest plain cell)

Input : MQTT  ckblora/decoded   (JSON from bridge.py)
Output: MQTT  <region>/gateway/<eui>/command/down  (gw.DownlinkFrame protobuf)

Run: ~/ckb-lora-bridge/venv/bin/python ~/ckb-lora-bridge/ckb_bridge.py
"""
import json
import os
import struct
import threading
import time
import urllib.request

import paho.mqtt.client as mqtt

import gwtx  # reuse the DownlinkFrame protobuf builder + topics
import phase2_handlers as P2

BROKER = "localhost"
PORT = 1883
SUB_TOPIC = "ckblora/decoded"
LOG = os.path.expanduser("~/ckb-lora-bridge/ckb_bridge.log")

CKB_RPC = os.environ.get("CKB_RPC", "https://testnet.ckb.dev")

MAGIC = 0xCB
TYPE_REQUEST = 0x02
TYPE_RESPONSE = 0x03

OP_PING = 0x01
OP_BAL = 0x02
OP_TIP = 0x03
OP_SEND_REQ = 0x04
OP_WITNESS = 0x05
OP_CELLS = 0x06

# default (SECP256K1_BLAKE160) lock, same code hash on testnet & mainnet
SECP_CODE_HASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
HASH_TYPE = "type"

# downlink RF (must match what the device listens on)
DL_FREQ = 923_300_000
DL_SF = 9
DL_BW = 125_000
DL_POWER = 20


def log(msg):
    line = f"[ckb-bridge] {time.strftime('%H:%M:%S')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG, "a") as fp:
            fp.write(line + "\n")
    except Exception:
        pass


# ── CKB RPC ───────────────────────────────────────────────────────────────────
def rpc(method, params):
    body = json.dumps({"id": 1, "jsonrpc": "2.0", "method": method, "params": params}).encode()
    req = urllib.request.Request(CKB_RPC, data=body, headers={
        "Content-Type": "application/json",
        "User-Agent": "curl/8.5.0",   # testnet.ckb.dev sits behind Cloudflare; block default UA
    })
    with urllib.request.urlopen(req, timeout=12) as r:
        res = json.loads(r.read())
    if "error" in res:
        raise RuntimeError(res["error"])
    return res["result"]


def balance_shannons(code_hash, hash_type, args_hex):
    sk = {"script": {"code_hash": code_hash, "hash_type": hash_type,
                    "args": args_hex},
          "script_type": "lock"}
    res = rpc("get_cells_capacity", [sk])
    return int(res["capacity"], 16)


def largest_cell(code_hash, hash_type, args_hex, limit=0x100):
    """Largest plain-CKB cell (no type script / empty data) locked by this script.

    Returns (tx_hash_str, index_int, capacity_int) or None. One cell is enough
    for a simple send, and keeps the LoRa response inside one 64 B frame.
    """
    sk = {"script": {"code_hash": code_hash, "hash_type": hash_type,
                    "args": args_hex},
          "script_type": "lock"}
    res = rpc("get_cells", [sk, "asc", hex(limit)])
    best = None
    for c in res.get("objects", []):
        data = c.get("output_data", "0x")
        if data not in ("0x", "", None):
            continue                      # skip cells carrying data / type scripts
        cap = int(c["output"]["capacity"], 16)
        op = c["out_point"]
        idx = int(op["index"], 16)
        if best is None or cap > best[2]:
            best = (op["tx_hash"], idx, cap)
    return best


HASH_TYPES = {0: "data", 1: "type", 2: "data1", 3: "data2"}


def parse_lock_body(req_id, op, body):
    """body = code_hash(32) + hash_type(1) + args_len(1) + args(N) -> (ch, ht, args) | None"""
    if len(body) < 34:
        log(f"op=0x{op:02x} req={req_id} bad body ({len(body)}B)")
        send_response(req_id, 4)
        return None
    ch = "0x" + body[0:32].hex()
    ht = HASH_TYPES.get(body[32], "type")
    alen = body[33]
    args = "0x" + body[34:34 + alen].hex()
    return ch, ht, args


# ── frame helpers ─────────────────────────────────────────────────────────────
def send_response(req_id, status, body=b""):
    # downlink: [CB][03][id_lo][id_hi][status][body...]   (16-bit req id)
    frame = bytes([MAGIC, TYPE_RESPONSE, req_id & 0xFF, (req_id >> 8) & 0xFF,
                   status & 0xFF]) + body
    dl = gwtx.build_downlink_frame(frame, DL_FREQ, DL_SF, DL_BW, 1, 8, DL_POWER,
                                   int(time.time()) & 0xFFFFFFFF)
    gwtx.publish_raw(dl)
    log(f"-> resp req={req_id} status={status} body={body.hex()} "
        f"({len(frame)}B frame, {len(dl)}B downlink)")


def handle(req_id, op, body):
    if op == OP_PING:
        log(f"PING req={req_id}")
        send_response(req_id, 0)

    elif op == OP_TIP:
        blk = int(rpc("get_tip_block_number", []), 16)
        log(f"TIP req={req_id} -> {blk}")
        send_response(req_id, 0, struct.pack("<I", blk & 0xFFFFFFFF))

    elif op == OP_BAL:
        p = parse_lock_body(req_id, op, body)
        if not p:
            return
        code_hash, ht, args = p
        cap = balance_shannons(code_hash, ht, args)
        log(f"BAL req={req_id} script={code_hash[:10]}..:{ht}:{args} -> {cap} shannons ({cap/1e8:.4f} CKB)")
        send_response(req_id, 0, struct.pack("<Q", cap))

    elif op == OP_CELLS:
        p = parse_lock_body(req_id, op, body)
        if not p:
            return
        code_hash, ht, args = p
        cell = largest_cell(code_hash, ht, args)
        if not cell:
            log(f"CELLS req={req_id} script={code_hash[:10]}..:{ht}:{args} -> no spendable cells")
            send_response(req_id, 5)
            return
        txh, idx, cap = cell
        log(f"CELLS req={req_id} -> {txh[:12]}..:{idx} {cap} shannons ({cap/1e8:.4f} CKB)")
        send_response(req_id, 0, bytes.fromhex(txh[2:]) + struct.pack("<I", idx) + struct.pack("<Q", cap))

    elif op == OP_SEND_REQ:
        P2.handle_send_req(req_id, body)

    elif op == OP_WITNESS:
        P2.handle_witness(req_id, body)

    else:
        log(f"unknown op 0x{op:02x} req={req_id}")
        send_response(req_id, 2)


# ── MQTT ──────────────────────────────────────────────────────────────────────
_client = None


def _schedule(delay_s, fn):
    """Run fn after delay_s without blocking the MQTT loop (thread timer)."""
    threading.Timer(delay_s, fn).start()


def on_connect(client, _ud, _flags, rc, _props=None):
    log(f"connected rc={rc}; subscribing {SUB_TOPIC}")
    client.subscribe(SUB_TOPIC, 0)


def on_message(_c, _ud, msg):
    try:
        rec = json.loads(msg.payload)
    except Exception:
        return
    if rec.get("type") != TYPE_REQUEST:
        return
    raw = bytes.fromhex(rec.get("raw", ""))
    if len(raw) < 5:
        return
    # uplink: [CB][02][id_lo][id_hi][op][body...]   (16-bit req id)
    req_id = raw[2] | (raw[3] << 8)
    op = raw[4]
    log(f"REQ id={req_id} op=0x{op:02x} rssi={rec.get('rssi')} snr={rec.get('snr')} body={raw[5:].hex()}")
    try:
        handle(req_id, op, raw[5:])
    except Exception as e:  # noqa: BLE001
        log(f"handler error: {e}")
        send_response(req_id, 3)


def main():
    global _client
    _client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    P2.wire(rpc, send_response, log, _schedule)
    log(f"starting; CKB_RPC={CKB_RPC} downlink={DL_FREQ/1e6:.1f}MHz SF{DL_SF}")
    _client.on_connect = on_connect
    _client.on_message = on_message
    _client.reconnect_delay_set(1, 30)
    _client.connect(BROKER, PORT, 60)
    # periodically drop built-but-unsigned sends so PENDING cannot leak
    def _sweep():
        try:
            P2.sweep_pending()
        finally:
            _schedule(15, _sweep)
    _schedule(15, _sweep)
    _client.loop_forever()


if __name__ == "__main__":
    main()
