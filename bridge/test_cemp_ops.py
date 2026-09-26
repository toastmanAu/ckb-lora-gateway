#!/usr/bin/env python3
"""Host tests for cemp_ops.py — no hardware, no live RPC.

Fakes the RPC + response sinks and exercises every P7 op, including the
stream-spillover path and the hostile-input rejections.
"""
import struct
import sys

sys.path.insert(0, ".")

import cemp_ops
from cemp_ops import (
    OP_CEMP_HELLO, OP_CEMP_PROFILE_GET, OP_CEMP_DISCOVER, OP_CEMP_CELL_GET,
    OP_CEMP_RESOLVE_INPUTS, OP_CEMP_TX_SUBMIT, OP_CEMP_TX_STATUS,
    ST_OK, ST_BAD_BODY, ST_NOT_FOUND, ST_STREAM, ST_TOO_MANY,
)

PASS = FAIL = 0
def ok(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS  {name}")
    else:
        FAIL += 1; print(f"  FAIL  {name}")

SECP = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"

class FakeRPC:
    """Minimal RPC double. Tests queue responses by method."""
    UNSET = object()
    def __init__(self):
        self.answers = {}
        self.calls = []
    def __call__(self, method, params):
        self.calls.append((method, params))
        a = self.answers.get(method, FakeRPC.UNSET)
        if a is FakeRPC.UNSET:
            raise RuntimeError(f"no fake for {method}")
        if callable(a):
            return a(params)
        return a

def make_ops(rpc=None):
    ops = cemp_ops.CempOps()
    responses = []
    streams = []
    rpc = rpc or FakeRPC()
    ops.wire(rpc=rpc,
             send_response=lambda rid, st, body=b"": responses.append((rid, st, body)),
             log=lambda *_: None,
             send_stream=lambda b: streams.append(b))
    return ops, responses, streams, rpc

def live_cell(cap, lock_args_hex, data_hex="0x", hash_type="type"):
    return {"status": "live", "cell": {
        "output": {"capacity": hex(cap),
                   "lock": {"code_hash": SECP, "hash_type": hash_type, "args": lock_args_hex},
                   "type": None},
        "data": {"content": data_hex, "hash": "0x00"},
    }}

# ── 1. HELLO ──────────────────────────────────────────────────────────────────
ops, resp, streams, rpc = make_ops()
ops.handle(1, OP_CEMP_HELLO, bytes([1]) + struct.pack("<I", 0x1F))
rid, st, body = resp[-1]
ok("HELLO status OK", st == ST_OK)
ok("HELLO caps length 12", len(body) == 12)
ok("HELLO proto version 1", body[0] == 1)
feat = struct.unpack_from("<I", body, 1)[0]
ok("HELLO advertises DISCOVER+CELL_GET+RESOLVE+SUBMIT+STATUS",
   feat & cemp_ops.FEAT_DISCOVER and feat & cemp_ops.FEAT_CELL_GET
   and feat & cemp_ops.FEAT_RESOLVE_INPUTS and feat & cemp_ops.FEAT_TX_SUBMIT
   and feat & cemp_ops.FEAT_TX_STATUS)

# ── 2. PROFILE_GET ────────────────────────────────────────────────────────────
profile_id = "ab" * 32
rpc = FakeRPC()
rpc.answers["get_cells"] = {"objects": [
    {"out_point": {"tx_hash": "0x" + "11" * 32, "index": "0x0"},
     "output": {"capacity": "0x1", "lock": {}, "type": None},
     "output_data": "0xdeadbeef"},
]}
ops, resp, streams, rpc = make_ops(rpc)
ops.handle(2, OP_CEMP_PROFILE_GET, bytes.fromhex(profile_id))
rid, st, body = resp[-1]
ok("PROFILE_GET returns raw data", st == ST_OK and body == bytes.fromhex("deadbeef"))
ok("PROFILE_GET queried by lock args", rpc.calls and rpc.calls[0][0] == "get_cells"
   and rpc.calls[0][1][0]["script"]["args"] == "0x" + profile_id)

# bad body
ops, resp, streams, rpc = make_ops()
ops.handle(3, OP_CEMP_PROFILE_GET, b"\x00" * 10)
ok("PROFILE_GET rejects bad body", resp[-1][1] == ST_BAD_BODY)

# not found
rpc = FakeRPC(); rpc.answers["get_cells"] = {"objects": []}
ops, resp, streams, rpc = make_ops(rpc)
ops.handle(4, OP_CEMP_PROFILE_GET, bytes.fromhex(profile_id))
ok("PROFILE_GET not-found", resp[-1][1] == ST_NOT_FOUND)

# ── 3. DISCOVER ───────────────────────────────────────────────────────────────
route_tag = "cd" * 32
objects = [
    {"out_point": {"tx_hash": "0x" + "22" * 32, "index": "0x1"},
     "output": {"capacity": "0x1", "lock": {}, "type": None}, "output_data": "0x"},
    {"out_point": {"tx_hash": "0x" + "33" * 32, "index": "0x0"},
     "output": {"capacity": "0x1", "lock": {}, "type": None}, "output_data": "0x"},
]
rpc = FakeRPC(); rpc.answers["get_cells"] = {"objects": objects}
ops, resp, streams, rpc = make_ops(rpc)
body = bytes.fromhex(route_tag) + struct.pack("<H", 4)
ops.handle(5, OP_CEMP_DISCOVER, body)
rid, st, payload = resp[-1]
if st == ST_STREAM:
    payload = streams[-1]
n = struct.unpack_from("<H", payload, 0)[0]
ok("DISCOVER returns 2 outpoints", st in (ST_OK, ST_STREAM) and n == 2)
ok("DISCOVER outpoint 0 correct", payload[2:34] == bytes.fromhex("22" * 32))
ok("DISCOVER index encoded", struct.unpack_from("<I", payload, 34)[0] == 1)
ok("DISCOVER used route tag as args", rpc.calls[0][1][0]["script"]["args"] == "0x" + route_tag)

# discover cache: second call must NOT hit rpc again
calls_before = len(rpc.calls)
ops.handle(6, OP_CEMP_DISCOVER, body)
ok("DISCOVER serves from cache", len(rpc.calls) == calls_before)

# limit clamp
ops2, resp2, _, rpc2 = make_ops(FakeRPC())
rpc2.answers["get_cells"] = {"objects": objects}
ops2.handle(7, OP_CEMP_DISCOVER, bytes.fromhex(route_tag) + struct.pack("<H", 60000))
ok("DISCOVER clamps huge limit", rpc2.calls[0][1][2] == hex(cemp_ops.MAX_DISCOVER_LIMIT))

# bad body
ops3, resp3, _, _ = make_ops()
ops3.handle(8, OP_CEMP_DISCOVER, b"\x00" * 10)
ok("DISCOVER rejects bad body", resp3[-1][1] == ST_BAD_BODY)

# ── 4. CELL_GET ───────────────────────────────────────────────────────────────
rpc = FakeRPC()
# small cell -> fits one frame
rpc.answers["get_live_cell"] = live_cell(1000, "0x" + "ab" * 20, "0xaabb")
ops, resp, streams, rpc = make_ops(rpc)
ops.handle(9, OP_CEMP_CELL_GET, bytes.fromhex("44" * 32) + struct.pack("<I", 0))
rid, st, body = resp[-1]
if st == ST_STREAM:
    body = streams[-1]
cap = struct.unpack_from("<Q", body, 0)[0]
llen = struct.unpack_from("<H", body, 8)[0]
ok("CELL_GET small: status OK", st in (ST_OK, ST_STREAM))
ok("CELL_GET capacity", cap == 1000)
ok("CELL_GET lock len 53", llen == 53)
ok("CELL_GET carries data", body.endswith(bytes.fromhex("aabb")))

# big cell -> must spill to stream
rpc = FakeRPC()
rpc.answers["get_live_cell"] = live_cell(1000, "0x" + "ab" * 20, "0x" + "cc" * 200)
ops, resp, streams, rpc = make_ops(rpc)
ops.handle(10, OP_CEMP_CELL_GET, bytes.fromhex("44" * 32) + struct.pack("<I", 0))
ok("CELL_GET big signals ST_STREAM", resp[-1][1] == ST_STREAM)
ok("CELL_GET big streamed once", len(streams) == 1 and len(streams[0]) > cemp_ops.STREAM_THRESHOLD)

# not live
rpc = FakeRPC(); rpc.answers["get_live_cell"] = {"status": "dead", "cell": None}
ops, resp, streams, rpc = make_ops(rpc)
ops.handle(11, OP_CEMP_CELL_GET, bytes.fromhex("44" * 32) + struct.pack("<I", 0))
ok("CELL_GET dead -> not found", resp[-1][1] == ST_NOT_FOUND)

# bad body
ops, resp, _, _ = make_ops()
ops.handle(12, OP_CEMP_CELL_GET, b"\x00" * 10)
ok("CELL_GET rejects bad body", resp[-1][1] == ST_BAD_BODY)

# ── 5. RESOLVE_INPUTS ─────────────────────────────────────────────────────────
rpc = FakeRPC()
rpc.answers["get_live_cell"] = lambda params: live_cell(
    5000, params[0]["index"] and "0x" + "ee" * 20 or "0x" + "ee" * 20, "0x" + "12" * 8)
rpc.answers["get_live_cell"] = live_cell(5000, "0x" + "ee" * 20, "0x" + "12" * 8)
ops, resp, streams, rpc = make_ops(rpc)
body = struct.pack("<H", 2) + (bytes.fromhex("55" * 32) + struct.pack("<I", 0)) * 2
ops.handle(13, OP_CEMP_RESOLVE_INPUTS, body)
rid, st, payload = resp[-1] if resp[-1][1] != ST_STREAM else (None, ST_STREAM, streams[-1])
ok("RESOLVE two inputs", st in (ST_OK, ST_STREAM))
count = struct.unpack_from("<H", payload, 0)[0]
ok("RESOLVE count echoed", count == 2)
# first input starts at offset 2
first_cap = struct.unpack_from("<Q", payload, 2)[0]
ok("RESOLVE first capacity", first_cap == 5000)

# count cap
ops, resp, _, _ = make_ops()
ops.handle(14, OP_CEMP_RESOLVE_INPUTS, struct.pack("<H", 999))
ok("RESOLVE rejects huge count", resp[-1][1] == ST_TOO_MANY)

# zero count
ops, resp, _, _ = make_ops()
ops.handle(15, OP_CEMP_RESOLVE_INPUTS, struct.pack("<H", 0))
ok("RESOLVE rejects zero count", resp[-1][1] == ST_TOO_MANY)

# size mismatch
ops, resp, _, _ = make_ops()
ops.handle(16, OP_CEMP_RESOLVE_INPUTS, struct.pack("<H", 2) + b"\x00" * 10)
ok("RESOLVE rejects size mismatch", resp[-1][1] == ST_BAD_BODY)

# not live
rpc = FakeRPC(); rpc.answers["get_live_cell"] = {"status": "dead", "cell": None}
ops, resp, streams, rpc = make_ops(rpc)
body = struct.pack("<H", 1) + bytes.fromhex("55" * 32) + struct.pack("<I", 0)
ops.handle(17, OP_CEMP_RESOLVE_INPUTS, body)
ok("RESOLVE not-live input", resp[-1][1] == ST_NOT_FOUND)

# ── 6. TX_SUBMIT ──────────────────────────────────────────────────────────────
rpc = FakeRPC(); rpc.answers["send_transaction"] = "0x" + "aa" * 32
ops, resp, streams, rpc = make_ops(rpc)
raw_tx = b"\x01\x02\x03\x04" * 10
ops.handle(18, OP_CEMP_TX_SUBMIT, struct.pack("<I", len(raw_tx)) + raw_tx)
rid, st, body = resp[-1]
ok("TX_SUBMIT returns hash", st == ST_OK and body == bytes.fromhex("aa" * 32))
ok("TX_SUBMIT passed raw hex to rpc", rpc.calls[0][1][0] == "0x" + raw_tx.hex())

# duplicate -> success
def dup(params): raise RuntimeError("TransactionAlreadyKnown: already in pool")
rpc = FakeRPC(); rpc.answers["send_transaction"] = dup
ops, resp, streams, rpc = make_ops(rpc)
ops.handle(19, OP_CEMP_TX_SUBMIT, struct.pack("<I", len(raw_tx)) + raw_tx)
ok("TX_SUBMIT dup treated as OK", resp[-1][1] == ST_OK)

# size mismatch
ops, resp, _, _ = make_ops()
ops.handle(20, OP_CEMP_TX_SUBMIT, struct.pack("<I", 999) + b"\x00" * 4)
ok("TX_SUBMIT rejects size mismatch", resp[-1][1] == ST_BAD_BODY)

# rpc failure
def boom(params): raise RuntimeError("rejected: invalid")
rpc = FakeRPC(); rpc.answers["send_transaction"] = boom
ops, resp, streams, rpc = make_ops(rpc)
ops.handle(21, OP_CEMP_TX_SUBMIT, struct.pack("<I", len(raw_tx)) + raw_tx)
ok("TX_SUBMIT rpc failure -> error", resp[-1][1] == cemp_ops.ST_RPC_ERROR)

# ── 7. TX_STATUS ──────────────────────────────────────────────────────────────
tx_hash = "0x" + "66" * 32
rpc = FakeRPC(); rpc.answers["get_transaction"] = {
    "tx_status": {"status": "committed", "block_hash": "0x" + "77" * 32}}
rpc.answers["get_header"] = {"number": "0x1234"}
ops, resp, streams, rpc = make_ops(rpc)
ops.handle(22, OP_CEMP_TX_STATUS, bytes.fromhex("66" * 32))
rid, st, body = resp[-1]
code, blk = struct.unpack("<BI", body)
ok("TX_STATUS committed code=1", code == 1)
ok("TX_STATUS block number", blk == 0x1234)

# pending
rpc = FakeRPC(); rpc.answers["get_transaction"] = {
    "tx_status": {"status": "pending", "block_hash": None}}
ops, resp, streams, rpc = make_ops(rpc)
ops.handle(23, OP_CEMP_TX_STATUS, bytes.fromhex("66" * 32))
code, blk = struct.unpack("<BI", resp[-1][2])
ok("TX_STATUS pending code=0", code == 0 and blk == 0)

# unknown (None)
rpc = FakeRPC(); rpc.answers["get_transaction"] = None
ops, resp, streams, rpc = make_ops(rpc)
ops.handle(24, OP_CEMP_TX_STATUS, bytes.fromhex("66" * 32))
ok("TX_STATUS unknown -> 0/0", struct.unpack("<BI", resp[-1][2]) == (0, 0))

# rejected
rpc = FakeRPC(); rpc.answers["get_transaction"] = {
    "tx_status": {"status": "rejected", "block_hash": None}}
ops, resp, streams, rpc = make_ops(rpc)
ops.handle(25, OP_CEMP_TX_STATUS, bytes.fromhex("66" * 32))
ok("TX_STATUS rejected code=2", struct.unpack("<BI", resp[-1][2])[0] == 2)

# bad body
ops, resp, _, _ = make_ops()
ops.handle(26, OP_CEMP_TX_STATUS, b"\x00" * 10)
ok("TX_STATUS rejects bad body", resp[-1][1] == ST_BAD_BODY)

# ── 8. no-stream-channel fallback ─────────────────────────────────────────────
ops = cemp_ops.CempOps()
resp = []
rpc = FakeRPC(); rpc.answers["get_live_cell"] = live_cell(1000, "0x" + "ab" * 20, "0x" + "cc" * 200)
ops.wire(rpc=rpc, send_response=lambda r, s, b=b"": resp.append((r, s, b)),
         log=lambda *_: None, send_stream=None)
ops.handle(27, OP_CEMP_CELL_GET, bytes.fromhex("44" * 32) + struct.pack("<I", 0))
ok("no stream channel -> RPC_ERROR not hang", resp[-1][1] == cemp_ops.ST_RPC_ERROR)

# ── 9. unknown op passthrough ─────────────────────────────────────────────────
ops, resp, _, _ = make_ops()
r = ops.handle(28, 0xEE, b"")
ok("unknown op returns 'unknown'", r == "unknown")

print(f"\nCEMP_OPS: {'PASS' if FAIL == 0 else 'FAIL'} ({PASS} case(s), {FAIL} failure(s))")
sys.exit(1 if FAIL else 0)
