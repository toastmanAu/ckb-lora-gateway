#!/usr/bin/env python3
"""
cemp_ops.py — gateway-side CEMP application operations (Phase P7).

These sit *above* the raw CKB primitives in `ckb_bridge.py` (PING/BAL/TIP/
CELLS/SEND_REQ/WITNESS). Where those move plain CKB, these let a device:

  * discover CEMP cells addressed to its route tags,
  * pull complete raw cell data through the P6 stream layer (never truncated),
  * assemble the exact inputs it needs to build its ML-DSA signing stream,
  * submit a fully device-signed transaction for broadcast.

NON-CUSTODIAL INVARIANTS (do not weaken):
  * the gateway never sees a mnemonic, secret key, shared secret, message key
    or plaintext payload — only public cell data and, at submit time, a
    finished signed transaction;
  * `CEMP_RESOLVE_INPUTS` returns *public* CellOutput + cell data only;
  * `CEMP_TX_SUBMIT` only calls `send_transaction` on a device-built tx.

Wire ops (uplink body after the 5-byte legacy envelope):
  0x10 CEMP_HELLO           body = version_u8(1)+features_u32_le(4)  -> caps(12)
  0x11 CEMP_PROFILE_GET     body = profile_id(32)                    -> raw profile cell data
  0x12 CEMP_DISCOVER        body = route_tag(32)+limit_u16_le(2)     -> outpoint list
  0x13 CEMP_CELL_GET        body = tx_hash(32)+index_u32_le(4)       -> full cell (streamed)
  0x14 CEMP_RESOLVE_INPUTS  body = count_u16_le(2)+[tx_hash(32)+idx_u32_le(4)]*  -> inputs
  0x15 CEMP_TX_SUBMIT       body = raw_tx_len_u32_le(4)+raw_tx(N)    -> tx_hash(32)
  0x16 CEMP_TX_STATUS       body = tx_hash(32)                       -> status(1)+block(4|0)

Responses are legacy frames ([CB][03][id][status][body]) when the body is small,
and are switched to the P6 stream when the body exceeds one safe LoRa frame
(callers must set STREAM_THRESHOLD accordingly). The device decides how to read
them via the status byte: status 0x80 = "answer arrives on the stream channel".
"""
from __future__ import annotations

import struct
import time

# ── op codes ──────────────────────────────────────────────────────────────────
OP_CEMP_HELLO = 0x10
OP_CEMP_PROFILE_GET = 0x11
OP_CEMP_DISCOVER = 0x12
OP_CEMP_CELL_GET = 0x13
OP_CEMP_RESOLVE_INPUTS = 0x14
OP_CEMP_TX_SUBMIT = 0x15
OP_CEMP_TX_STATUS = 0x16

# ── status codes (gateway -> device) ─────────────────────────────────────────
ST_OK = 0
ST_BAD_BODY = 4
ST_NOT_FOUND = 5
ST_TOO_MANY = 8
ST_RPC_ERROR = 9
ST_STREAM = 0x80          # "the real answer is being sent on the stream channel"

# ── protocol versioning (spec rule 13: everything serialised is versioned) ────
CEMP_GW_PROTOCOL_VERSION = 1

# A single legacy LoRa downlink frame is comfortable at <= 64 B body. Anything
# bigger must go via the P6 stream so it is never truncated.
STREAM_THRESHOLD = 64

# Hard caps so a hostile device cannot exhaust the gateway.
MAX_DISCOVER_LIMIT = 64
MAX_RESOLVE_INPUTS = 32
MAX_TX_BYTES = 128 * 1024          # CKB tx size ceiling
DISCOVER_CACHE_TTL_S = 30

# Feature bits advertised in HELLO.
FEAT_DISCOVER = 1 << 0
FEAT_CELL_GET = 1 << 1
FEAT_RESOLVE_INPUTS = 1 << 2
FEAT_TX_SUBMIT = 1 << 3
FEAT_TX_STATUS = 1 << 4


class CempOps:
    """Gateway CEMP operation handler.

    Collaborators are injected by ckb_bridge at wire() time so this module stays
    import-clean and unit-testable without a live MQTT/RPC connection.
    """

    def __init__(self):
        self.rpc = None
        self.send_response = None
        self.send_stream = None       # callable(bytes) -> None   (P6 stream sender)
        self.log = print
        self.pending = {}             # n/a for P7 (device signs) — kept for parity
        self._discover_cache = {}     # route_tag_hex -> (expiry, payload)

    def wire(self, rpc, send_response, log, send_stream=None):
        self.rpc = rpc
        self.send_response = send_response
        self.log = log
        self.send_stream = send_stream

    # ── helpers ───────────────────────────────────────────────────────────────
    def _respond(self, req_id, status, body: bytes = b""):
        """Send a small legacy-frame response, or stream a large one.

        If the body cannot fit a single safe LoRa frame, reply with ST_STREAM and
        push the payload through the P6 stream channel so it arrives intact.
        """
        if len(body) > STREAM_THRESHOLD:
            if self.send_stream is None:
                self.log(f"cemp req={req_id} body {len(body)}B too large and no stream channel")
                self.send_response(req_id, ST_RPC_ERROR)
                return
            self.send_response(req_id, ST_STREAM)
            self.send_stream(body)
            self.log(f"cemp req={req_id} -> STREAM ({len(body)}B)")
            return
        self.send_response(req_id, status, body)

    # ── op handlers ───────────────────────────────────────────────────────────
    def handle(self, req_id: int, op: int, body: bytes) -> str:
        if op == OP_CEMP_HELLO:
            return self._hello(req_id, body)
        if op == OP_CEMP_PROFILE_GET:
            return self._profile_get(req_id, body)
        if op == OP_CEMP_DISCOVER:
            return self._discover(req_id, body)
        if op == OP_CEMP_CELL_GET:
            return self._cell_get(req_id, body)
        if op == OP_CEMP_RESOLVE_INPUTS:
            return self._resolve_inputs(req_id, body)
        if op == OP_CEMP_TX_SUBMIT:
            return self._tx_submit(req_id, body)
        if op == OP_CEMP_TX_STATUS:
            return self._tx_status(req_id, body)
        return "unknown"

    def _hello(self, req_id, body):
        """Exchange protocol version + feature bits. Never fails on bad version:
        the device needs the gateway's caps to decide, not a hard error."""
        dev_ver = body[0] if len(body) >= 1 else 0
        dev_features = struct.unpack_from("<I", body, 1)[0] if len(body) >= 5 else 0
        features = FEAT_DISCOVER | FEAT_CELL_GET | FEAT_RESOLVE_INPUTS | FEAT_TX_SUBMIT | FEAT_TX_STATUS
        # caps = proto_ver(1) + features(4) + max_stream_payload(4) + max_inputs(2) + reserved(1)
        caps = (bytes([CEMP_GW_PROTOCOL_VERSION])
                + struct.pack("<I", features)
                + struct.pack("<I", MAX_TX_BYTES)
                + struct.pack("<H", MAX_RESOLVE_INPUTS)
                + b"\x00")
        self.log(f"CEMP_HELLO req={req_id} dev_ver={dev_ver} dev_feat=0x{dev_features:08x} "
                 f"-> gw_ver={CEMP_GW_PROTOCOL_VERSION} feat=0x{features:08x}")
        self.send_response(req_id, ST_OK, caps)
        return "hello"

    def _profile_get(self, req_id, body):
        """Return the canonical raw profile cell data for a profile id.

        A CEMP profile is a cell whose lock args == profile_id. We locate the
        newest live one and return its raw data so the device can verify the
        binding itself (provenance is NOT trusted from the gateway).
        """
        if len(body) != 32:
            self.log(f"CEMP_PROFILE_GET req={req_id} bad body ({len(body)}B)")
            self.send_response(req_id, ST_BAD_BODY)
            return "profile-bad-body"
        profile_id = "0x" + body.hex()
        try:
            cells = self._cells_by_lock_args(profile_id, limit=8)
        except Exception as e:  # noqa: BLE001
            self.log(f"CEMP_PROFILE_GET req={req_id} rpc error: {e}")
            self.send_response(req_id, ST_RPC_ERROR)
            return "profile-rpc-error"
        if not cells:
            self.log(f"CEMP_PROFILE_GET req={req_id} profile={profile_id[:12]}.. not found")
            self.send_response(req_id, ST_NOT_FOUND)
            return "profile-not-found"
        # newest = first from "desc", but get_cells order is tx order; pick the
        # one with the largest block number when known, else the first.
        best = cells[0]
        data = best.get("output_data", "0x")
        raw = bytes.fromhex(data[2:]) if data.startswith("0x") else b""
        self.log(f"CEMP_PROFILE_GET req={req_id} profile={profile_id[:12]}.. -> {len(raw)}B")
        self._respond(req_id, ST_OK, raw)
        return "profile"

    def _discover(self, req_id, body):
        """Return candidate outpoints whose lock args match a route tag.

        The device supplies its *route tag* (never its profile id — see the
        CellSend memory / rule: a leaked profile id exposes every epoch's inbox
        tag). We hand back outpoints + minimal metadata; the device decides what
        to fetch and decrypt.
        """
        if len(body) != 34:
            self.log(f"CEMP_DISCOVER req={req_id} bad body ({len(body)}B)")
            self.send_response(req_id, ST_BAD_BODY)
            return "discover-bad-body"
        route_tag = body[:32]
        limit = struct.unpack_from("<H", body, 32)[0]
        if limit == 0:
            limit = 16
        if limit > MAX_DISCOVER_LIMIT:
            limit = MAX_DISCOVER_LIMIT
        tag_hex = "0x" + route_tag.hex()

        now = time.time()
        hit = self._discover_cache.get(tag_hex)
        if hit and hit[0] > now:
            payload = hit[1]
        else:
            try:
                cells = self._cells_by_lock_args(tag_hex, limit=limit)
            except Exception as e:  # noqa: BLE001
                self.log(f"CEMP_DISCOVER req={req_id} rpc error: {e}")
                self.send_response(req_id, ST_RPC_ERROR)
                return "discover-rpc-error"
            payload = self._encode_outpoints(cells)
            self._discover_cache[tag_hex] = (now + DISCOVER_CACHE_TTL_S, payload)

        self.log(f"CEMP_DISCOVER req={req_id} tag={tag_hex[:12]}.. limit={limit} -> {len(payload)}B")
        self._respond(req_id, ST_OK, payload)
        return "discover"

    def _cell_get(self, req_id, body):
        """Return a complete cell (raw cell data + its output) — never truncated.

        Large cells always go out on the stream channel.
        """
        if len(body) != 36:
            self.log(f"CEMP_CELL_GET req={req_id} bad body ({len(body)}B)")
            self.send_response(req_id, ST_BAD_BODY)
            return "cell-bad-body"
        tx_hash = "0x" + body[:32].hex()
        index = struct.unpack_from("<I", body, 32)[0]
        try:
            cell = self.rpc("get_live_cell",
                            [{"tx_hash": tx_hash, "index": hex(index)}, True])
        except Exception as e:  # noqa: BLE001
            self.log(f"CEMP_CELL_GET req={req_id} rpc error: {e}")
            self.send_response(req_id, ST_RPC_ERROR)
            return "cell-rpc-error"
        status = (cell or {}).get("status")
        if status != "live" or not cell.get("cell"):
            self.log(f"CEMP_CELL_GET req={req_id} {tx_hash[:12]}..:{index} status={status}")
            self.send_response(req_id, ST_NOT_FOUND)
            return "cell-not-found"
        c = cell["cell"]
        data_hex = c.get("data", {}).get("content", "0x")
        raw = bytes.fromhex(data_hex[2:]) if data_hex.startswith("0x") else b""
        # Frame: capacity_u64 + lock_len_u16 + lock_bytes + type_len_u16 + type_bytes + data
        out = c["output"]
        lock = out["lock"]
        lock_bytes = (bytes.fromhex(lock["code_hash"][2:])
                      + bytes([_hash_type_num(lock["hash_type"])])
                      + bytes.fromhex(lock["args"][2:]))
        type_script = out.get("type")
        type_bytes = b""
        if type_script:
            type_bytes = (bytes.fromhex(type_script["code_hash"][2:])
                          + bytes([_hash_type_num(type_script["hash_type"])])
                          + bytes.fromhex(type_script["args"][2:]))
        cap = int(out["capacity"], 16)
        payload = (struct.pack("<Q", cap)
                   + struct.pack("<H", len(lock_bytes)) + lock_bytes
                   + struct.pack("<H", len(type_bytes)) + type_bytes
                   + raw)
        self.log(f"CEMP_CELL_GET req={req_id} {tx_hash[:12]}..:{index} -> {len(raw)}B data, {len(payload)}B")
        self._respond(req_id, ST_OK, payload)
        return "cell"

    def _resolve_inputs(self, req_id, body):
        """Return exact CellOutput + cell data for each requested input.

        This is what the device needs to build its ML-DSA signing stream: the
        signing hash covers each input's *full* cell (capacity, lock, type, data),
        so partial data is useless. Public data only — no keys.
        """
        if len(body) < 2:
            self.log(f"CEMP_RESOLVE_INPUTS req={req_id} bad body ({len(body)}B)")
            self.send_response(req_id, ST_BAD_BODY)
            return "resolve-bad-body"
        count = struct.unpack_from("<H", body, 0)[0]
        if count == 0 or count > MAX_RESOLVE_INPUTS:
            self.log(f"CEMP_RESOLVE_INPUTS req={req_id} count={count} out of range")
            self.send_response(req_id, ST_TOO_MANY)
            return "resolve-count"
        if len(body) != 2 + count * 36:
            self.log(f"CEMP_RESOLVE_INPUTS req={req_id} size mismatch ({len(body)}B for {count})")
            self.send_response(req_id, ST_BAD_BODY)
            return "resolve-size"

        parts = [struct.pack("<H", count)]
        for i in range(count):
            off = 2 + i * 36
            tx_hash = "0x" + body[off:off + 32].hex()
            index = struct.unpack_from("<I", body, off + 32)[0]
            try:
                cell = self.rpc("get_live_cell",
                                [{"tx_hash": tx_hash, "index": hex(index)}, True])
            except Exception as e:  # noqa: BLE001
                self.log(f"CEMP_RESOLVE_INPUTS req={req_id} rpc error on {i}: {e}")
                self.send_response(req_id, ST_RPC_ERROR)
                return "resolve-rpc-error"
            if (cell or {}).get("status") != "live" or not cell.get("cell"):
                self.log(f"CEMP_RESOLVE_INPUTS req={req_id} input {i} not live")
                self.send_response(req_id, ST_NOT_FOUND)
                return "resolve-not-live"
            c = cell["cell"]
            out = c["output"]
            data_hex = c.get("data", {}).get("content", "0x")
            raw = bytes.fromhex(data_hex[2:]) if data_hex.startswith("0x") else b""
            lock = out["lock"]
            lock_bytes = (bytes.fromhex(lock["code_hash"][2:])
                          + bytes([_hash_type_num(lock["hash_type"])])
                          + bytes.fromhex(lock["args"][2:]))
            type_script = out.get("type")
            type_bytes = b""
            if type_script:
                type_bytes = (bytes.fromhex(type_script["code_hash"][2:])
                              + bytes([_hash_type_num(type_script["hash_type"])])
                              + bytes.fromhex(type_script["args"][2:]))
            cap = int(out["capacity"], 16)
            # per-input: capacity u64 + lock_len u16 + lock + type_len u16 + type + data_len u32 + data
            parts.append(struct.pack("<Q", cap)
                         + struct.pack("<H", len(lock_bytes)) + lock_bytes
                         + struct.pack("<H", len(type_bytes)) + type_bytes
                         + struct.pack("<I", len(raw)) + raw)
        payload = b"".join(parts)
        self.log(f"CEMP_RESOLVE_INPUTS req={req_id} n={count} -> {len(payload)}B")
        self._respond(req_id, ST_OK, payload)
        return "resolve"

    def _tx_submit(self, req_id, body):
        """Broadcast a fully device-signed transaction.

        The gateway does NOT build or sign. It only validates the sizing and
        hands the raw tx to `send_transaction`. Duplicate broadcasts are treated
        as success (the device retransmits when an ack is lost), exactly like the
        OP_WITNESS path.
        """
        if len(body) < 4:
            self.log(f"CEMP_TX_SUBMIT req={req_id} bad body ({len(body)}B)")
            self.send_response(req_id, ST_BAD_BODY)
            return "submit-bad-body"
        raw_len = struct.unpack_from("<I", body, 0)[0]
        if raw_len == 0 or raw_len > MAX_TX_BYTES or len(body) != 4 + raw_len:
            self.log(f"CEMP_TX_SUBMIT req={req_id} bad tx len raw={raw_len} body={len(body)}")
            self.send_response(req_id, ST_BAD_BODY)
            return "submit-size"
        raw_tx = body[4:4 + raw_len]
        try:
            tx_hash = self.rpc("send_transaction", ["0x" + raw_tx.hex()])
        except Exception as e:  # noqa: BLE001
            msg = str(e).lower()
            if "already" in msg or "duplicate" in msg or "known" in msg:
                # Cannot recover the hash from a raw tx here without local
                # hashing; ask the device to re-query by its own computed hash.
                self.log(f"CEMP_TX_SUBMIT req={req_id} already known -> status query")
                self.send_response(req_id, ST_OK)
                return "submit-dup"
            self.log(f"CEMP_TX_SUBMIT req={req_id} broadcast FAILED: {e}")
            self.send_response(req_id, ST_RPC_ERROR)
            return "submit-fail"
        th = bytes.fromhex(tx_hash[2:]) if tx_hash.startswith("0x") else bytes.fromhex(tx_hash)
        self.log(f"CEMP_TX_SUBMIT req={req_id} -> {tx_hash[:14]}..")
        self.send_response(req_id, ST_OK, th)
        return "submit"

    def _tx_status(self, req_id, body):
        """Return commit status for a tx hash: status(1) + block_u32_le(4, 0 if pending)."""
        if len(body) != 32:
            self.log(f"CEMP_TX_STATUS req={req_id} bad body ({len(body)}B)")
            self.send_response(req_id, ST_BAD_BODY)
            return "status-bad-body"
        tx_hash = "0x" + body.hex()
        try:
            res = self.rpc("get_transaction", [tx_hash])
        except Exception as e:  # noqa: BLE001
            self.log(f"CEMP_TX_STATUS req={req_id} rpc error: {e}")
            self.send_response(req_id, ST_RPC_ERROR)
            return "status-rpc-error"
        if not res:
            # not found yet (still in mempool or unknown)
            self.send_response(req_id, ST_OK, struct.pack("<BI", 0, 0))
            self.log(f"CEMP_TX_STATUS req={req_id} {tx_hash[:14]}.. -> pending/unknown")
            return "status-pending"
        ts = res.get("tx_status", {})
        st = ts.get("status", "unknown")
        block = ts.get("block_hash")
        # 0=unknown/pending, 1=committed, 2=rejected
        code = {"pending": 0, "proposed": 0, "committed": 1, "unknown": 0,
                "rejected": 2}.get(st, 0)
        blk_num = 0
        if code == 1 and block:
            try:
                hdr = self.rpc("get_header", [block])
                if hdr:
                    blk_num = int(hdr["number"], 16)
            except Exception:  # noqa: BLE001
                pass
        self.send_response(req_id, ST_OK, struct.pack("<BI", code, blk_num & 0xFFFFFFFF))
        self.log(f"CEMP_TX_STATUS req={req_id} {tx_hash[:14]}.. -> {st} block={blk_num}")
        return "status"

    # ── RPC helpers ───────────────────────────────────────────────────────────
    def _cells_by_lock_args(self, args_hex, limit):
        """Cells locked by our standard lock with the given args (route tag /
        profile id). Mirrors ckb_bridge.largest_cell's search shape."""
        sk = {"script": {"code_hash": SECP_CODE_HASH, "hash_type": "type",
                         "args": args_hex},
              "script_type": "lock"}
        res = self.rpc("get_cells", [sk, "desc", hex(limit)])
        return res.get("objects", [])

    def _encode_outpoints(self, cells):
        """Encode a discover result: count_u16 + [tx_hash(32)+index_u32]*.

        Kept deliberately minimal so it usually fits one frame; if the device
        wants the data it follows up with CEMP_CELL_GET per outpoint.
        """
        out = [struct.pack("<H", len(cells))]
        for c in cells:
            op = c["out_point"]
            th = bytes.fromhex(op["tx_hash"][2:])
            idx = int(op["index"], 16)
            out.append(th + struct.pack("<I", idx))
        return b"".join(out)


# default secp256k1_blake160 lock (type hash), shared testnet/mainnet.
# Defined in phase2_handlers; import to keep one source of truth.
from phase2_handlers import SECP_CODE_HASH_B  # noqa: E402
SECP_CODE_HASH = "0x" + SECP_CODE_HASH_B.hex()


def _hash_type_num(name: str) -> int:
    return {"data": 0, "type": 1, "data1": 2, "data2": 3}.get(name, 1)
