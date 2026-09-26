"""
cemp_stream_rx.py — gateway-side P6 reliable stream receiver.

Runs inside the live ckb-lora-bridge process (or alongside it). Consumes raw
uplink frames that carry a CEMP-LoRa stream payload and:
  - feeds them to a pure-Python port of the P6 state machine
  - emits selective ACKs back down the RF chain (via gwtx)
  - logs each completed object with CRC verification

Wire shape: uplink frames from the T-Deck are the raw cemp_stream frame bytes
(0x10..0x14) inserted as the body of a legacy envelope so the existing bridge
dispatcher can route them:

    [CB][02][id_lo][id_hi][OP_STREAM][ <cemp_stream frame> ]

The bridge's on_message() routes OP_STREAM bodies here.

This is the mirror of ckb-light-esp/components/ckb_transport/cemp_stream.c and
must stay byte-compatible with it. Validated against the C implementation by
tests/test_cemp_stream_vectors.py.
"""
from __future__ import annotations

import struct
import threading
import time

# ── frame classes ────────────────────────────────────────────────────────────
FRAME_OPEN = 0x10
FRAME_DATA = 0x11
FRAME_ACK = 0x12
FRAME_CLOSE = 0x13
FRAME_CANCEL = 0x14

OP_STREAM = 0x07          # new bridge op: stream transport

STREAM_VERSION = 0x01
ACK_WINDOW = 32

MAX_BYTES = 16 * 1024
MAX_FRAGS = (MAX_BYTES // 16) + 1
ACK_EVERY = 8
TIMEOUT_S = 30.0


def crc32(data: bytes) -> int:
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def parse_open(f: bytes):
    if len(f) != 17 or f[1] != STREAM_VERSION:
        return None
    sid = struct.unpack_from("<I", f, 2)[0]
    otype = f[6]
    total = struct.unpack_from("<I", f, 7)[0]
    fsz = struct.unpack_from("<H", f, 11)[0]
    ocrc = struct.unpack_from("<I", f, 13)[0]
    if sid == 0 or total == 0 or total > MAX_BYTES:
        return None
    if fsz < 16 or fsz > 255:
        return None
    nfrag = (total + fsz - 1) // fsz
    if nfrag == 0 or nfrag > MAX_FRAGS:
        return None
    return sid, otype, total, fsz, ocrc, nfrag


def build_ack(sid: int, base: int, bitmap: int) -> bytes:
    return bytes([FRAME_ACK]) + struct.pack("<I", sid) + struct.pack("<H", base) + struct.pack("<I", bitmap)


def build_close(sid: int) -> bytes:
    return bytes([FRAME_CLOSE]) + struct.pack("<I", sid)


def build_open(sid: int, otype: int, total: int, fsz: int, ocrc: int) -> bytes:
    return (bytes([FRAME_OPEN, STREAM_VERSION]) + struct.pack("<I", sid)
            + bytes([otype]) + struct.pack("<I", total)
            + struct.pack("<H", fsz) + struct.pack("<I", ocrc))


def build_data(sid: int, idx: int, payload: bytes) -> bytes:
    hdr = (bytes([FRAME_DATA]) + struct.pack("<I", sid)
           + struct.pack("<H", idx) + struct.pack("<H", len(payload)))
    body = hdr + payload
    return body + struct.pack("<H", crc16(body))


def encode_stream(sid: int, otype: int, data: bytes, fsz: int):
    """Gateway-side encoder: OPEN + one DATA per fragment.

    Mirror of the C `cemp_build_open`/`cemp_build_data` and the device's
    vendored cemp_stream.c, so the deck reassembles a gateway-initiated stream
    exactly as it sends one.
    """
    if not data or len(data) > MAX_BYTES:
        raise ValueError("encode_stream: bad data length")
    if fsz < 16 or fsz > 255:
        raise ValueError("encode_stream: bad fragment size")
    nfrag = (len(data) + fsz - 1) // fsz
    frames = [build_open(sid, otype, len(data), fsz, crc32(data))]
    for i in range(nfrag):
        off = i * fsz
        frames.append(build_data(sid, i, data[off:off + fsz]))
    return frames, nfrag


class Stream:
    def __init__(self, sid, otype, total, fsz, ocrc, nfrag):
        self.sid = sid
        self.otype = otype
        self.total = total
        self.fsz = fsz
        self.ocrc = ocrc
        self.nfrag = nfrag
        self.buf = bytearray(total)
        self.have = [False] * nfrag
        self.received = 0
        self.since_ack = 0
        self.last = time.time()


class StreamReceiver:
    """One instance per gateway. Thread-safe via a lock around handle()."""

    def __init__(self, log=print, send_downlink=None):
        self.streams: dict[int, Stream] = {}
        self.lock = threading.Lock()
        self.log = log
        self.send_downlink = send_downlink   # callable(frame_bytes) -> bool
        self.completed = []
        # sid -> (final_ack, close, when) for a short grace period after the
        # object completes, so a late-polling device still gets told "done".
        self.recent_done: dict[int, tuple[bytes, bytes, float]] = {}
        # Pending downlink frames queued until the device polls (it is
        # half-duplex: it cannot hear an ACK sent while it is mid-transmit).
        self.pending: list[bytes] = []

    def _ack_for(self, s: Stream, idx: int) -> bytes:
        # Cumulative: always advertise the whole window at and below the highest
        # received fragment, so the sender can slide its window on the next poll.
        high = max((i for i, h in enumerate(s.have) if h), default=idx)
        base = (high // ACK_WINDOW) * ACK_WINDOW
        bitmap = 0
        for k in range(ACK_WINDOW):
            fi = base + k
            if fi < s.nfrag and s.have[fi]:
                bitmap |= (1 << k)
        return build_ack(s.sid, base, bitmap)

    def _highest_received_window(self, s: Stream) -> bytes:
        """ACK the window of the highest contiguous-or-not received fragment,
        cumulatively, so the sender can advance."""
        recv = [i for i, h in enumerate(s.have) if h]
        if not recv:
            return build_ack(s.sid, 0, 0)
        high = max(recv)
        base = (high // ACK_WINDOW) * ACK_WINDOW
        bitmap = 0
        for k in range(ACK_WINDOW):
            fi = base + k
            if fi < s.nfrag and s.have[fi]:
                bitmap |= (1 << k)
        return build_ack(s.sid, base, bitmap)

    def handle(self, frame: bytes) -> str:
        """Feed one cemp_stream frame. Returns a short status string."""
        if not frame:
            return "empty"
        with self.lock:
            cls = frame[0]
            if cls == FRAME_OPEN:
                p = parse_open(frame)
                if p is None:
                    return "bad-open"
                sid, otype, total, fsz, ocrc, nfrag = p
                # The device is the sole sender and always starts a new object
                # with a fresh OPEN. Any existing stream for this sid is stale
                # (device restarted); start clean so a reboot can't inherit the
                # previous run's fragments.
                if sid in self.streams:
                    self.log(f"[stream] OPEN sid={sid} re-OPEN -> resetting stale stream")
                    del self.streams[sid]
                self.recent_done.pop(sid, None)
                self.streams[sid] = Stream(sid, otype, total, fsz, ocrc, nfrag)
                self.log(f"[stream] OPEN id={sid} type=0x{otype:02x} total={total} "
                         f"frag={fsz} nfrag={nfrag} crc={ocrc:08x}")
                return "open"

            if cls == FRAME_DATA:
                if len(frame) < 11:
                    return "bad-data"
                sid = struct.unpack_from("<I", frame, 1)[0]
                idx = struct.unpack_from("<H", frame, 5)[0]
                plen = struct.unpack_from("<H", frame, 7)[0]
                if len(frame) != 11 + plen:
                    return "bad-data-len"
                crc = struct.unpack_from("<H", frame, 9 + plen)[0]
                if crc16(frame[:9 + plen]) != crc:
                    return "data-crc"
                s = self.streams.get(sid)
                if s is None:
                    return "data-no-stream"
                if idx >= s.nfrag:
                    return "data-index"
                s.last = time.time()
                off = idx * s.fsz
                payload = frame[9:9 + plen]
                if s.have[idx]:
                    # idempotent + re-ACK
                    if bytes(s.buf[off:off + plen]) != payload:
                        return "data-conflict"
                    self._emit(self._ack_for(s, idx))
                    return "data-dup"
                expect = min(s.fsz, s.total - off)
                if plen != expect:
                    return "data-plen"
                s.buf[off:off + plen] = payload
                s.have[idx] = True
                s.received += 1
                s.since_ack += 1
                self.log(f"[stream] data sid={sid} idx={idx} have={s.received}/{s.nfrag}")

                status = "data"
                if s.since_ack >= ACK_EVERY or s.received == s.nfrag:
                    self._emit(self._ack_for(s, idx))
                    s.since_ack = 0
                    status = "data-ack"

                if s.received == s.nfrag:
                    if crc32(bytes(s.buf)) != s.ocrc:
                        self.log(f"[stream] id={sid} OBJECT CRC MISMATCH")
                        del self.streams[sid]
                        return "object-crc"
                    self.log(f"[stream] id={sid} OBJECT COMPLETE {s.total} B "
                             f"type=0x{s.otype:02x} crc=OK")
                    self.completed.append((sid, bytes(s.buf)))
                    # Latch the terminal ACK + CLOSE so a late poll still learns
                    # the stream finished even after we drop the live state.
                    final_ack = self._highest_received_window(s)
                    close = build_close(sid)
                    self.pending.append(final_ack)
                    self.pending.append(close)
                    self.recent_done[sid] = (final_ack, close, time.time())
                    del self.streams[sid]
                    return "object-complete"
                return status

            if cls == FRAME_CANCEL:
                if len(frame) == 6:
                    sid = struct.unpack_from("<I", frame, 1)[0]
                    self.streams.pop(sid, None)
                    return "cancel"
                return "bad-cancel"

            return f"ignored-0x{cls:02x}"

    def _emit(self, frame: bytes):
        """Queue a downlink frame until the device polls (do not transmit now)."""
        self.pending.append(frame)
        self.log(f"[stream] queued downlink {frame.hex()} ({len(self.pending)} pending)")

    def flush_pending(self) -> int:
        """Device is listening now: ACK current progress for every in-progress
        stream, then transmit all queued frames. This breaks the window/cadence
        deadlock — the device fills its window and can only learn progress when
        it polls, so a poll must always answer with the current cumulative
        bitmap for the highest window it has data in.
        Returns the number of frames flushed."""
        DONE_GRACE_S = 20.0
        now = time.time()
        with self.lock:
            # Re-answer recently completed streams so a late poll still learns
            # the final window + CLOSE.
            self.recent_done = {
                sid: v for sid, v in self.recent_done.items()
                if now - v[2] < DONE_GRACE_S
            }
            for s in list(self.streams.values()):
                if not any(s.have):
                    continue
                ack = self._highest_received_window(s)
                self.log(f"[stream] flush sid={s.sid} have={s.received}/{s.nfrag} -> {ack.hex()}")
                self.pending.append(ack)
            for sid, (fack, close, _) in self.recent_done.items():
                self.pending.append(fack)
                self.pending.append(close)
            # Collapse duplicates / stale frames: keep only the newest ACK per sid.
            dedup: dict[int, bytes] = {}
            for f in self.pending:
                if f and f[0] == FRAME_ACK and len(f) >= 11:
                    sid = struct.unpack_from("<I", f, 2)[0]
                    dedup[sid] = f
                else:
                    dedup[id(f)] = f  # non-ACK frames kept as-is
            frames = list(dedup.values())
            self.pending.clear()
        for f in frames:
            self.log(f"[stream] -> downlink {f.hex()}")
            if self.send_downlink is not None:
                try:
                    self.send_downlink(f)
                except Exception as e:  # noqa: BLE001
                    self.log(f"[stream] downlink send failed: {e}")
        return len(frames)

    def expire(self):
        now = time.time()
        with self.lock:
            dead = [sid for sid, s in self.streams.items() if now - s.last > TIMEOUT_S]
            for sid in dead:
                self.log(f"[stream] id={sid} timed out")
                del self.streams[sid]
        return len(dead)
