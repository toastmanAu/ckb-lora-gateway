#!/usr/bin/env python3
"""
Minimal CKB transaction builder + secp256k1_blake160 sighash  (gateway side)
============================================================================
No CKB libs available in the gateway venv, so we implement just enough Molecule
encoding to build a 1-input/2-output plain-CKB transfer and compute the sighash
the device must sign.

Sighash rule (CKB, since v0.100):
  message = blake2b(  tx_hash_all
                    + (witness_len_u64_le as 8 bytes)  -- len of the witness placeholder
                    + each_input_witness_field          -- NOTE: for args-signed locks,
                    ... )                                 the first witness is the 65B sig+flags
  Actually the spec: signing_hash = blake2b(tx_hash || len(witnesses[0..n-1] concat) ||
                                            witnesses[0..n-1])  i.e. all witnesses EXCEPT
  the one being signed (last), each prefixed by its u64 length.

For a lock-args signature (secp256k1_blake160) the signed witness is the LAST
witness; the signing hash covers the tx_hash plus the *other* witnesses (here:
none, the args witness is index 0 and is the one being produced).

Reference: RFC  "CKB transaction structure" — we mirror the exact serialisation:
  RawTransaction = version(4) cell_deps Vec  header_deps Vec  inputs Vec
                   outputs Vec  outputs_data Vec
  TxView (what is hashed) = blake2b(RawTransaction serialisation)
  SigningHash = blake2b( TxView ++ len_of_witnesses_before ++ those_witnesses )
"""
import hashlib
import struct


def b2b(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32,
                          person=b"ckb-default-hash").digest()


# ── Molecule fixed/var builders ───────────────────────────────────────────────
def fixvec(items: list[bytes]) -> bytes:
    """FixVec: u32 count + concatenated fixed-size items (NO leading total_size)."""
    return struct.pack("<I", len(items)) + b"".join(items)


def dynvec(items: list[bytes]) -> bytes:
    """Molecule Table/DynVec (== pyckb.molecule.Split.encode):
        total_size(u32) | offset[0](u32) | offset[1](u32) | ... | items...
    There is NO separate count field: the count is (total_size-4)/4. total_size
    = 4 + 4*N + sum(len(items)); each offset is measured from the start of the
    size field (so the first offset = 4 + 4*N). Empty vec => just 04000000."""
    n = len(items)
    head_size = 4 + 4 * n           # size field + N offset words
    offsets = b""
    body = b""
    running = head_size
    for it in items:
        offsets += struct.pack("<I", running)
        running += len(it)
        body += it
    size = head_size + len(body)
    return struct.pack("<I", size) + offsets + body


def byte32(x: bytes) -> bytes:
    assert len(x) == 32
    return x


def bytes_field(b: bytes) -> bytes:
    """Molecule `Bytes` = u32 length + raw bytes (NOT a dynvec of one item)."""
    return u32(len(b)) + b


def u32(v): return struct.pack("<I", v)
def u64(v): return struct.pack("<Q", v)


# ── CKB structures ────────────────────────────────────────────────────────────
def out_point(tx_hash: bytes, index: int) -> bytes:
    return byte32(tx_hash) + u32(index)


def cell_input(prev: bytes, since: int = 0) -> bytes:
    # Molecule: CellInput { since: Uint64, previous_output: OutPoint }
    return struct.pack("<Q", since) + prev


def script(code_hash: bytes, hash_type: int, args: bytes) -> bytes:
    # Script is a Table { code_hash: Byte32, hash_type: Byte, args: Bytes }
    ht = {0: b"\x00", 1: b"\x01", 2: b"\x02", 3: b"\x04"}[hash_type]
    return dynvec([byte32(code_hash), ht, bytes_field(args)])


def cell_output(capacity: int, lock: bytes, type_script=None) -> bytes:
    # CellOutput Table { capacity: Uint64, lock: Script, type: Option<Script> }.
    # CKB Option<Script> encodes as EMPTY when None (no 0x00 tag), and as the
    # bare Script table when present — matches pyckb.molecule.Option.
    ts = b"" if type_script is None else type_script
    return dynvec([struct.pack("<Q", capacity), lock, ts])


# ── RawTransaction / TxView ───────────────────────────────────────────────────
def raw_transaction(version: int, cell_deps: list[bytes], header_deps: list[bytes],
                    inputs: list[bytes], outputs: list[bytes],
                    outputs_data: list[bytes]) -> bytes:
    """RawTransaction = molecule Table (Split) of 6 fields:
        [ U32 version, CellDepVec, Byte32Vec header_deps,
          CellInputVec, CellOutputVec, BytesVec outputs_data ]
    Serialised as: total_size(u32) | offset[0..5](u32) | fields...
    (matches pyckb.RawTransaction.molecule() exactly)."""
    fields = [
        u32(version),
        fixvec(cell_deps),      # CellDepVec   = Slice/FixVec (fixed 37B items)
        fixvec(header_deps),    # Byte32Vec    = Slice/FixVec (fixed 32B items)
        fixvec(inputs),         # CellInputVec = Slice/FixVec (fixed 44B items)
        dynvec(outputs),        # CellOutputVec = Scale/DynVec (variable)
        dynvec([bytes_field(d) for d in outputs_data]),   # BytesVec: wrap each as Bytes
    ]
    return dynvec(fields)


def tx_view(raw: bytes) -> bytes:
    return b2b(raw)


def signing_hash(tx_hash: bytes, witnesses_before: list[bytes],
                 signed_witness: bytes = b"") -> bytes:
    """CKB signing hash (mode 'all'), matching pyckb.Transaction.hash_sighash_all:

        b2b( tx_hash
             || u64(len(signed_witness)) || signed_witness
             || for each earlier witness w: u64(len(w)) || w )

    NOTE: the SIGNED witness itself is included (it holds the WitnessArgs
    placeholder with the 65 zero-byte lock during signing). Earlier witnesses
    are those before it. For a single-input tx, signed_witness = the placeholder
    and witnesses_before is empty. (Missed this in the first cut -> sig failed
    with error -2, 2026-09-22.)"""
    blob = struct.pack("<Q", len(signed_witness)) + signed_witness
    for w in witnesses_before:
        blob += struct.pack("<Q", len(w)) + w
    return b2b(tx_hash + blob)


# ── witness args (what gets signed for lock-args sigs) ────────────────────────
def witness_args(lock: bytes = None, input_type: bytes = None,
                 output_type: bytes = None) -> bytes:
    """WitnessArgs = Table([Option<Bytes> lock, Option<Bytes> input_type,
    Option<Bytes> output_type]). Each option encodes as EMPTY bytes when None
    (CKB's Option has no tag byte), or as a Bytes (u32 len + data) when present.
    (pyckb: Table([Custom(0)]*3) with each field = Bytes or b"".)"""
    def opt(b):
        return b"" if b is None else bytes_field(b)
    return dynvec([opt(lock), opt(input_type), opt(output_type)])


PERSONAL = b"ckb-default-hash"


def placeholder_witness() -> bytes:
    """WitnessArgs with a 65-byte zero lock (sig + flag) — used to build the
    signing hash in SEND_REQ. The device later returns the real 65B signature."""
    return witness_args(lock=bytes(65))


def real_witness(sig65: bytes) -> bytes:
    assert len(sig65) == 65
    return witness_args(lock=sig65)


# ── secp256k1 signing helpers (verify only; device signs) ─────────────────────
def blake160(data: bytes) -> bytes:
    return b2b(data)[:20]


def args_from_pubkey(pub_sec1: bytes) -> bytes:
    """blake160 of the secp256k1 compressed pubkey (33B) — the lock args."""
    return blake160(pub_sec1)
