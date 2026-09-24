
# ── PHASE 2: send path (deck signs, gateway broadcasts) ───────────────────────
#
# OP_SEND_REQ  body = from_args(20) + to_args(20) + amount_u64_le  (48 B)
#    -> pick plain cells from `from`, build unsigned tx, compute sighash,
#       stash pending tx (both molecule parts AND RPC JSON), respond sighash(32).
# OP_WITNESS   body = sig65 (64-byte compact sig + 1 flags)
#    -> inject witness, broadcast, respond txhash(32).
#
# KEYS NEVER LEAVE THE DEVICE: the gateway only ever receives a signature.
import time
import ckb_molecule as CKB

# rpc + send_response + log are injected by ckb_bridge at import time via wire().
rpc = None
send_response = None
log = None


def wire(_rpc, _send_response, _log):
    global rpc, send_response, log
    rpc, send_response, log = _rpc, _send_response, _log

PENDING = {}            # req_id -> dict
FEE_SHANNONS = 100000   # 0.001 CKB flat fee (testnet)

SECP_CODE_HASH_B = bytes.fromhex(
    "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8")
# secp256k1_blake160 dep_group cell dep (testnet + mainnet share this out point)
# testnet secp256k1_blake160 dep_group cell dep (index 0)
SECP_DEP = ("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37", 0)


def _plain_cells(args_hex, limit=0x40):
    sk = {"script": {"code_hash": "0x" + SECP_CODE_HASH_B.hex(),
                     "hash_type": "type", "args": args_hex},
          "script_type": "lock"}
    res = rpc("get_cells", [sk, "asc", hex(limit)])
    out = []
    for c in res.get("objects", []):
        if c.get("output_data", "0x") not in ("0x", "", None):
            continue
        out.append((c["out_point"]["tx_hash"], int(c["out_point"]["index"], 16),
                    int(c["output"]["capacity"], 16)))
    return out


def handle_send_req(req_id, body):
    if len(body) < 48:
        log(f"SEND_REQ req={req_id} bad body ({len(body)}B)")
        send_response(req_id, 4)
        return
    from_args = body[0:20]
    to_args = body[20:40]
    amount = int.from_bytes(body[40:48], "little")

    cells = _plain_cells("0x" + from_args.hex())
    if not cells:
        log(f"SEND_REQ req={req_id} no spendable cells for 0x{from_args.hex()}")
        send_response(req_id, 5)
        return
    cells.sort(key=lambda c: c[2], reverse=True)
    need = amount + FEE_SHANNONS
    picked, total = [], 0
    for c in cells:
        picked.append(c)
        total += c[2]
        if total >= need:
            break
    if total < need:
        log(f"SEND_REQ req={req_id} insufficient {total} < {need}")
        send_response(req_id, 5)
        return

    from_lock_m = CKB.script(SECP_CODE_HASH_B, 1, from_args)
    to_lock_m = CKB.script(SECP_CODE_HASH_B, 1, to_args)
    dep_m = CKB.out_point(bytes.fromhex(SECP_DEP[0][2:]), SECP_DEP[1]) + b"\x01"
    inputs_m = [CKB.cell_input(CKB.out_point(bytes.fromhex(t[2:]), i))
                for (t, i, _c) in picked]
    change = total - amount - FEE_SHANNONS
    outputs_m = [CKB.cell_output(amount, to_lock_m)]
    if change > 0:
        outputs_m.append(CKB.cell_output(change, from_lock_m))
    odata_m = [b""] * len(outputs_m)

    raw = CKB.raw_transaction(0, [dep_m], [], inputs_m, outputs_m, odata_m)
    tx_hash = CKB.tx_view(raw)
    # sighash: the signed witness is witness[0], a WitnessArgs placeholder whose
    # lock field is 65 zero bytes. signing_hash includes that witness.
    wiplaceholder = CKB.placeholder_witness()
    sighash = CKB.signing_hash(tx_hash, [], wiplaceholder)

    # RPC JSON twin (for send_transaction at WITNESS time)
    rpc_outputs = [{"capacity": hex(amount),
                    "lock": {"code_hash": "0x" + SECP_CODE_HASH_B.hex(),
                             "hash_type": "type", "args": "0x" + to_args.hex()},
                    "type": None}]
    if change > 0:
        rpc_outputs.append({"capacity": hex(change),
                            "lock": {"code_hash": "0x" + SECP_CODE_HASH_B.hex(),
                                     "hash_type": "type", "args": "0x" + from_args.hex()},
                            "type": None})
    rpc_inputs = [{"since": "0x0",
                   "previous_output": {"tx_hash": t, "index": hex(i)}}
                  for (t, i, _c) in picked]

    PENDING[req_id] = {
        "tx_hash": tx_hash,
        "rpc": {
            "version": "0x0",
            "cell_deps": [{"out_point": {"tx_hash": SECP_DEP[0],
                                         "index": hex(SECP_DEP[1])},
                           "dep_type": "dep_group"}],
            "header_deps": [],
            "inputs": rpc_inputs,
            "outputs": rpc_outputs,
            "outputs_data": ["0x"] * len(rpc_outputs),
        },
        "ts": time.time(),
    }
    log(f"SEND_REQ req={req_id} in={len(picked)} out={len(rpc_outputs)} "
        f"amount={amount} change={change} sighash={sighash.hex()}")
    send_response(req_id, 0, sighash)


def handle_witness(req_id, body):
    pend = PENDING.get(req_id)
    if not pend:
        log(f"WITNESS req={req_id} no pending send")
        send_response(req_id, 6)
        return
    if len(body) < 65:
        log(f"WITNESS req={req_id} sig too short ({len(body)}B)")
        send_response(req_id, 4)
        return
    sig65 = body[:65]
    tx = dict(pend["rpc"])
    tx["witnesses"] = ["0x" + CKB.real_witness(sig65).hex()]
    try:
        txh = rpc("send_transaction", [tx])
    except Exception as e:  # noqa: BLE001
        log(f"WITNESS req={req_id} broadcast FAILED: {e}")
        send_response(req_id, 7)
        return
    PENDING.pop(req_id, None)
    log(f"WITNESS req={req_id} broadcast -> {txh}")
    send_response(req_id, 0, bytes.fromhex(txh[2:]))
