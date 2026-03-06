#!/usr/bin/env python3
"""
gateway.py — CKB LoRa Gateway Bridge
Listens for LoRa packets from field devices via sx1302_hal UDP forwarder,
translates to CKB light client RPC calls, sends responses back over LoRa.

Protocol:
  CKBHDR?              → CKBHDR:<block_number>
  CKBBAL?<address>     → CKBBAL:<shannon_amount>
  CKBTX?<raw_tx_hex>   → CKBTX:OK:<txhash>  or  CKBTX:ERR:<reason>
"""

import socket, json, struct, time, logging, requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('ckb-lora-gw')

# ── Config ────────────────────────────────────────────────────────────────────
CKB_RPC         = "http://localhost:9000"   # ckb-light-client RPC
FORWARDER_HOST  = "127.0.0.1"              # sx1302_hal UDP forwarder
FORWARDER_PORT  = 1700                      # standard semtech UDP port
LORA_FREQ       = 916.8                     # AU915 uplink channel
LORA_SF         = 9
LORA_BW         = 125

# ── CKB RPC helpers ───────────────────────────────────────────────────────────
def ckb_rpc(method, params=[]):
    try:
        r = requests.post(CKB_RPC, json={
            "jsonrpc": "2.0", "id": 1,
            "method": method, "params": params
        }, timeout=5)
        return r.json().get("result")
    except Exception as e:
        log.error(f"RPC error {method}: {e}")
        return None

def get_tip_block():
    tip = ckb_rpc("get_tip_header")
    if tip:
        return int(tip["number"], 16)
    return None

def get_balance(address):
    # Light client: get_cells_capacity for lock script derived from address
    # Simplified — query via indexer
    result = ckb_rpc("get_cells_capacity", [{"script": {"code_hash": "0x...", "hash_type": "type", "args": address}, "script_type": "lock"}])
    if result:
        return int(result.get("capacity", "0x0"), 16)
    return None

def send_transaction(raw_tx_hex):
    result = ckb_rpc("send_transaction", [raw_tx_hex, "passthrough"])
    return result  # tx hash or None

# ── LoRa packet handling ──────────────────────────────────────────────────────
def handle_lora_payload(payload: bytes) -> str:
    """Parse request, return response string."""
    try:
        msg = payload.decode('utf-8').strip()
        log.info(f"RX: {msg}")

        if msg == "CKBHDR?":
            block = get_tip_block()
            return f"CKBHDR:{block}" if block else "CKBHDR:ERR"

        elif msg.startswith("CKBBAL?"):
            address = msg[7:]
            balance = get_balance(address)
            return f"CKBBAL:{balance}" if balance is not None else "CKBBAL:ERR"

        elif msg.startswith("CKBTX?"):
            raw_tx = msg[6:]
            txhash = send_transaction(raw_tx)
            return f"CKBTX:OK:{txhash}" if txhash else "CKBTX:ERR:rejected"

        else:
            log.warning(f"Unknown command: {msg}")
            return "ERR:UNKNOWN"

    except Exception as e:
        log.error(f"Handle error: {e}")
        return "ERR:INTERNAL"

# ── Semtech UDP protocol (sx1302_hal forwarder) ───────────────────────────────
def parse_push_data(data: bytes):
    """Extract LoRa payloads from Semtech PUSH_DATA packet."""
    if len(data) < 12: return []
    # Token: bytes 1-2, GWID: bytes 4-11, JSON: bytes 12+
    try:
        json_str = data[12:].decode('utf-8')
        obj = json.loads(json_str)
        payloads = []
        for rxpk in obj.get("rxpk", []):
            import base64
            raw = base64.b64decode(rxpk.get("data", ""))
            payloads.append((raw, rxpk))
        return payloads
    except Exception as e:
        log.error(f"Parse error: {e}")
        return []

def build_pull_resp(token: bytes, payload: str) -> bytes:
    """Build Semtech PULL_RESP packet to send downlink."""
    import base64, json as j
    txpk = {
        "imme": True,
        "freq": LORA_FREQ,
        "rfch": 0,
        "powe": 14,
        "modu": "LORA",
        "datr": f"SF{LORA_SF}BW{LORA_BW}",
        "codr": "4/5",
        "ipol": True,
        "size": len(payload),
        "data": base64.b64encode(payload.encode()).decode()
    }
    json_bytes = j.dumps({"txpk": txpk}).encode()
    # PULL_RESP: version=2, token (2 bytes), identifier=3
    return bytes([2]) + token + bytes([3]) + json_bytes

# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    log.info(f"CKB LoRa Gateway starting — RPC: {CKB_RPC}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((FORWARDER_HOST, FORWARDER_PORT))
    sock.settimeout(1.0)

    pull_addr = None   # address of the sx1302_hal forwarder (set on PULL_DATA)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) < 4: continue

            version, token_hi, token_lo, identifier = data[0], data[1], data[2], data[3]
            token = bytes([token_hi, token_lo])

            if identifier == 0:  # PUSH_DATA
                # ACK it
                sock.sendto(bytes([2, token_hi, token_lo, 1]), addr)
                # Process payloads
                for payload, rxpk in parse_push_data(data):
                    response = handle_lora_payload(payload)
                    log.info(f"TX: {response}")
                    if pull_addr:
                        resp_pkt = build_pull_resp(token, response)
                        sock.sendto(resp_pkt, pull_addr)

            elif identifier == 2:  # PULL_DATA
                pull_addr = addr
                # ACK
                sock.sendto(bytes([2, token_hi, token_lo, 4]), addr)

        except socket.timeout:
            pass
        except KeyboardInterrupt:
            log.info("Shutting down")
            break

if __name__ == "__main__":
    main()
