# Current implementation (live on the SenseCAP M1)

_Status as of 2026-09-20. Supersedes the ASCII protocol in `gateway.py`, which was
the initial March skeleton._

## Chain

```
LilyGO T-Deck (SX1262)
   │  raw LoRa frames, AU915 sub-band 2 (uplink 916.8 MHz / downlink 923.3 MHz,
   │  SF9 BW125, private sync word 0x12)
   ▼
SenseCAP M1 = RPi4 + WM1302/SX1302 concentrator   (192.168.68.74)
   │  UDP 1700 (Semtech packet forwarder protocol)
   ▼
lora_pkt_fwd ──▶ ChirpStack gateway-bridge (docker, MQTT 1883, protobuf)
   ▼
ckb-lora-bridge  (bridge.py)   decode raw frames → JSONL + republish MQTT "ckblora/decoded"
   ├── ckb-lora-ckb-bridge (ckb_bridge.py)  talks CKB RPC, answers device requests
   └── ckb-lora-router     (router.py)       node sighting table, HTTP :8099
```

## Services on the M1

| unit | file | role |
|------|------|------|
| `lora_pkt_fwd` | — | SX1302 packet forwarder (config: `config/global_conf_au915.json`) |
| `ckb-lora-bridge` | `bridge/bridge.py` | decode raw CKB-LoRa frames from MQTT |
| `ckb-lora-ckb-bridge` | `bridge/ckb_bridge.py` | binary req/resp bridge to CKB RPC |
| `ckb-lora-router` | `bridge/router.py` | HTTP `:8099` (`/`, `/api/nodes`) + optional webhook |
| docker compose | — | ChirpStack (gateway-bridge / postgres / redis / mosquitto) |

## Wire protocol (binary, ckb_bridge.py)

```
uplink   [0xCB][0x02][req_id][op][body ...]        device -> gateway
downlink [0xCB][0x03][req_id][status][body ...]    gateway -> device
```

| op | name | request body | reply body |
|----|------|--------------|------------|
| 0x01 | PING | — | — |
| 0x02 | BAL  | lock (code_hash 32 \| hash_type 1 \| args_len 1 \| args) | capacity u64 LE |
| 0x03 | TIP  | — | block number u32 LE |
| 0x04 | SEND_REQ / 0x05 WITNESS | (tx relay, in progress) | — |
| 0x06 | CELLS | lock (as BAL) | outpoint tx_hash 32 \| index u32 LE \| capacity u64 LE |

**0x06 CELLS** returns the wallet's *largest plain CKB cell*, so the deck has a UTXO
to construct a transaction from. Verified live: `TESTKEY1 → 0x17863ff1…:1`, 100,000 CKB.

## Trust model

Field devices hold the keys. The gateway is **broadcast-only** — it never sees
private keys and cannot construct transactions on the device's behalf. The T-Deck
builds and signs the transaction on-device (vendored CKB-ESP32 secp256k1/blake2b
signer) and uploads it in fragments for the gateway to relay.

## Deploy

```bash
scp bridge/*.py phill@192.168.68.74:~/ckb-lora-bridge/
ssh phill@192.168.68.74 'sudo systemctl restart ckb-lora-ckb-bridge ckb-lora-bridge ckb-lora-router'
```
