# ckb-lora-gateway

**CKB Light Client + LoRa Gateway on SenseCAP M1 (Raspberry Pi 4 + SX1302)**

A CKB blockchain gateway that combines:
- **ckb-light-client** — syncs CKB headers from a full node (no 200GB chain required)
- **sx1302_hal** — drives the SX1302 8-channel LoRa concentrator inside the SenseCAP M1
- **gateway bridge** — translates LoRa queries from field devices (T-Deck, T-QT C6, etc.) to CKB RPC calls and back

## What it does

Field devices (ESP32-based, LoRa-equipped) can:
- Query current block height
- Check address balance
- Submit transactions

All without WiFi — just LoRa range (~2–5km line of sight).

## Architecture

```
[Field Device] ──LoRa──▶ [SenseCAP M1 / Pi4]
                              SX1302 concentrator (8ch)
                              ckb-light-client (synced to ckbnode)
                              gateway bridge (Python/Node)
                         ──WiFi/LAN──▶ [ckbnode full node]
```

## Hardware

- **Gateway**: SenseCAP M1 (Raspberry Pi 4 + SX1302 LoRa HAT)
  - Repurposed from Helium mining
  - Raspbian Lite 64-bit (SD card swap from stock SenseCAP firmware)
  - SX1302 on SPI — 8 simultaneous LoRa channels (AU915)
- **Field devices**: T-Deck (ESP32-S3 + SX1262), T-QT C6 (ESP32-C6 + external LoRa)

## LoRa Protocol

Simple text protocol over LoRa:

| Request | Response |
|---------|----------|
| `CKBHDR?` | `CKBHDR:<block_number>` |
| `CKBBAL?<address>` | `CKBBAL:<shannon_amount>` |
| `CKBTX?<raw_tx_hex>` | `CKBTX:OK:<txhash>` or `CKBTX:ERR:<msg>` |

## Setup

See [docs/setup.md](docs/setup.md) for SD swap, sx1302_hal install, and ckb-light-client Docker setup.

## Status

🚧 In development — SD swap and initial setup in progress.

## Related

- [ckb-light-esp](https://github.com/toastmanAu/ckb-light-esp) — ESP32 CKB light client (field devices)
- [ckb-node-dashboard](https://github.com/toastmanAu/ckb-node-dashboard) — CKB full node dashboard
