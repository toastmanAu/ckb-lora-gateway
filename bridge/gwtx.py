#!/usr/bin/env python3
"""
CKB-LoRa gateway TX  (downlink injector)
========================================
Sends an over-the-air frame FROM the SenseCAP M1 concentrator (via the ChirpStack
gateway-bridge) so LoRa devices can receive downlinks.

Path:  MQTT command/down (gw.DownlinkFrame protobuf) -> gateway-bridge -> UDP ->
       Semtech packet forwarder -> SX1302/SX1250 TX.

AU915 note: the gateway's TX chain is configured for 923.3-927.5 MHz
(radio_0 tx_freq_min/max). Frames outside that range are rejected by the PF
(tx ack status = TX_FREQ). Uplink is 916.8 MHz.

Usage:
  gwtx.py --freq 923300000 --sf 7 --bw 125000 --power 20 --beacon TDECK002 42
  gwtx.py --freq 923300000 --hex cb01544445434b3030322a000000
"""
import argparse
import sys
import time

import paho.mqtt.client as mqtt

BROKER = "localhost"
PORT = 1883
EUI = "0016c001ff169916"
REGION = "au915_1"
CMD_TOPIC = f"{REGION}/gateway/{EUI}/command/down"
ACK_TOPIC = f"{REGION}/gateway/{EUI}/event/ack"


# ---- minimal protobuf writer -------------------------------------------------
def _varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _key(f, w):
    return _varint((f << 3) | w)


def _vi(f, v):                      # varint field
    return _key(f, 0) + _varint(v)


def _ld(f, b):                      # length-delimited field
    return _key(f, 2) + _varint(len(b)) + b


def build_downlink_frame(phy_payload, freq, sf, bw, cr, preamble, power, did):
    lora = _vi(1, bw) + _vi(2, sf) + _vi(5, cr) + _vi(6, preamble)
    modulation = _ld(3, lora)                                    # Modulation.lora = 3
    timing = _ld(1, b"")                                         # Timing.immediately
    tx_info = _vi(1, freq) + _vi(2, power) + _ld(3, modulation) + _ld(6, timing)
    item = _ld(1, phy_payload) + _ld(3, tx_info)                 # DownlinkFrameItem
    frame = _vi(3, did) + _ld(5, item) + _ld(7, EUI.encode())    # DownlinkFrame
    return frame


# -- persistent publisher (for long-running services) --------------------------
_pub_client = None


def _get_pub_client():
    global _pub_client
    if _pub_client is None:
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        c.connect(BROKER, PORT, 60)
        c.loop_start()
        _pub_client = c
    return _pub_client


def publish_raw(frame_bytes):
    """Publish a prebuilt gw.DownlinkFrame to the gateway command topic."""
    _get_pub_client().publish(CMD_TOPIC, frame_bytes, 0)


def decode_ack(b):
    """Pull TxAckStatus varints out of a gw.DownlinkTxAck (best-effort)."""
    out = []
    i = 0
    while i < len(b):
        k = 0
        s = 0
        while True:
            c = b[i]; i += 1; k |= (c & 0x7F) << s; s += 7
            if not (c & 0x80):
                break
        f, w = k >> 3, k & 7
        if w == 0:
            v = 0; s = 0
            while True:
                c = b[i]; i += 1; v |= (c & 0x7F) << s; s += 7
                if not (c & 0x80):
                    break
            out.append((f, v))
        elif w == 2:
            l = 0; s = 0
            while True:
                c = b[i]; i += 1; l |= (c & 0x7F) << s; s += 7
                if not (c & 0x80):
                    break
            out.append((f, b[i:i + l])); i += l
        else:
            break
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--freq", type=int, default=923300000)
    ap.add_argument("--sf", type=int, default=7)
    ap.add_argument("--bw", type=int, default=125000)
    ap.add_argument("--cr", type=int, default=1)      # 1 = 4/5
    ap.add_argument("--preamble", type=int, default=8)
    ap.add_argument("--power", type=int, default=20)
    ap.add_argument("--hex", help="raw payload hex")
    ap.add_argument("--beacon", nargs=2, metavar=("NAME", "BLOCK"),
                    help="build a 14-byte CKB-LoRa beacon")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--interval", type=float, default=1.5)
    args = ap.parse_args()

    if args.hex:
        payload = bytes.fromhex(args.hex)
    elif args.beacon:
        name = args.beacon[0][:8].ljust(8, "\x00").encode()
        block = int(args.beacon[1]) & 0xFFFFFFFF
        payload = b"\xCB\x01" + name + block.to_bytes(4, "little")
    else:
        print("need --hex or --beacon NAME BLOCK", file=sys.stderr)
        sys.exit(2)

    print(f"[gwtx] payload {payload.hex()}  freq={args.freq/1e6:.1f}MHz sf{args.sf} "
          f"bw{args.bw} cr4/{args.cr+4} power={args.power}dBm")

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    got = []

    def on_connect(c, _u, _f, rc, _p=None):
        c.subscribe(ACK_TOPIC, 0)

    def on_message(_c, _u, msg):
        fields = decode_ack(msg.payload)
        got.append(fields)
        print("[gwtx] ACK raw bytes:", msg.payload.hex())
        for f, v in fields:
            if isinstance(v, bytes):
                for f2, v2 in decode_ack(v):
                    if f2 == 1:
                        names = {0: "IGNORED", 1: "OK", 2: "TOO_LATE", 3: "TOO_EARLY",
                                 4: "COLLISION_PACKET", 5: "COLLISION_BEACON",
                                 6: "TX_FREQ", 7: "TX_POWER", 8: "GPS_UNLOCKED",
                                 9: "QUEUE_FULL", 10: "INTERNAL_ERROR",
                                 11: "DUTY_CYCLE_OVERFLOW"}
                        print(f"[gwtx]   item status: {names.get(v2, v2)}")
            elif f == 2:
                print(f"[gwtx]   downlink_id: {v}")

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER, PORT, 60)
    client.loop_start()
    time.sleep(0.5)

    for n in range(args.count):
        did = int(time.time()) & 0xFFFFFFFF
        frame = build_downlink_frame(payload, args.freq, args.sf, args.bw,
                                     args.cr, args.preamble, args.power, did)
        print(f"[gwtx] publish #{n+1} -> {CMD_TOPIC}  ({len(frame)}B)  downlink_id={did}")
        client.publish(CMD_TOPIC, frame, 0)
        time.sleep(args.interval)

    time.sleep(1.5)
    client.loop_stop()
    if not got:
        print("[gwtx] no ack seen (gateway-bridge downlink ack topic silent)")


if __name__ == "__main__":
    main()
