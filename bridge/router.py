#!/usr/bin/env python3
"""
CKB-LoRa onward router
======================
Consumes decoded CKB-LoRa frames from MQTT (`ckblora/decoded`, published by
bridge.py) and routes them onward:

  * keeps a live per-node sighting table (persisted to nodes.json)
  * serves it over HTTP  ->  http://<host>:8099/         (HTML)
                             http://<host>:8099/api/nodes (JSON)
  * optionally POSTs every frame to a webhook  (env: CKBLORA_WEBHOOK)

This is the "next hop" after the raw-frame decode. Point CKBLORA_WEBHOOK at a
dashboard/ingest/CKB-side handler to fan frames further.

Run:  ~/ckb-lora-bridge/venv/bin/python ~/ckb-lora-bridge/router.py
"""
import json
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import paho.mqtt.client as mqtt

BROKER = os.environ.get("CKBLORA_BROKER", "localhost")
PORT = int(os.environ.get("CKBLORA_BROKER_PORT", "1883"))
SUB_TOPIC = os.environ.get("CKBLORA_SUB_TOPIC", "ckblora/decoded")
HTTP_PORT = int(os.environ.get("CKBLORA_HTTP_PORT", "8099"))
WEBHOOK = os.environ.get("CKBLORA_WEBHOOK", "").strip()
STATE = os.path.expanduser("~/ckb-lora-bridge/nodes.json")

_lock = threading.Lock()
_nodes = {}


def _save():
    try:
        tmp = STATE + ".tmp"
        with open(tmp, "w") as fp:
            json.dump({"updated": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "nodes": _nodes}, fp)
        os.replace(tmp, STATE)
    except Exception as e:  # noqa: BLE001
        print("[router] state save error:", e, flush=True)


def _ingest(rec):
    name = rec.get("name") or "?"
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with _lock:
        n = _nodes.get(name)
        if n is None:
            n = {"name": name, "first_seen": now, "count": 0}
            _nodes[name] = n
            print(f"[router] NEW node: {name}", flush=True)
        n["last_seen"] = now
        n["block"] = rec.get("block")
        n["rssi"] = rec.get("rssi")
        n["snr"] = rec.get("snr")
        n["gatewayId"] = rec.get("gatewayId")
        n["count"] = n.get("count", 0) + 1
        snap = dict(n)
        _save()
    if WEBHOOK:
        threading.Thread(target=_forward, args=(rec,), daemon=True).start()
    return snap


def _forward(rec):
    try:
        data = json.dumps(rec).encode()
        req = urllib.request.Request(WEBHOOK, data=data,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as e:  # noqa: BLE001
        print("[router] webhook error:", e, flush=True)


# ------------------------------------------------------------------ MQTT
def on_connect(client, _ud, _flags, rc, _props=None):
    print(f"[router] mqtt connected rc={rc}; subscribing {SUB_TOPIC}", flush=True)
    client.subscribe(SUB_TOPIC, 0)


def on_message(_client, _ud, msg):
    try:
        rec = json.loads(msg.payload.decode())
    except Exception:
        return
    snap = _ingest(rec)
    print(f"[router] {snap['name']} block={snap.get('block')} rssi={snap.get('rssi')} "
          f"snr={snap.get('snr')} count={snap['count']}", flush=True)


def mqtt_thread():
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    c.on_connect = on_connect
    c.on_message = on_message
    c.reconnect_delay_set(1, 30)
    c.connect(BROKER, PORT, 60)
    c.loop_forever()


# ------------------------------------------------------------------ HTTP
PAGE = """<!doctype html><html><head><meta charset=utf-8>
<title>CKB-LoRa nodes</title>
<meta http-equiv=refresh content=5>
<style>body{{font:14px monospace;background:#111;color:#ddd;padding:16px}}
h1{{font-size:16px;color:#0ff}}table{{border-collapse:collapse}}
td,th{{padding:4px 12px;border-bottom:1px solid #333;text-align:left}}
th{{color:#0ff}}</style></head><body>
<h1>CKB-LoRa node sightings</h1>
<p>{updated}</p>
<table><tr><th>name</th><th>block</th><th>rssi</th><th>snr</th><th>count</th><th>last seen</th><th>gateway</th></tr>
{rows}
</table></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_a):
        pass

    def do_GET(self):
        if self.path.startswith("/api/nodes"):
            with _lock:
                body = json.dumps({"updated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                   "nodes": list(_nodes.values())}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        with _lock:
            rows = "".join(
                f"<tr><td>{n['name']}</td><td>{n.get('block')}</td><td>{n.get('rssi')}</td>"
                f"<td>{n.get('snr')}</td><td>{n.get('count')}</td><td>{n.get('last_seen')}</td>"
                f"<td>{n.get('gatewayId')}</td></tr>" for n in _nodes.values()
            )
        html = PAGE.format(updated=time.strftime("%Y-%m-%dT%H:%M:%S%z"), rows=rows).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)


def main():
    if os.path.exists(STATE):
        try:
            _nodes.update(json.load(open(STATE)).get("nodes", {}))
        except Exception:
            pass
    threading.Thread(target=mqtt_thread, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    print(f"[router] HTTP on :{HTTP_PORT}  webhook={'set' if WEBHOOK else 'none'}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
