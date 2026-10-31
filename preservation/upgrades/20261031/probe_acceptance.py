"""Check each real node separately so group-wide deadlines cannot mask an untested node."""
import argparse
import json
import re
import sys
import time

from ssh_ops import HERE, PRIVATE

sys.path.insert(0, str(HERE.parent / "update-20261011/honk-doona"))
import honk_api as api

POLL_TIMEOUT = 45
POLL_INTERVAL = 1
PROTOCOLS = ("vless", "tuic", "hysteria2")


def probe(token, node, kind):
    body = {"target": {"type": "node", "node_id": node["id"]}, "kind": kind,
            "transport": ["udp" if kind == "dns" else "tcp"],
            "ip_version": "ipv4", "warmth": "cold"}
    operation, _ = api.request("/api/v1/probes", method="POST", body=body, token=token)
    deadline = time.monotonic() + POLL_TIMEOUT
    while time.monotonic() < deadline:
        result, _ = api.request(operation["href"], token=token)
        if result["status"] not in {"queued", "running"}:
            return result
        time.sleep(POLL_INTERVAL)
    raise TimeoutError("Node probe did not complete")


def verify_node(context, node):
    token, output = context
    for kind in ("http", "dns"):
        result = probe(token, node, kind)
        path = output / (node["protocol"] + "-" + kind + ".json")
        path.write_text(json.dumps(result, indent=2))
        rows = (result.get("result") or {}).get("results", [])
        ok = result["status"] == "succeeded" and len(rows) == 1
        ok = ok and rows[0]["state"] == "healthy" and rows[0]["error"] is None
        print(json.dumps({"protocol": node["protocol"], "kind": kind, "healthy": ok,
                          "latency_ms": rows[0].get("latency_ms") if rows else None}), flush=True)
        if not ok:
            raise RuntimeError("Node probe failed; private operation evidence retained")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("label")
    label = parser.parse_args().label
    if not re.fullmatch(r"[a-z0-9-]+", label):
        raise ValueError("Invalid evidence label")
    output = PRIVATE / label
    output.mkdir(exist_ok=False)
    token = api.authenticate()
    try:
        records, _ = api.request("/api/v1/nodes", token=token)
        for protocol in PROTOCOLS:
            matches = [n for n in records["nodes"] if n["protocol"] == protocol]
            if len(matches) != 1:
                raise ValueError("Expected exactly one existing node for " + protocol)
            verify_node((token, output), matches[0])
        print("THREE_NODES_HTTP_AND_UDP_DNS_PASS")
    finally:
        api.logout(token)


if __name__ == "__main__":
    main()
