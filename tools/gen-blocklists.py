#!/usr/bin/env python3
"""Regenerate the blocklists from PROXYWARE_DOMAINS. Run after editing that set.

    python3 tools/gen-blocklists.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import exitcheck as E  # noqa: E402

doms = sorted(E.PROXYWARE_DOMAINS)
root = os.path.join(os.path.dirname(__file__), "..")

header = f"""! Title: exitcheck proxyware blocklist
! Description: Control/telemetry endpoints for residential-proxy and proxyware SDKs
!   (Bright Data, Hola, Castar, Honeygain, IPRoyal, PacketStream and friends).
!   These are what a Smart TV or phone app contacts when it is being used as
!   someone else's exit node. Blocking them breaks the relay, not the app.
! Generated: {time.strftime('%Y-%m-%d')} from exitcheck PROXYWARE_DOMAINS ({len(doms)} entries)
! Syntax: Adblock-style. Works in AdGuard Home and Pi-hole v6 adlists.
!   Each rule blocks the domain AND all its subdomains.
!
"""

out = {
    "blocklist.txt": header + "\n".join(f"||{d}^" for d in doms) + "\n",
    "blocklist-plain.txt": "\n".join(doms) + "\n",
    "blocklist-pihole-regex.txt":
        "\n".join(r"(\.|^)" + d.replace(".", r"\.") + "$" for d in doms) + "\n",
}
for name, body in out.items():
    with open(os.path.join(root, name), "w") as f:
        f.write(body)
    print(f"{name:30} {len(doms)} entries")
