# exitcheck

**Is anything on your network relaying traffic for strangers?**

Residential-proxy SDKs — Bright Data, Hola, Castar and friends — ride inside free
Smart TV and mobile apps and quietly turn the device into an exit node for someone
else's web scraping. In June 2026 Spur scanned 6,038 Smart TV apps and found
**42.5% of LG webOS apps carried one**. Your TV is doing the crawling; your IP
takes the blame.

`exitcheck` looks for the three signatures that leaves behind.

- Python 3.8+, **standard library only**. No `pip install`, no dependency tree —
  which matters for a tool you point at your own network.
- One file. Read it before you run it.

```bash
git clone https://github.com/YOURNAME/exitcheck && cd exitcheck
python3 exitcheck.py scan --sweep
```

## What it checks

### 1. `scan` — does anything actually forward traffic?

Finds hosts via ARP (`--sweep` to ping first), port-scans each, then **probes every
open port** with SOCKS5, SOCKS4, HTTP absolute-URI and HTTP CONNECT.

The verdict is the point:

| | meaning |
|---|---|
| `RELAY` | **proven.** We pushed a request through and got the real remote page back. |
| `GATED` | speaks a proxy protocol correctly but refuses to forward. |
| `NONE` | not a proxy. |

`RELAY` is only ever returned on positive proof. A `200 OK` reply to `CONNECT` is
**not** proof — Amazon's Alexa stack answers exactly that on port 9080 and is not a
proxy. exitcheck always speaks *through* the tunnel and looks for a known marker
from the real remote page before accusing anything. That false positive is pinned
by a test.

```bash
python3 exitcheck.py scan --sweep              # whole /24
python3 exitcheck.py scan --host 10.0.0.25 --full   # one device, all 65535 ports
```

Exit code is `2` if a confirmed relay was found, so it drops into cron or CI.

### 2. `router` — config audit and upload ratios

```bash
python3 exitcheck.py router --router 10.0.0.1 --user admin
```

Audits the things that actually matter if a router is compromised: **DNS servers**
(rewritten DNS is the classic hijack), port forwards and DMZ, remote management,
firewall level, UPnP.

Then ranks every client by **upload/download ratio**. Exit nodes push traffic *out*;
watching pulls it *in*. A TV at 10:1 down:up is streaming. A TV at 1:1 deserves a
look.

### 3. `log` — proxyware domains and beacons

```bash
python3 exitcheck.py log vendorlog.txt
python3 exitcheck.py log --router 10.0.0.1 --save vendorlog.txt
```

Matches every queried domain against a list of known proxyware control endpoints,
then runs **beacon detection** over the timestamps: fixed-interval callbacks look
nothing like human browsing, so anything hitting the same host every *n* minutes
with low variance gets flagged with its period.

### 4. `monitor` — live per-client bandwidth

```bash
python3 exitcheck.py monitor --duration 300
```

Per-client up/down rates against the WAN total, so you can see who is actually
using the line right now.

## Honest limits

Read these before trusting a clean result.

- **A proxyware SDK dials out; it does not listen.** A clean `scan` means nothing is
  an *open relay*. It does not clear the device. The upload ratio is the better
  signal, and app-level inspection is better still.
- **Many routers log only *failed* DNS lookups.** A proxyware domain that resolves
  fine never appears in the log. Absence of evidence is weak evidence here. A
  DNS sinkhole (Pi-hole, AdGuard Home) with per-client logging is the real fix.
- **Symmetric traffic is not proof.** Video calls, P2P gaming, cloud backup and NAS
  sync all upload heavily. The ratio is a lead, never a conviction.
- **Counters reset** when a client re-associates, so totals cover an unknown window.
  Use `monitor` for a measurement with known bounds.
- Wi-Fi client stats cover Wi-Fi clients. Check your router's Ethernet counters
  separately if you have wired devices.

## Router support

`router`, `log` and `monitor` need a backend. `scan` does not and works anywhere.

| backend | status |
|---|---|
| `sagemcom` | working — tested on F@st 5657 GPON |

Adding one is a single class with `hosts()`, `config()`, `clients()`, `counters()`
and `fetch_log()`. See `Sagemcom` and add it to `ROUTERS`. PRs very welcome —
**so are additions to `PROXYWARE_DOMAINS`**, which is the part of this project with
the shortest shelf life.

Credentials come from `--password`, `$EXITCHECK_PASSWORD`, or an interactive prompt.
Nothing is written to disk except the OUI cache and any log you ask it to `--save`.

## Tests

```bash
python3 test_exitcheck.py
```

No framework. Covers the probe decision table (including the `200 OK` false
positive), beacon detection, domain matching, log parsing and the ratio heuristic.

## Scope

Scan only networks you own or are authorised to test. Port scanning and proxy
probing other people's equipment is hostile and in many places illegal.

MIT.
