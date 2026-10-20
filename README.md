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
git clone https://github.com/navotvolkgroundup/exitcheck && cd exitcheck
python3 exitcheck.py scan --sweep
```

Or install it:

```bash
pipx install git+https://github.com/navotvolkgroundup/exitcheck
exitcheck scan --sweep
```

`scan` needs no router, no config and no account. It works on any network.

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

### 4. `tv` — what is actually installed on the TV

```bash
exitcheck tv 192.168.1.25          # TV must be switched ON
```

The network cannot see which apps a TV has installed, and that is exactly where
the SDKs live. This reads the app list over the TV's own control API (webOS
SSAP, Tizen remote channel) and flags apps whose **publisher** has a documented
proxy-monetisation record — PlayWorks, CloudTV, Longvision, Bright Data, Castar,
Massive, Honeygain/Oxylabs.

First run shows a pairing prompt on the TV; accept it with the remote and the
key is cached. Exit code `2` if anything is flagged.

A flag identifies the **publisher**, not the build on your TV, and is not
evidence the device is relaying — confirm that with `scan` and the upload
ratios in `router`. Matching is on vendor and app ID only, never the title, so
an app called "Massive Attack Radio" is not the Massive SDK.

There is deliberately **no unauthenticated fallback** for Tizen. The per-app
status endpoint can only confirm IDs you already know, and published ID lists
cover mainstream streaming apps rather than the small-publisher games that
carry the SDKs — a check that cannot see the risky category would only
manufacture false reassurance.

### 5. `monitor` — live per-client bandwidth

```bash
python3 exitcheck.py monitor --duration 300
```

Per-client up/down rates against the WAN total, so you can see who is actually
using the line right now.

## Blocklists

`blocklist.txt` is generated from `PROXYWARE_DOMAINS` and blocks the control
endpoints these SDKs call home to. Blocking them breaks the relay, not the app.

| file | for |
|---|---|
| `blocklist.txt` | AdGuard Home, Pi-hole v6 (Adblock syntax, covers subdomains) |
| `blocklist-plain.txt` | NextDNS / Control D denylist (bare domains, paste in) |
| `blocklist-pihole-regex.txt` | Pi-hole v5 regex table |

Regenerate after editing `PROXYWARE_DOMAINS`:

```bash
python3 tools/gen-blocklists.py
```

CI fails if the lists drift out of sync with the source set.

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

`scan` and `tv` need no router at all. `router`, `log` and `monitor` use a
backend, and backends support *different subsets* — commands say so and carry
on rather than failing.

| backend | auth | status | gives you |
|---|---|---|---|
| `sagemcom` | yes | **verified on hardware** (F@st 5657 GPON) | everything: config, per-client counters, logs |
| `upnp` | **no** | **verified on hardware** | WAN IP + port mappings, on almost any router |
| `openwrt` | yes | from vendor docs, **untested** | DHCP leases, WAN address |
| `fritzbox` | yes | from vendor docs, **untested** | host list, WAN address (TR-064) |
| `asuswrt` | yes | from vendor docs, **untested** | client list, WAN link |
| `mikrotik` | yes | from vendor docs, **untested** | DHCP leases, addresses (RouterOS v7 REST) |

```bash
exitcheck --list-backends
```

**"Untested" is meant literally.** Those four are written from published vendor
documentation and have never been run against the real device — the author owns
one router. The tool prints a warning when you use one. If you run one
successfully, say so in an issue and it gets promoted; if it breaks, that is a
bug worth reporting, not a surprise.

**Start with `upnp` if your router is not listed.** It is a standard protocol,
needs no credentials, and an unexpected port mapping is one of the few
router-level findings that actually matters — UPnP is how malware adds one.

Backends are autodetected by default. Detection tries the vendor backends first
and falls back to UPnP, which answers almost everywhere but exposes far less.

## Credentials

Put them in a file, not your shell history:

```bash
cp .env.example .env     # .env is git-ignored
exitcheck router
```

```ini
EXITCHECK_ROUTER=192.168.1.1
EXITCHECK_TYPE=auto
EXITCHECK_USER=admin
EXITCHECK_PASSWORD=secret
```

Read from `--env-file`, then `./.env`, then `~/.exitcheck.env`. Real environment
variables always win over the file. With no password anywhere you are prompted;
`--password` exists but puts the secret in your shell history and `ps` output.

Adding a backend is one class with `hosts()`, `config()`, `clients()`,
`counters()` and `fetch_log()` — implement what the device exposes and let the
rest raise `Unsupported`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Tests

```bash
python3 test_exitcheck.py
```

No framework. Covers the probe decision table (including the `200 OK` false
positive), beacon detection, domain matching, log parsing and the ratio heuristic.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The two things that help most are
**new proxyware domains** (with evidence) and **router backends** — `scan` works
everywhere, but `router`, `log` and `monitor` currently only speak Sagemcom.

## Scope

Scan only networks you own or are authorised to test. Port scanning and proxy
probing other people's equipment is hostile and in many places illegal.

This is a diagnostic: it reads, probes and reports. It does not change your
router's configuration.

MIT.
