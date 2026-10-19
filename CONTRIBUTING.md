# Contributing

Two kinds of contribution matter most here.

## 1. Proxyware domains

`PROXYWARE_DOMAINS` in `exitcheck.py` is the part of this project that goes stale
fastest. New SDKs appear, endpoints move.

Open an issue with the **Add a proxyware domain** template, or send a PR:

1. Add the registrable domain to `PROXYWARE_DOMAINS` (subdomains are matched
   automatically — add `brightdata.com`, not `tm-sdk.brightdata.com`).
2. Regenerate the blocklists: `python3 tools/gen-blocklists.py`
3. Commit both. CI fails if they drift out of sync.

**Evidence is required.** Vendor documentation, an SDK teardown, a published
write-up, or your own capture. Please do not copy entries across from other
blocklists without checking them — a short list people can trust is worth more
than a long one they can't.

Blocking an entry should break the *relaying*, not the app. Shared CDNs and
general app backends do not belong here.

## 2. Router backends

`scan` works on any network. `router`, `log` and `monitor` need a backend,
and only Sagemcom exists today because that is what the author owns.

A backend is one class with five methods:

| method | returns |
|---|---|
| `hosts()` | `[{mac, ip, name, active, iface}]` |
| `config()` | dict with `dns_servers`, `port_forwards`, `remote_access`, `firewall`, `upnp`, `firmware`, `model`, `wan_ip` |
| `clients()` | `[(mac, ap)]` for associated wifi clients |
| `counters(targets)` | `{mac: (down_bytes, up_bytes)}` plus `"WAN"` |
| `fetch_log()` | the router's log as text, or `None` |

Then add it to `ROUTERS`. Copy `Sagemcom` and work from there.

**Mind the direction convention.** Access-point stats are usually from the AP's
point of view, so "bytes sent" is AP→client, which is the client's *download*.
The WAN interface is the other way round. Getting this backwards inverts every
conclusion the tool draws, and it will look plausible while doing it.

If your router's log uses a different line format, `parse_log()` needs a hook —
open an issue with a few sample lines (redact your domains).

## Tests

```bash
python3 test_exitcheck.py
```

No framework, no fixtures, no network. It stands up fake servers on localhost
and asserts the probe's decision table, including the false positive that
motivated the design: a service answering `200 OK` to `CONNECT` without being a
proxy. **If you touch `probe_proxy`, that test is the contract.** `RELAY` must
only ever be returned on positive proof that traffic was forwarded.

## Scope

This is a diagnostic. It reads, probes and reports — it does not change your
router's configuration, and it should stay that way. A tool people point at
their own network needs to be boring and predictable.

Keep it dependency-free. Standard library only.
