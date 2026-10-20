#!/usr/bin/env python3
"""
exitcheck - is anything on your network relaying traffic for strangers?

Finds residential-proxy / proxyware behaviour on your LAN: Bright Data, Hola,
Castar and friends ride inside free Smart TV and mobile apps and quietly turn
the device into an exit node. This looks for the three signatures that leaves:

  1. a listening SOCKS/HTTP relay that actually forwards
  2. DNS traffic to known proxyware control domains, including fixed-interval beacons
  3. an upload/download ratio that looks like relaying rather than watching

Stdlib only, no pip install. Scan only networks you own or are authorised to test.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import hashlib
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict

__version__ = "0.1.0"

# ---------------------------------------------------------------- known bad --

# Control/telemetry domains for consumer proxyware and residential-proxy SDKs.
# Community-maintained: PRs welcome, this list is the whole point of the project.
PROXYWARE_DOMAINS = {
    # Bright Data (formerly Luminati) and its consumer SDK, fed by Hola
    "brightdata.com", "luminati.io", "lum-superproxy.io", "superproxy.io",
    "brightsdk.com", "bright-sdk.com", "earnapp.com",
    "hola.org", "holavpn.net", "hola.net",
    # Castar SDK - the other big one found in Smart TV apps
    "castarsdk.com", "castar.io",
    # pay-per-GB consumer proxyware
    "honeygain.com", "honeygain.net", "pawns.app", "iproyal.com",
    "packetstream.io", "peer2profit.com", "peer2profit.io", "repocket.co",
    "traffmonetizer.com", "getgrass.io", "grass.io", "mysterium.network",
    "proxyrack.com", "proxyrack.net", "infatica.io", "nodemaven.com",
    # commercial residential pools whose SDKs show up embedded in apps
    "oxylabs.io", "smartproxy.com", "netnut.io", "webshare.io",
    "rayobyte.com", "soax.com", "ipidea.net", "922proxy.com", "nsocks.net",
}

# Ports worth looking at first. --full scans all 65535 instead.
PROXY_PORTS = [
    1080, 1081, 3128, 8080, 8081, 8118, 8888, 9050, 9051, 9091, 9150,
    80, 443, 22, 23, 1900, 3000, 3001, 4070, 5000, 5555, 6000, 7000,
    8000, 8008, 8009, 8443, 9090, 9999, 18181, 32768, 55442, 55443,
]

# Ports that, if open, deserve a sentence in the report regardless of verdict.
NOTABLE = {
    1080: "SOCKS proxy default port",
    1081: "SOCKS alternate",
    3128: "Squid/HTTP proxy default",
    8118: "Privoxy default",
    9050: "Tor SOCKS default",
    9150: "Tor Browser SOCKS",
    8888: "common HTTP proxy port",
    5555: "Android ADB - remote shell if unauthenticated",
    23: "Telnet",
}

# The relay oracle. We confirm RELAY by fetching this through the suspect port
# and looking for the marker, so it MUST be reachable and plain-HTTP.
# Not example.com: it is RFC 2606 reserved and some networks NXDOMAIN it, which
# silently turns every RELAY into a false negative. preflight() now checks.
# captive.apple.com is plain-HTTP by design, globally reachable, and returns a
# fixed body. The marker is the whole title tag, not the bare word "Success",
# so a local service babbling "success" cannot forge a RELAY verdict.
# Rejected: example.com (RFC 2606, NXDOMAINs on some networks) and
# neverssl.com (TCP-unreachable on at least one real ISP).
RELAY_HOST, RELAY_PORT = "captive.apple.com", 80
RELAY_MARKER = "<TITLE>Success</TITLE>"

# ------------------------------------------------------------------- output --

class Out:
    """Minimal colour/plain reporter."""
    def __init__(self, color=True):
        self.c = color and sys.stdout.isatty()

    def _w(self, code, s):
        return f"\033[{code}m{s}\033[0m" if self.c else s

    def head(self, s):   print("\n" + self._w("1", s) + "\n" + "-" * len(s))
    def bad(self, s):    print("  " + self._w("1;31", "[!] " + s))
    def warn(self, s):   print("  " + self._w("33", "[~] " + s))
    def ok(self, s):     print("  " + self._w("32", "[+] " + s))
    def info(self, s):   print("  " + s)

# ---------------------------------------------------------------- discovery --

MAC_RE = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{11,17})")

def norm_mac(mac: str) -> str:
    parts = mac.split(":")
    if len(parts) != 6:
        return mac.upper()
    return ":".join(f"{int(p, 16):02X}" for p in parts)

def is_randomized(mac: str) -> bool:
    """Locally-administered bit set - iOS/Android MAC randomisation, not a real OUI."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False

def arp_table() -> dict[str, str]:
    """{ip: MAC} from the OS ARP cache. Works on macOS and Linux."""
    try:
        out = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    hosts = {}
    for ip, mac in MAC_RE.findall(out):
        if not mac.startswith("ff:ff"):
            hosts[ip] = norm_mac(mac)
    return hosts

def ping_sweep(cidr_base: str, workers=128) -> None:
    """Ping .1-.254 to populate the ARP cache. cidr_base like '192.168.1'."""
    flag = "-W1" if sys.platform != "darwin" else "-W1000"
    def one(n):
        subprocess.run(["ping", "-c1", flag, f"{cidr_base}.{n}"],
                       capture_output=True, timeout=5)
    with cf.ThreadPoolExecutor(workers) as ex:
        list(ex.map(one, range(1, 255)))

def local_subnet() -> str | None:
    """Best-effort /24 base of the primary interface, e.g. '192.168.1'."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0].rsplit(".", 1)[0]
    except OSError:
        return None
    finally:
        s.close()

# ------------------------------------------------------------- oui registry --

OUI_CACHE = os.path.expanduser("~/.cache/exitcheck/oui.json")

def load_oui_cache() -> dict:
    try:
        with open(OUI_CACHE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}

def save_oui_cache(cache: dict) -> None:
    os.makedirs(os.path.dirname(OUI_CACHE), exist_ok=True)
    try:
        with open(OUI_CACHE, "w") as f:
            json.dump(cache, f)
    except OSError:
        pass

def vendor(mac: str, cache: dict, online=True) -> str:
    if is_randomized(mac):
        return "randomized MAC"
    pfx = mac.replace(":", "")[:6]
    if pfx in cache:
        return cache[pfx]
    if not online:
        return "?"
    try:
        with urllib.request.urlopen(f"https://api.maclookup.app/v2/macs/{pfx}", timeout=8) as r:
            name = (json.loads(r.read()).get("company") or "?").strip()
    except Exception:
        return "?"
    cache[pfx] = name
    return name

# -------------------------------------------------------------- port scanner --

def scan_ports(ip: str, ports, timeout=0.7, workers=400) -> list[int]:
    def chk(p):
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((ip, p))
            return p
        except OSError:
            return None
        finally:
            s.close()
    with cf.ThreadPoolExecutor(workers) as ex:
        return sorted(p for p in ex.map(chk, ports) if p)

# -------------------------------------------------------------- proxy probe --
# Verdicts:
#   RELAY  - confirmed: we pushed a request through it and got the real remote page back
#   GATED  - speaks a proxy protocol correctly but refuses to forward (auth/whitelist)
#   NONE   - not a proxy
#
# RELAY is only ever returned on positive proof. A service answering "200 OK" to
# CONNECT is NOT enough: Amazon's Alexa stack does exactly that on port 9080 and
# would be a false positive. We always speak through the tunnel and look for a
# marker from the real remote page.

def _recv_until(s, terminator=b"\r\n\r\n", cap=65536, deadline=6.0):
    buf, end = b"", time.time() + deadline
    while terminator not in buf and len(buf) < cap and time.time() < end:
        try:
            chunk = s.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    return buf

def _speak_http(s, host, marker) -> bool:
    """Send a GET down an already-open tunnel and look for the real page."""
    try:
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    except OSError:
        return False
    return marker.lower().encode() in _recv_until(s, b"</html>").lower()

def probe_socks5(ip, port, host, hport, marker, timeout):
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(b"\x05\x02\x00\x02")
        r = s.recv(2)
        if len(r) != 2 or r[0] != 0x05:
            return None, None
        if r[1] == 0xFF:
            return "NONE", "SOCKS5 refused all auth methods"
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", hport))
        rep = s.recv(10)
        if len(rep) < 2:
            return "GATED", "SOCKS5 handshake ok, no CONNECT reply"
        if rep[1] != 0x00:
            auth = " (needs auth)" if r[1] == 0x02 else " (no auth required)"
            return "GATED", f"SOCKS5{auth}, CONNECT refused code 0x{rep[1]:02x}"
        if _speak_http(s, host, marker):
            return "RELAY", "SOCKS5 CONNECT succeeded and forwarded real traffic"
        return "GATED", "SOCKS5 CONNECT accepted but nothing came back"
    except OSError:
        return None, None
    finally:
        s.close()

def probe_socks4(ip, port, host, hport, marker, timeout):
    try:
        dst = socket.inet_aton(socket.gethostbyname(host))
    except OSError:
        return None, None
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(b"\x04\x01" + struct.pack(">H", hport) + dst + b"\x00")
        rep = s.recv(8)
        if len(rep) < 2 or rep[0] != 0x00:
            return None, None
        if rep[1] != 0x5A:
            return "GATED", f"SOCKS4 reply 0x{rep[1]:02x} (request rejected)"
        if _speak_http(s, host, marker):
            return "RELAY", "SOCKS4 CONNECT succeeded and forwarded real traffic"
        return "GATED", "SOCKS4 accepted but nothing came back"
    except OSError:
        return None, None
    finally:
        s.close()

def probe_http_absolute(ip, port, host, hport, marker, timeout):
    """A forward proxy serves an absolute-URI GET by fetching it."""
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(f"GET http://{host}:{hport}/ HTTP/1.1\r\nHost: {host}\r\n"
                  f"Connection: close\r\n\r\n".encode())
        body = _recv_until(s, b"</html>")
        if marker.lower().encode() in body.lower():
            return "RELAY", "HTTP absolute-URI request was fetched and returned"
        return None, None
    except OSError:
        return None, None
    finally:
        s.close()

def probe_http_connect(ip, port, host, hport, marker, timeout):
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(f"CONNECT {host}:{hport} HTTP/1.1\r\nHost: {host}:{hport}\r\n\r\n".encode())
        head = _recv_until(s)
        if b" 200" not in head.split(b"\r\n")[0]:
            return None, None
        # 200 alone proves nothing - speak through it before believing it.
        if _speak_http(s, host, marker):
            return "RELAY", "HTTP CONNECT tunnel carried real traffic"
        return "GATED", "answered 200 to CONNECT but did not tunnel (likely not a proxy)"
    except OSError:
        return None, None
    finally:
        s.close()

def preflight(host=RELAY_HOST, port=RELAY_PORT, marker=RELAY_MARKER, timeout=8):
    """Can we reach the oracle directly? If not, RELAY can never be confirmed.

    Validate the instrument before trusting its readings: if this target does
    not resolve, every open relay on the network reads as clean.
    """
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                  f"Connection: close\r\n\r\n".encode())
        return marker.lower().encode() in _recv_until(s, b"</html>").lower()
    except OSError:
        return False
    finally:
        s.close()


def probe_proxy(ip, port, host=RELAY_HOST, hport=RELAY_PORT,
                marker=RELAY_MARKER, timeout=5):
    """Returns (verdict, detail) - the most severe result across all probes."""
    results = []
    for fn in (probe_socks5, probe_socks4, probe_http_absolute, probe_http_connect):
        v, d = fn(ip, port, host, hport, marker, timeout)
        if v:
            results.append((v, d))
        if v == "RELAY":
            return v, d
    for want in ("GATED", "NONE"):
        for v, d in results:
            if v == want:
                return v, d
    return "NONE", ""

# ------------------------------------------------------------------ tv apps --
# The network cannot see which apps a TV has installed, and that is where the
# proxy SDKs live. Only the TV can tell you, over its own control API.

# Publishers named in public research as monetising user devices as residential
# proxy exit nodes, plus the SDK vendors themselves. A match means "this app
# comes from a publisher with a documented track record" - NOT that this build
# contains an SDK, and NOT that it is relaying. Treat it as a reason to look.
PROXYWARE_PUBLISHERS = {
    "playworks": "named in Spur research as monetising devices as proxy exit nodes",
    "cloudtv": "named in Spur research as monetising devices as proxy exit nodes",
    "longvision": "named in Spur research as monetising devices as proxy exit nodes",
    "brightdata": "Bright Data - residential proxy network, consumer SDK",
    "bright data": "Bright Data - residential proxy network, consumer SDK",
    "bright sdk": "Bright Data consumer SDK",
    "brd": "Bright Data SDK artefact prefix",
    "castar": "Castar SDK - residential proxy",
    "massive": "Massive - residential proxy SDK",
    "honeygain": "Honeygain (Oxylabs) - bandwidth monetisation SDK",
    "oxylabs": "Oxylabs - residential proxy network",
}

TV_CACHE = os.path.expanduser("~/.cache/exitcheck/tv")


def flag_app(app):
    """Does this app come from a publisher with a proxy-monetisation record?"""
    # vendor + app id only. Titles are marketing text: an app called
    # "Massive Attack Radio" is not the Massive proxy SDK.
    hay = " ".join(str(app.get(k) or "") for k in ("vendor", "id", "appId")).lower()
    for pub, why in PROXYWARE_PUBLISHERS.items():
        if pub == "brd":
            if ".brd." in hay or hay.startswith("brd.") or "brd_sdk" in hay:
                return pub, why
        elif pub in hay:
            return pub, why
    return None, None


def _tv_token(key, val=None):
    os.makedirs(TV_CACHE, exist_ok=True)
    f = os.path.join(TV_CACHE, key)
    if val is None:
        try:
            return open(f).read().strip()
        except OSError:
            return None
    open(f, "w").write(val)
    return val


class WS:
    """Minimal RFC 6455 text-frame client. Enough for TV control APIs."""

    def __init__(self, host, port, path, tls=False, timeout=40):
        self.s = socket.create_connection((host, port), timeout)
        self.s.settimeout(timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE      # TVs ship self-signed certs
            self.s = ctx.wrap_socket(self.s)
        k = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {k}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = self.s.recv(4096)
            if not d:
                raise ConnectionError("closed during handshake")
            buf += d
        if b" 101" not in buf.split(b"\r\n")[0]:
            raise ConnectionError("websocket upgrade refused")
        self.buf = buf.split(b"\r\n\r\n", 1)[1]

    def send(self, obj):
        p = json.dumps(obj).encode()
        n = len(p)
        hdr = b"\x81" + (bytes([0x80 | n]) if n < 126 else
                         b"\xfe" + struct.pack(">H", n) if n < 65536 else
                         b"\xff" + struct.pack(">Q", n))
        m = os.urandom(4)
        self.s.sendall(hdr + m + bytes(c ^ m[i % 4] for i, c in enumerate(p)))

    def _read(self, n):
        while len(self.buf) < n:
            d = self.s.recv(65536)
            if not d:
                raise ConnectionError("closed")
            self.buf += d
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv(self):
        while True:
            h = self._read(2)
            op, n = h[0] & 0x0F, h[1] & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read(8))[0]
            body = self._read(n)
            if op == 8:
                raise ConnectionError("closed by TV")
            if op in (1, 2):
                return json.loads(body.decode("utf-8", "replace"))

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def lg_apps(ip, timeout=60):
    """webOS SSAP. First run shows a pairing prompt on the TV."""
    key = _tv_token(f"lg-{ip}")
    payload = {"forcePairing": False, "pairingType": "PROMPT",
               "manifest": {"manifestVersion": 1, "appVersion": "1.0",
                            "signed": {"created": "20260101",
                                       "appId": "com.exitcheck.app",
                                       "vendorId": "com.exitcheck",
                                       "localizedAppNames": {"": "exitcheck"},
                                       "permissions": ["LAUNCH", "READ_INSTALLED_APPS"]},
                            "permissions": ["LAUNCH", "READ_INSTALLED_APPS"]}}
    if key:
        payload["client-key"] = key
    w = WS(ip, 3000, "/", timeout=timeout)
    w.send({"type": "register", "id": "r0", "payload": payload})
    end = time.time() + timeout
    while time.time() < end:
        m = w.recv()
        if m.get("type") == "error":
            w.close()
            raise RuntimeError(m.get("error"))
        if m.get("type") == "registered":
            k = (m.get("payload") or {}).get("client-key")
            if k:
                _tv_token(f"lg-{ip}", k)
            break
    w.send({"type": "request", "id": "a0",
            "uri": "ssap://com.webos.applicationManager/listApps"})
    end = time.time() + 30
    while time.time() < end:
        m = w.recv()
        if m.get("id") == "a0":
            w.close()
            return (m.get("payload") or {}).get("apps", [])
    w.close()
    return []


def samsung_apps(ip, timeout=45):
    """Tizen remote-control channel. Needs an on-screen OK within ~30s.

    No unauthenticated fallback on purpose. The per-app status endpoint can
    only confirm app IDs you already know, and published ID lists cover
    mainstream streaming apps - not the small-publisher games that carry the
    SDKs. A check that cannot see the risky category would only manufacture
    false reassurance.
    """
    name = base64.b64encode(b"exitcheck").decode()
    tok = _tv_token(f"samsung-{ip}")
    path = f"/api/v2/channels/samsung.remote.control?name={name}"
    if tok:
        path += f"&token={tok}"
    w = WS(ip, 8002, path, tls=True, timeout=timeout)
    end = time.time() + timeout
    while time.time() < end:
        m = w.recv()
        ev = m.get("event")
        if ev == "ms.channel.unauthorized":
            w.close()
            raise RuntimeError("TV denied the connection")
        if ev == "ms.channel.timeOut":
            w.close()
            raise RuntimeError(
                "no one acknowledged the prompt within 30s. On the TV: Settings > "
                "General > External Device Manager > Device Connection Manager - set "
                "Access Notification to 'First Time Only', and delete any denied "
                "'exitcheck' entry from Device List")
        if ev == "ms.channel.connect":
            t = (m.get("data") or {}).get("token")
            if t:
                _tv_token(f"samsung-{ip}", t)
            break
    w.send({"method": "ms.channel.emit",
            "params": {"event": "ed.installedApp.get", "to": "host"}})
    end = time.time() + 25
    while time.time() < end:
        m = w.recv()
        if m.get("event") == "ed.installedApp.get":
            w.close()
            return (m.get("data") or {}).get("data", [])
    w.close()
    return []


def detect_tv(ip, timeout=3):
    """Which control API is this TV speaking?"""
    def open_(p):
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((ip, p))
            return True
        except OSError:
            return False
        finally:
            s.close()
    if open_(3000) or open_(3001):
        return "lg"
    if open_(8002) or open_(8001):
        return "samsung"
    return None


# ------------------------------------------------------------- credentials --

ENV_FILES = (".env", os.path.expanduser("~/.exitcheck.env"))


def load_env(path=None):
    """Read KEY=VALUE lines into os.environ. Existing vars always win.

    Looked for in: --env-file, ./.env, ~/.exitcheck.env. Keeps router
    passwords out of your shell history and off the process list.
    """
    loaded = []
    for f in ([path] if path else ENV_FILES):
        if not f or not os.path.isfile(f):
            continue
        try:
            with open(f) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip()
                    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                        v = v[1:-1]
                    os.environ.setdefault(k, v)       # real env wins
            loaded.append(f)
        except OSError:
            pass
        if path:
            break
    return loaded


# ----------------------------------------------------------- router backend --

class Unsupported(Exception):
    """This backend cannot do this. Commands degrade instead of crashing."""


class Router:
    """Backend contract. Implement what the device actually exposes.

    `verified` means someone ran it against real hardware. Backends written
    from vendor documentation start False and say so in the output - this
    tool should never imply a check it has not actually performed.
    """
    name = "?"
    verified = False
    needs_auth = True
    default_user = "admin"

    def __init__(self, host, user=None, password=None, **kw):
        self.host = host if "://" in host else "http://" + host
        self.hostname = self.host.split("://", 1)[1].split("/")[0].split(":")[0]
        self.user, self.password = user, password

    def login(self):
        return self

    def hosts(self):
        raise Unsupported("device list")

    def config(self):
        raise Unsupported("configuration audit")

    def clients(self):
        raise Unsupported("wifi client list")

    def counters(self, targets):
        raise Unsupported("per-client byte counters")

    def fetch_log(self):
        raise Unsupported("log retrieval")

    # -- helpers shared by the HTTP backends -------------------------------
    def _get(self, url, timeout=15, headers=None, data=None, opener=None):
        req = urllib.request.Request(url, data=data, headers=headers or {})
        o = opener or urllib.request.build_opener()
        with o.open(req, timeout=timeout) as r:
            return r.read()

    def _json(self, url, payload, timeout=15, headers=None):
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        return json.loads(self._get(url, timeout, h, json.dumps(payload).encode()))


# Adding a router = one class with hosts()/config()/clients()/fetch_log().
# Sagemcom is implemented because that is what the author owns.

class Sagemcom(Router):
    """Sagemcom F@st (/cgi/json-req)."""
    name = "sagemcom"
    verified = True          # run against an F@st 5657 GPON
    default_user = "admin"

    def __init__(self, host, user=None, password=None, sha512=False, **kw):
        super().__init__(host, user, password)
        self.base = self.host
        self.rid, self.sid, self.nonce = 0, "0", ""
        self._h = (lambda s: hashlib.sha512(s.encode()).hexdigest()) if sha512 else \
                  (lambda s: hashlib.md5(s.encode()).hexdigest())
        self.hpw = self._h(password or "")

    def _post(self, actions):
        import random
        cn = random.randint(0, 2**32 - 1)
        ha1 = self._h(f"{self.user}:{self.nonce}:{self.hpw}")
        req = {"request": {"id": self.rid, "session-id": self.sid, "priority": True,
                           "actions": actions, "cnonce": cn,
                           "auth-key": self._h(f"{ha1}:{self.rid}:{cn}:JSON:/cgi/json-req")}}
        self.rid += 1
        data = urllib.parse.urlencode({"req": json.dumps(req)}).encode()
        with urllib.request.urlopen(self.base + "/cgi/json-req", data, timeout=25) as r:
            return json.loads(r.read())

    def login(self):
        r = self._post([{"id": 0, "method": "logIn", "parameters": {
            "user": self.user, "persistent": "true", "session-options": {
                "nss": [{"name": "gtw", "uri": "http://sagemcom.com/gateway-data"}],
                "language": "ident",
                "context-flags": {"get-content-name": True, "local-time": True},
                "capability-depth": 2,
                "capability-flags": {"name": True, "default-value": False,
                                     "restriction": True, "description": False},
                "time-format": "ISO_8601"}}}])
        a = r["reply"]["actions"][0]
        if a["error"]["description"] != "XMO_NO_ERR":
            raise RuntimeError(f"login failed: {a['error']['description']}")
        p = a["callbacks"][0]["parameters"]
        self.sid, self.nonce = str(p["id"]), p["nonce"]
        return self

    def get(self, xpath, depth=-1):
        a = self._post([{"id": 0, "method": "getValue", "xpath": xpath,
                         "options": {"depth": depth}}])["reply"]["actions"][0]
        if a["error"]["description"] != "XMO_NO_ERR":
            return None
        return a["callbacks"][0]["parameters"]["value"]

    def hosts(self):
        v = self.get("Device/Hosts/Hosts", 3) or []
        return [{"mac": h["PhysAddress"], "ip": h.get("IPAddress", ""),
                 "name": h.get("UserFriendlyName") or h.get("HostName") or "",
                 "active": bool(h.get("Active")), "iface": h.get("InterfaceType", "")}
                for h in v if isinstance(h, dict)]

    def config(self):
        """The handful of settings that actually matter if a router is compromised."""
        dns = [d.get("DNSServer") for d in (self.get("Device/DNS/Relay/Forwardings", 3) or [])
               if isinstance(d, dict) and d.get("Status") == "ENABLED" and d.get("DNSServer")]
        maps = [m for m in (self.get("Device/NAT/PortMappings", 3) or [])
                if isinstance(m, dict) and m.get("Enable")]
        ra = (self.get("Device/UserInterface/RemoteAccess", 3) or {}).get("RemoteAccess", {})
        wan = self.get("Device/IP/Interfaces/Interface[Alias='IP_DATA']/IPv4Addresses", 3) or []
        wan_ip = next((a.get("IPAddress") for a in wan if isinstance(a, dict) and a.get("IPAddress")), None)
        wan_type = next((a.get("AddressingType") for a in wan if isinstance(a, dict)), None)
        return {"dns_servers": dns, "port_forwards": maps,
                "wan_ip": wan_ip, "wan_type": wan_type,
                "remote_access": bool(ra.get("Enable")),
                "firewall": self.get("Device/Firewall/Config"),
                "upnp": (self.get("Device/UPnP/Device", 2) or {}).get("Device", {}).get("UPnPIGD"),
                "firmware": self.get("Device/DeviceInfo/ExternalFirmwareVersion"),
                "model": self.get("Device/DeviceInfo/ModelName")}

    def _aps(self):
        return [a.get("Alias") for a in (self.get("Device/WiFi/AccessPoints", 2) or [])
                if isinstance(a, dict)]

    def clients(self):
        """[(mac, ap)] for every associated+active wifi client."""
        out = []
        for ap in self._aps():
            v = self.get(f"Device/WiFi/AccessPoints/AccessPoint[Alias='{ap}']/AssociatedDevices", 4)
            for d in (v or []):
                if isinstance(d, dict) and d.get("Active"):
                    out.append((d["MACAddress"], ap))
        return out

    def counters(self, targets):
        """One batched request. {mac: (down, up)} plus 'WAN'.

        AssociatedDevice stats are from the AP's point of view, so BytesSent is
        AP->client, i.e. the client's DOWNLOAD. The WAN interface is the other
        way round. Getting this backwards inverts every conclusion.
        """
        wan = "Device/IP/Interfaces/Interface[Alias='IP_DATA']/Stats"
        acts = [{"id": i, "method": "getValue", "options": {"depth": 2},
                 "xpath": f"Device/WiFi/AccessPoints/AccessPoint[Alias='{ap}']"
                          f"/AssociatedDevices/AssociatedDevice[MACAddress='{m}']/Stats"}
                for i, (m, ap) in enumerate(targets)]
        acts.append({"id": len(targets), "method": "getValue", "xpath": wan,
                     "options": {"depth": 2}})
        out = {}
        for a in self._post(acts)["reply"]["actions"]:
            if a["error"]["description"] != "XMO_NO_ERR":
                continue
            s = a["callbacks"][0]["parameters"]["value"]["Stats"]
            sent, recv = int(s["BytesSent"]), int(s["BytesReceived"])
            if a["id"] == len(targets):
                out["WAN"] = (recv, sent)
            else:
                out[targets[a["id"]][0]] = (sent, recv)
        return out

    def fetch_log(self):
        a = self._post([{"id": 0, "method": "getVendorLogDownloadURI",
                         "xpath": "Device/DeviceInfo/VendorLogFiles/VendorLogFile[@uid='1']",
                         "parameters": {"FileName": "VendorLog"}}])["reply"]["actions"][0]
        if a["error"]["description"] != "XMO_NO_ERR":
            return None
        uri = a["callbacks"][0]["parameters"]["uri"]
        with urllib.request.urlopen(self.base + uri, timeout=120) as r:
            return r.read().decode("utf-8", "replace")

class UPnP(Router):
    """Generic UPnP IGD. No credentials, works on a large share of consumer
    routers. Only exposes what IGD defines: external IP and port mappings.

    Worth running everywhere: an unexpected port mapping is one of the few
    router-level findings that matters, and UPnP is how malware adds one.
    """
    name = "upnp"
    verified = True          # run against a Sagemcom F@st 5657
    needs_auth = False
    NS = {"d": "urn:schemas-upnp-org:device-1-0"}
    WAN = ("urn:schemas-upnp-org:service:WANIPConnection:1",
           "urn:schemas-upnp-org:service:WANPPPConnection:1")

    def __init__(self, host, user=None, password=None, **kw):
        super().__init__(host, user, password)
        self.ctrl = self.svc = None

    @staticmethod
    def discover(timeout=3):
        """SSDP M-SEARCH for an IGD. Returns the description URL."""
        msg = ("M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\n"
               'MAN:"ssdp:discover"\r\nMX:2\r\n'
               "ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(msg.encode(), ("239.255.255.250", 1900))
            while True:
                data, _ = s.recvfrom(4096)
                for line in data.decode("utf-8", "replace").split("\r\n"):
                    if line.lower().startswith("location:"):
                        return line.split(":", 1)[1].strip()
        except OSError:
            return None
        finally:
            s.close()

    def _desc_urls(self):
        found = self.discover()
        if found and self.hostname in found:
            yield found
        for p in (49152, 5000, 1900, 80, 2869, 49153):
            for path in ("/rootDesc.xml", "/description.xml", "/igd.xml",
                         "/DeviceDescription.xml", "/upnp/IGD.xml"):
                yield f"http://{self.hostname}:{p}{path}"

    def login(self):
        for url in self._desc_urls():
            try:
                xml = self._get(url, timeout=5)
                root = ET.fromstring(xml)
            except (OSError, ET.ParseError, ValueError, urllib.error.URLError):
                continue
            for svc in root.iter():
                if not svc.tag.endswith("service"):
                    continue
                st = cu = None
                for ch in svc:
                    if ch.tag.endswith("serviceType"):
                        st = (ch.text or "").strip()
                    elif ch.tag.endswith("controlURL"):
                        cu = (ch.text or "").strip()
                if st in self.WAN and cu:
                    base = url.rsplit("/", 1)[0]
                    self.ctrl = cu if cu.startswith("http") else (
                        f"http://{urllib.parse.urlparse(url).netloc}{cu}"
                        if cu.startswith("/") else f"{base}/{cu}")
                    self.svc = st
                    return self
        raise RuntimeError("no UPnP IGD WAN service found (UPnP may be off)")

    def _soap(self, action, args=""):
        body = (f'<?xml version="1.0"?><s:Envelope '
                f'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                f'<s:Body><u:{action} xmlns:u="{self.svc}">{args}'
                f'</u:{action}></s:Body></s:Envelope>')
        out = self._get(self.ctrl, 12,
                        {"Content-Type": 'text/xml; charset="utf-8"',
                         "SOAPAction": f'"{self.svc}#{action}"'}, body.encode())
        return {e.tag.split("}")[-1]: (e.text or "") for e in ET.fromstring(out).iter()}

    def config(self):
        wan = None
        try:
            wan = self._soap("GetExternalIPAddress").get("NewExternalIPAddress")
        except Exception:
            pass
        maps = []
        for i in range(0, 64):
            try:
                m = self._soap("GetGenericPortMappingEntry",
                               f"<NewPortMappingIndex>{i}</NewPortMappingIndex>")
            except Exception:
                break
            if "NewExternalPort" not in m:
                break
            maps.append({"Alias": m.get("NewPortMappingDescription", ""),
                         "ExternalPort": m.get("NewExternalPort"),
                         "InternalClient": m.get("NewInternalClient"),
                         "InternalPort": m.get("NewInternalPort"),
                         "Protocol": m.get("NewProtocol"),
                         "Enable": m.get("NewEnabled") == "1"})
        return {"dns_servers": [], "port_forwards": [m for m in maps if m["Enable"]],
                "remote_access": None, "firewall": None, "upnp": True,
                "firmware": None, "model": "generic UPnP IGD",
                "wan_ip": wan, "wan_type": None}


class OpenWrt(Router):
    """OpenWrt and derivatives (GL.iNet, Turris, ...) via ubus JSON-RPC.

    Needs uhttpd-mod-ubus + an rpcd ACL granting luci-rpc read access.
    Written from the OpenWrt ubus documentation; not yet run on hardware.
    """
    name = "openwrt"
    verified = False
    default_user = "root"
    NULL = "00000000000000000000000000000000"

    def __init__(self, host, user=None, password=None, **kw):
        super().__init__(host, user, password)
        self.sid = None

    def _call(self, obj, method, params=None, sid=None):
        r = self._json(self.host + "/ubus", {
            "jsonrpc": "2.0", "id": 1, "method": "call",
            "params": [sid or self.sid or self.NULL, obj, method, params or {}]})
        if "error" in r:
            raise RuntimeError(r["error"].get("message", "ubus error"))
        res = r.get("result") or []
        if len(res) > 1:
            return res[1]
        if res and res[0] not in (0, None):
            raise RuntimeError(f"ubus status {res[0]} on {obj}.{method}")
        return {}

    def login(self):
        d = self._call("session", "login",
                       {"username": self.user or self.default_user,
                        "password": self.password or ""}, sid=self.NULL)
        self.sid = d.get("ubus_rpc_session")
        if not self.sid:
            raise RuntimeError("ubus login failed")
        return self

    def hosts(self):
        out, seen = [], set()
        d = self._call("luci-rpc", "getDHCPLeases")
        for fam in ("dhcp_leases", "dhcp6_leases"):
            for l in d.get(fam) or []:
                mac = (l.get("macaddr") or "").upper()
                if not mac or mac in seen:
                    continue
                seen.add(mac)
                out.append({"mac": mac, "ip": l.get("ipaddr") or l.get("ip6addr") or "",
                            "name": l.get("hostname") or "", "active": True,
                            "iface": ""})
        return out

    def config(self):
        wan = None
        for name in ("wan", "wan6"):
            try:
                st = self._call(f"network.interface.{name}", "status")
            except RuntimeError:
                continue
            for a in st.get("ipv4-address") or []:
                wan = a.get("address") or wan
            if wan:
                break
        return {"dns_servers": (st.get("dns-server") if wan else []) or [],
                "port_forwards": [], "remote_access": None, "firewall": None,
                "upnp": None, "firmware": None, "model": "OpenWrt",
                "wan_ip": wan, "wan_type": "dhcp"}


class FritzBox(Router):
    """AVM FRITZ!Box over TR-064 SOAP (port 49000, HTTP digest auth).

    Written from AVM's published TR-064 documentation; not yet run on hardware.
    """
    name = "fritzbox"
    verified = False
    default_user = "admin"

    def __init__(self, host, user=None, password=None, **kw):
        super().__init__(host, user, password)
        self.port = 49000
        self.opener = None

    def login(self):
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, f"http://{self.hostname}:{self.port}",
                         self.user or self.default_user, self.password or "")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPDigestAuthHandler(mgr))
        # Must actually touch the device: a login() that only builds an opener
        # always "succeeds" and would hijack autodetection on every router.
        self._get(f"http://{self.hostname}:{self.port}/tr64desc.xml", 6)
        return self

    def _soap(self, path, service, action, args=""):
        body = (f'<?xml version="1.0"?><s:Envelope '
                f'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
                f'<s:Body><u:{action} xmlns:u="{service}">{args}'
                f'</u:{action}></s:Body></s:Envelope>')
        out = self._get(f"http://{self.hostname}:{self.port}{path}", 15,
                        {"Content-Type": 'text/xml; charset="utf-8"',
                         "SOAPAction": f"{service}#{action}"},
                        body.encode(), opener=self.opener)
        return {e.tag.split("}")[-1]: (e.text or "") for e in ET.fromstring(out).iter()}

    def hosts(self):
        n = int(self._soap("/upnp/control/hosts", "urn:dslforum-org:service:Hosts:1",
                           "GetHostNumberOfEntries").get("NewHostNumberOfEntries", 0))
        out = []
        for i in range(n):
            h = self._soap("/upnp/control/hosts", "urn:dslforum-org:service:Hosts:1",
                           "GetGenericHostEntry",
                           f"<NewIndex>{i}</NewIndex>")
            out.append({"mac": (h.get("NewMACAddress") or "").upper(),
                        "ip": h.get("NewIPAddress") or "",
                        "name": h.get("NewHostName") or "",
                        "active": h.get("NewActive") == "1",
                        "iface": h.get("NewInterfaceType") or ""})
        return out

    def config(self):
        svc = "urn:dslforum-org:service:WANIPConnection:1"
        wan = self._soap("/upnp/control/wanipconnection1", svc,
                         "GetExternalIPAddress").get("NewExternalIPAddress")
        return {"dns_servers": [], "port_forwards": [], "remote_access": None,
                "firewall": None, "upnp": None, "firmware": None,
                "model": "FRITZ!Box", "wan_ip": wan, "wan_type": None}


class AsusWrt(Router):
    """ASUSWRT and Merlin via /login.cgi + /appGet.cgi.

    Written from the documented appGet hook interface; not yet run on hardware.
    """
    name = "asuswrt"
    verified = False
    default_user = "admin"

    def __init__(self, host, user=None, password=None, **kw):
        super().__init__(host, user, password)
        self.token = None

    def login(self):
        cred = base64.b64encode(
            f"{self.user or self.default_user}:{self.password or ''}".encode()).decode()
        body = urllib.parse.urlencode({"login_authorization": cred}).encode()
        raw = self._get(self.host + "/login.cgi", 15,
                        {"Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "asusrouter-Android"}, body)
        try:
            self.token = json.loads(raw).get("asus_token")
        except ValueError:
            self.token = None
        if not self.token:
            raise RuntimeError("ASUSWRT login failed")
        return self

    def _hook(self, hook):
        body = urllib.parse.urlencode({"hook": hook}).encode()
        raw = self._get(self.host + "/appGet.cgi", 20,
                        {"Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "asusrouter-Android",
                         "Cookie": f"asus_token={self.token}"}, body)
        return json.loads(raw.decode("utf-8", "replace"))

    def hosts(self):
        data = self._hook("get_clientlist()").get("get_clientlist", {})
        out = []
        for mac, c in data.items():
            if not isinstance(c, dict) or ":" not in mac:
                continue
            out.append({"mac": mac.upper(), "ip": c.get("ip") or "",
                        "name": c.get("nickName") or c.get("name") or "",
                        "active": str(c.get("isOnline")) == "1",
                        "iface": "WiFi" if str(c.get("isWL")) not in ("0", "None")
                                 else "Ethernet"})
        return out

    def config(self):
        w = self._hook("wanlink()")
        return {"dns_servers": (w.get("wanlink_dns") or "").split(),
                "port_forwards": [], "remote_access": None, "firewall": None,
                "upnp": None, "firmware": None, "model": "ASUSWRT",
                "wan_ip": w.get("wanlink_ipaddr"), "wan_type": w.get("wanlink_type")}


class MikroTik(Router):
    """MikroTik RouterOS v7 REST API (https, basic auth).

    Written from MikroTik's REST documentation; not yet run on hardware.
    """
    name = "mikrotik"
    verified = False
    default_user = "admin"

    def __init__(self, host, user=None, password=None, **kw):
        super().__init__(host, user, password)
        if self.host.startswith("http://"):
            self.host = "https://" + self.host[len("http://"):]

    def _rest(self, path):
        cred = base64.b64encode(
            f"{self.user or self.default_user}:{self.password or ''}".encode()).decode()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE          # RouterOS ships a self-signed cert
        o = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        return json.loads(self._get(self.host + path, 15,
                                    {"Authorization": "Basic " + cred}, opener=o))

    def login(self):
        self._rest("/rest/system/resource")
        return self

    def hosts(self):
        return [{"mac": (l.get("mac-address") or "").upper(),
                 "ip": l.get("address") or "",
                 "name": l.get("host-name") or l.get("comment") or "",
                 "active": l.get("status") == "bound", "iface": ""}
                for l in self._rest("/rest/ip/dhcp-server/lease")]

    def config(self):
        wan = None
        for a in self._rest("/rest/ip/address"):
            ip = (a.get("address") or "").split("/")[0]
            if ip and not ip.startswith(("10.", "192.168.", "127.")):
                wan = ip
                break
        return {"dns_servers": [], "port_forwards": [], "remote_access": None,
                "firewall": None, "upnp": None, "firmware": None,
                "model": "RouterOS", "wan_ip": wan, "wan_type": None}


ROUTERS = {c.name: c for c in (Sagemcom, UPnP, OpenWrt, FritzBox, AsusWrt, MikroTik)}


def detect_router(host, user=None, password=None):
    """Probe for a backend, best first.

    Credentials are passed in because the authenticated backends cannot
    identify themselves without them - otherwise every router falls through
    to UPnP, which answers almost everywhere but exposes far less.
    """
    for cls in (Sagemcom, OpenWrt, AsusWrt, FritzBox, MikroTik, UPnP):
        if cls.needs_auth and not password:
            continue
        try:
            cls(host, user or cls.default_user, password).login()
            return cls.name
        except Exception:
            continue
    try:
        UPnP(host).login()
        return UPnP.name
    except Exception:
        return None


# ---------------------------------------------------------------- analysis --

LOG_RE = re.compile(
    r"^(\d{2}\.\d{2}\.\d{4})\s+(\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+)\s+\d+\s+(.*)$")
DOMAIN_RE = re.compile(r"\(([^)]+)\)\s*$")

def parse_log(text: str):
    """Sagemcom vendor-log lines -> [(epoch, severity, facility, message)]."""
    out = []
    for line in text.splitlines():
        m = LOG_RE.match(line.strip())
        if not m:
            continue
        d, t, sev, fac, msg = m.groups()
        try:
            ts = time.mktime(time.strptime(f"{d} {t}", "%d.%m.%Y %H:%M:%S"))
        except ValueError:
            continue
        out.append((ts, sev, fac, msg))
    return out

def proxyware_hit(domain: str):
    d = domain.lower().rstrip(".")
    for known in PROXYWARE_DOMAINS:
        if d == known or d.endswith("." + known):
            return known
    return None

def find_beacon(times, min_count=12, tol=0.10, min_frac=0.6):
    """Fixed-interval callbacks look nothing like human traffic.

    Returns (period_seconds, regularity 0-1, samples) or None.
    """
    if len(times) < min_count:
        return None
    deltas = sorted(b - a for a, b in zip(times, times[1:]) if b > a)
    if not deltas:
        return None
    med = deltas[len(deltas) // 2]
    if med <= 0:
        return None
    hits = sum(1 for d in deltas if abs(d - med) <= tol * med)
    frac = hits / len(deltas)
    return (med, frac, len(deltas) + 1) if frac >= min_frac else None

def analyse_log(text: str):
    recs = parse_log(text)
    by_domain = defaultdict(list)
    wifi_fail = []
    for ts, sev, fac, msg in recs:
        if fac == "DNS":
            m = DOMAIN_RE.search(msg)
            if m:
                by_domain[m.group(1)].append(ts)
        elif fac == "WIFI" and "incorrect login" in msg:
            wifi_fail.append((ts, msg))
    hits, beacons = [], []
    for dom, times in by_domain.items():
        known = proxyware_hit(dom)
        if known:
            hits.append((dom, known, len(times)))
        b = find_beacon(sorted(times))
        if b:
            beacons.append((dom, len(times), b[0], b[1]))
    beacons.sort(key=lambda x: -x[1])
    return {"records": len(recs), "domains": len(by_domain), "proxyware": hits,
            "beacons": beacons, "wifi_auth_failures": wifi_fail,
            "span": (recs[0][0], recs[-1][0]) if recs else None}

def ratio_verdict(down, up):
    """Exit nodes push traffic OUT. Watching pulls it IN.

    Legitimately symmetric: video calls, P2P gaming, cloud backup, NAS sync.
    So this is a lead, never a conviction.
    """
    if down + up < 5_000_000:
        return "idle", "too little traffic to judge"
    r = up / max(down, 1)
    if r >= 1.0:
        return "suspect", f"uploads more than it downloads (up/down {r:.2f})"
    if r >= 0.5:
        return "watch", f"unusually upload-heavy (up/down {r:.2f})"
    return "normal", f"up/down {r:.2f}"

def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PB"

# ---------------------------------------------------------------- commands --

def cmd_scan(a, o: Out):
    targets = {}
    if a.host:
        targets = {h: "" for h in a.host}
    else:
        base = a.net or local_subnet()
        if not base:
            o.bad("could not work out your subnet - pass --net 192.168.1 or --host IP")
            return 1
        if a.sweep:
            o.info(f"pinging {base}.1-254 to populate the ARP cache ...")
            ping_sweep(base)
        targets = {ip: mac for ip, mac in arp_table().items() if ip.startswith(base + ".")}
        if not targets:
            o.bad(f"no hosts found on {base}.0/24 - try --sweep")
            return 1

    if preflight(a.relay_host, a.relay_port, a.relay_marker):
        o.ok(f"relay oracle reachable ({a.relay_host}) - RELAY can be confirmed")
    else:
        o.bad(f"CANNOT REACH {a.relay_host}:{a.relay_port}, or it did not return "
              f"{a.relay_marker!r}.")
        o.info("Open relays will NOT be confirmed - every result below reads clean")
        o.info("whether it is or not. Fix your connection, or pick a reachable")
        o.info("plain-HTTP target: --relay-host H --relay-port P --relay-marker TEXT")

    cache = load_oui_cache()
    ports = list(range(1, 65536)) if a.full else PROXY_PORTS
    o.head(f"Scanning {len(targets)} host(s), {len(ports)} ports each")
    findings, report = [], []

    for ip in sorted(targets, key=lambda x: tuple(int(p) for p in x.split("."))):
        mac = targets[ip]
        ven = vendor(mac, cache, online=not a.offline) if mac else "?"
        open_ports = scan_ports(ip, ports, timeout=a.timeout)
        label = f"{ip}  {mac or '':17}  {ven}"
        entry = {"ip": ip, "mac": mac, "vendor": ven, "ports": [], "verdict": "clean"}
        if not open_ports:
            print(f"\n{label}\n    no open ports")
            report.append(entry)
            continue
        print(f"\n{label}")
        for p in open_ports:
            verdict, detail = probe_proxy(ip, p, a.relay_host, a.relay_port,
                                          a.relay_marker, a.timeout + 3)
            note = NOTABLE.get(p, "")
            entry["ports"].append({"port": p, "verdict": verdict, "detail": detail})
            if verdict == "RELAY":
                entry["verdict"] = "RELAY"
                o.bad(f"port {p}: OPEN RELAY - {detail}")
                findings.append((ip, p, detail))
            elif verdict == "GATED":
                if entry["verdict"] == "clean":
                    entry["verdict"] = "GATED"
                o.warn(f"port {p}: speaks a proxy protocol but will not forward - {detail}")
            else:
                print(f"    port {p:<6} open{'  (' + note + ')' if note else ''}")
        report.append(entry)

    o.head("Result")
    if findings:
        o.bad(f"{len(findings)} confirmed open relay(s). Something is proxying traffic.")
        for ip, p, d in findings:
            o.info(f"{ip}:{p} - {d}")
    else:
        o.ok("no device forwarded traffic for us. Nothing is acting as an open relay.")
        o.info("Note: a proxyware SDK dials OUT rather than listening, so this alone")
        o.info("does not clear a device. Check upload ratios too: exitcheck router")
    save_oui_cache(cache)
    if a.json:
        print(json.dumps(report, indent=1))
    return 2 if findings else 0

def connect_router(a, o: Out):
    host = a.router or os.environ.get("EXITCHECK_ROUTER") or "192.168.1.1"
    kind = a.type or os.environ.get("EXITCHECK_TYPE")
    if not kind or kind == "auto":
        o.info(f"detecting the router at {host} ...")
        kind = detect_router(host, a.user or os.environ.get("EXITCHECK_USER"),
                             a.password or os.environ.get("EXITCHECK_PASSWORD"))
        if not kind:
            o.bad(f"no supported router API answered at {host}.")
            o.info("Supported: " + ", ".join(sorted(ROUTERS)))
            o.info("Pass --type to skip detection, or --router to fix the address.")
            return None
        o.ok(f"detected: {kind}")
    cls = ROUTERS[kind]
    user = a.user or os.environ.get("EXITCHECK_USER") or cls.default_user
    pw = a.password or os.environ.get("EXITCHECK_PASSWORD")
    if cls.needs_auth and not pw:
        import getpass
        try:
            pw = getpass.getpass(f"password for {user}@{host}: ")
        except (EOFError, KeyboardInterrupt):
            o.bad("no password given")
            return None
    try:
        r = cls(host, user, pw, sha512=getattr(a, "sha512", False)).login()
    except Exception as e:
        o.bad(f"could not connect via {kind}: {e}")
        return None
    if not cls.verified:
        o.warn(f"the '{kind}' backend is written from vendor documentation and "
               f"has not been run against real hardware - treat output as unconfirmed")
    return r

def cmd_router(a, o: Out):
    r = connect_router(a, o)
    if not r:
        return 1
    try:
        cfg = r.config()
    except Unsupported as e:
        o.warn(f"this backend cannot do a {e}")
        cfg = None
    except Exception as e:
        o.bad(f"backend '{r.name}' failed reading the config: "
              f"{type(e).__name__}: {e}")
        cfg = None
    if cfg is None:
        return 1
    o.head(f"Router: {cfg.get('model')}  firmware {cfg.get('firmware')}")
    if cfg.get("remote_access"):
        o.bad("remote management is ENABLED - the admin UI is reachable from the internet")
    else:
        o.ok("remote management disabled")
    if cfg.get("wan_ip"):
        o.info(f"WAN address: {cfg['wan_ip']} ({cfg.get('wan_type')})")
        if cfg.get("wan_type") in ("IPCP", "DHCPv4"):
            o.info("  ^ assigned, so it can change. Anything pinned to this IP"
                   " (filtering DNS, allowlists) breaks silently when it does.")
    dns = cfg.get("dns_servers") or []
    if dns:
        o.info(f"DNS servers in use: {', '.join(dns)}")
        o.info("  ^ confirm these belong to your ISP. Rewritten DNS is the classic hijack.")
    if cfg.get("port_forwards"):
        o.warn(f"{len(cfg['port_forwards'])} enabled port forward(s)/DMZ:")
        for m in cfg["port_forwards"]:
            o.info(f"    {m.get('Alias')} ext {m.get('ExternalPort')} -> "
                   f"{m.get('InternalClient')}:{m.get('InternalPort')} {m.get('Protocol')}")
    else:
        o.ok("no enabled port forwards or DMZ")
    o.info(f"firewall level: {cfg.get('firewall')}   UPnP IGD: {cfg.get('upnp')}")

    try:
        tg = r.clients()
    except Unsupported as e:
        o.info("")
        o.info(f"(no {e} from this backend - upload ratios unavailable)")
        return 0
    except Exception as e:
        o.bad(f"backend '{r.name}' failed listing clients: {type(e).__name__}: {e}")
        return 1
    o.head("Per-client traffic (since each client associated)")
    o.info("Exit nodes push traffic out. Watching pulls it in.")
    if not tg:
        o.info("no active wifi clients")
        return 0
    try:
        names = {h["mac"]: h["name"] for h in r.hosts()}
        counters = r.counters(tg)
    except Unsupported as e:
        o.info(f"(no {e} from this backend)")
        return 0
    except Exception as e:
        o.bad(f"backend '{r.name}' failed reading counters: {type(e).__name__}: {e}")
        return 1
    rows = []
    for mac, (down, up) in counters.items():
        if mac == "WAN":
            continue
        rows.append((up / max(down, 1), mac, names.get(mac) or mac, down, up))
    rows.sort(reverse=True)
    print()
    for _, mac, name, down, up in rows:
        v, why = ratio_verdict(down, up)
        line = f"  {name[:24]:26} {human(down):>9} down  {human(up):>9} up   {why}"
        {"suspect": o.bad, "watch": o.warn}.get(v, lambda s: print(s))(
            line.strip() if v in ("suspect", "watch") else line)
    return 0

def cmd_log(a, o: Out):
    if a.file:
        text = open(a.file, encoding="utf-8", errors="replace").read()
    else:
        r = connect_router(a, o)
        if not r:
            return 1
        try:
            text = r.fetch_log()
        except Unsupported as e:
            o.bad(f"this backend has no {e}. Pass a saved log file instead.")
            return 1
        if not text:
            o.bad("router returned no log")
            return 1
        if a.save:
            open(a.save, "w").write(text)
            o.info(f"saved raw log to {a.save}")

    res = analyse_log(text)
    if not res["records"]:
        o.bad("no parseable log lines (expected 'DD.MM.YYYY HH:MM:SS SEV FACILITY N msg')")
        return 1
    s, e = res["span"]
    o.head(f"Log: {res['records']} lines, {res['domains']} distinct domains, "
           f"{time.strftime('%d %b', time.localtime(s))} - "
           f"{time.strftime('%d %b %Y', time.localtime(e))}")

    if res["proxyware"]:
        o.bad("KNOWN PROXYWARE DOMAINS QUERIED:")
        for dom, known, n in sorted(res["proxyware"], key=lambda x: -x[2]):
            o.info(f"    {dom}  ({n}x, matches {known})")
    else:
        o.ok("no queries to any known proxyware or residential-proxy domain")

    if res["beacons"]:
        o.head("Fixed-interval beacons (regular callbacks, not human browsing)")
        for dom, n, period, reg in res["beacons"][:15]:
            tag = o.bad if proxyware_hit(dom) else o.warn
            tag(f"{dom}  {n}x every ~{period/60:.1f} min  ({reg:.0%} regular)")
        o.info("Most are benign SDK telemetry. Look up any you do not recognise.")

    n = len(res["wifi_auth_failures"])
    (o.warn if n > 20 else o.ok)(f"{n} wifi authentication failure(s)"
                                 + (" - possible password guessing" if n > 20 else ""))
    o.info("Caveat: many routers log only FAILED DNS lookups, so a proxyware")
    o.info("domain that resolves fine will never appear here. Absence is weak evidence.")
    return 0

def cmd_tv(a, o: Out):
    kind = a.platform or detect_tv(a.ip)
    if not kind:
        o.bad(f"no TV control API answering on {a.ip} (tried 3000/3001 webOS, "
              f"8001/8002 Tizen).")
        o.info("The TV is probably in standby. Turn it on and try again.")
        return 1
    o.head(f"{a.ip} - {'LG webOS' if kind == 'lg' else 'Samsung Tizen'}")
    o.info("Accept the prompt on the TV if one appears (first run only).")
    try:
        apps = (lg_apps if kind == "lg" else samsung_apps)(a.ip)
    except (RuntimeError, ConnectionError, OSError) as e:
        o.bad(f"could not read the app list: {e}")
        return 1
    if not apps:
        o.warn("the TV returned no apps")
        return 1

    user = [x for x in apps if not x.get("systemApp")]
    flagged = [(x, *flag_app(x)) for x in user]
    hits = [(x, p, w) for x, p, w in flagged if p]

    o.info(f"{len(apps)} apps installed, {len(user)} non-system")
    if a.json:
        print(json.dumps(apps, indent=1, ensure_ascii=False))
        return 2 if hits else 0

    print()
    for x in sorted(user, key=lambda y: (y.get("title") or y.get("name") or "").lower()):
        title = (x.get("title") or x.get("name") or "?")[:32]
        vendor = (x.get("vendor") or "")[:22]
        pub, why = flag_app(x)
        if pub:
            o.bad(f"{title:34} {vendor:24} <- {pub}")
        else:
            print(f"      {title:34} {vendor}")

    o.head("Result")
    if hits:
        o.bad(f"{len(hits)} app(s) from publishers with a proxy-monetisation record:")
        seen = set()
        for _, pub, why in hits:
            if pub not in seen:
                seen.add(pub)
                o.info(f"  {pub}: {why}")
        o.info("")
        o.info("This identifies the PUBLISHER, not the build on your TV, and it is")
        o.info("not evidence the device is relaying - check that with `scan` and the")
        o.info("upload ratios in `router`. The SDKs are usually opt-in behind an")
        o.info("in-app 'no ads if you share resources' dialog. If you do not use")
        o.info("these apps, removing them closes the question.")
    else:
        o.ok("no app from a publisher on the known list")
        o.info("The list only covers publishers named in public research, so this")
        o.info("is not a clean bill of health - just no known-bad name present.")
    return 2 if hits else 0


def cmd_monitor(a, o: Out):
    r = connect_router(a, o)
    if not r:
        return 1
    try:
        tg = r.clients()
        names = {h["mac"]: h["name"] for h in r.hosts()}
    except Unsupported as e:
        o.bad(f"this backend has no {e}, so live monitoring is unavailable")
        return 1
    o.head(f"Monitoring {len(tg)} clients every {a.interval}s for {a.duration}s")
    o.info("One session only - these routers evict an older API session on new login.")
    totals = defaultdict(lambda: [0.0, 0.0])
    prev, t0, elapsed = r.counters(tg), time.time(), 0.0
    while elapsed < a.duration:
        time.sleep(a.interval)
        cur = r.counters(tg)
        dt = time.time() - t0
        t0 = time.time()
        elapsed += dt
        rows = []
        for k, v in cur.items():
            if k not in prev:
                continue
            d, u = (v[0] - prev[k][0]) / dt, (v[1] - prev[k][1]) / dt
            totals[k][0] += d * dt
            totals[k][1] += u * dt
            rows.append((d + u, k, d, u))
        rows.sort(reverse=True)
        print(f"\n--- t+{int(elapsed)}s " + "-" * 40)
        for _, k, d, u in rows:
            if k == "WAN" or d + u >= 2048:
                nm = "WAN TOTAL" if k == "WAN" else (names.get(k) or k)
                print(f"  {nm[:24]:26} {human(d):>9}/s down  {human(u):>9}/s up")
        prev = cur
    o.head(f"Totals over {int(elapsed)}s")
    for k, v in sorted(totals.items(), key=lambda x: -(x[1][0] + x[1][1])):
        nm = "WAN TOTAL" if k == "WAN" else (names.get(k) or k)
        vd, why = ratio_verdict(v[0], v[1])
        print(f"  {nm[:24]:26} {human(v[0]):>9} down  {human(v[1]):>9} up   "
              f"{'' if k == 'WAN' else why}")
    return 0

# --------------------------------------------------------------------- cli --

def main(argv=None):
    p = argparse.ArgumentParser(
        prog="exitcheck",
        description="Find out whether anything on your network is relaying traffic "
                    "for strangers. Scan only networks you own.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--list-backends", action="store_true",
                   help="show router backends and whether each is hardware-verified")
    if "--list-backends" in (argv if argv is not None else sys.argv[1:]):
        print(f"{'backend':12} {'auth':6} status")
        for n, c in sorted(ROUTERS.items()):
            print(f"  {n:12} {'yes' if c.needs_auth else 'no ':6} "
                  f"{'verified on hardware' if c.verified else 'from vendor docs, UNTESTED'}")
        return 0
    sub = p.add_subparsers(dest="cmd", required=True)

    def router_args(q):
        q.add_argument("--router", help="router address ($EXITCHECK_ROUTER, "
                                        "default 192.168.1.1)")
        q.add_argument("--type", choices=sorted(ROUTERS) + ["auto"],
                       help="backend; default autodetect ($EXITCHECK_TYPE)")
        q.add_argument("--user", help="$EXITCHECK_USER, else the backend default")
        q.add_argument("--password", help="$EXITCHECK_PASSWORD, else prompted. "
                                          "Prefer a .env file over the flag")
        q.add_argument("--env-file", help="credentials file (default: ./.env "
                                          "then ~/.exitcheck.env)")
        q.add_argument("--sha512", action="store_true",
                       help="router hashes with SHA-512 instead of MD5")

    s = sub.add_parser("scan", help="port-scan the LAN and probe for real proxy behaviour")
    s.add_argument("--host", action="append", help="scan only this IP (repeatable)")
    s.add_argument("--net", help="subnet base, e.g. 192.168.1")
    s.add_argument("--sweep", action="store_true", help="ping sweep first to fill ARP")
    s.add_argument("--full", action="store_true", help="all 65535 ports (slow)")
    s.add_argument("--timeout", type=float, default=0.7)
    s.add_argument("--offline", action="store_true", help="skip MAC vendor lookups")
    s.add_argument("--json", action="store_true")
    s.add_argument("--relay-host", default=RELAY_HOST)
    s.add_argument("--relay-port", type=int, default=RELAY_PORT)
    s.add_argument("--relay-marker", default=RELAY_MARKER,
                   help="text that must appear if traffic was really forwarded")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("router", help="audit router config and per-client upload ratios")
    router_args(s)
    s.set_defaults(fn=cmd_router)

    s = sub.add_parser("log", help="analyse a router log for proxyware domains and beacons")
    s.add_argument("file", nargs="?", help="log file; omit to fetch from the router")
    s.add_argument("--save", help="write the fetched log here")
    router_args(s)
    s.set_defaults(fn=cmd_log)

    s = sub.add_parser("tv", help="list a smart TV's installed apps and flag "
                                   "publishers with a proxy-monetisation record")
    s.add_argument("ip", help="the TV's address (it must be switched ON)")
    s.add_argument("--platform", choices=["lg", "samsung"],
                   help="skip autodetection")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_tv)

    s = sub.add_parser("monitor", help="live per-client bandwidth")
    s.add_argument("--duration", type=int, default=300)
    s.add_argument("--interval", type=int, default=15)
    router_args(s)
    s.set_defaults(fn=cmd_monitor)

    a = p.parse_args(argv)
    o = Out(color=not a.no_color)
    load_env(getattr(a, "env_file", None))
    try:
        return a.fn(a, o)
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130

if __name__ == "__main__":
    sys.exit(main())
