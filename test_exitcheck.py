#!/usr/bin/env python3
"""Self-check: python3 test_exitcheck.py

The probe's job is to say RELAY only on proof. The fakes below include the
exact false positive that motivated the design - a service that answers
"200 OK" to CONNECT without being a proxy at all (Amazon's Alexa stack does
this on port 9080). If that ever classifies as RELAY again, this fails.
"""
import base64, socket, struct, threading, time
import exitcheck as E

MARKER = "Example Domain"
PAGE = (f"HTTP/1.1 200 OK\r\nContent-Length: {len(MARKER) + 13}\r\n\r\n"
        f"<html>{MARKER}</html>").encode()


def serve(handler):
    """Start a one-shot threaded server, return its port."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            def run(s=c):
                try:
                    handler(s)
                except OSError:
                    pass          # client hung up mid-probe; that is the point
                finally:
                    s.close()
            threading.Thread(target=run, daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return port


def http_relay(s):                      # a genuine forward proxy
    req = s.recv(4096)
    if req.startswith(b"GET http://"):
        s.sendall(PAGE)


def http_relay_root(s):                 # serves the marker on a plain GET /
    if s.recv(4096).startswith(b"GET "):
        s.sendall(PAGE)


def fake_200(s):                        # the Alexa/NRDP false positive
    while True:
        if not s.recv(4096):
            return
        s.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nstatus=ok")


def socks5(relay: bool):
    def h(s):
        if s.recv(8)[:1] != b"\x05":
            return
        s.sendall(b"\x05\x00")
        req = s.recv(512)
        if not req[:2] == b"\x05\x01":
            return
        if not relay:
            s.sendall(b"\x05\x09\x00\x01" + b"\x00" * 6)   # custom refusal
            return
        s.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        if s.recv(4096).startswith(b"GET "):
            s.sendall(PAGE)
    return h


def ws_echo(s):
    """Server side of RFC 6455, just enough to echo one client's text frames."""
    import hashlib
    req = b""
    while b"\r\n\r\n" not in req:
        d = s.recv(4096)
        if not d:
            return
        req += d
    key = next(l.split(b": ", 1)[1] for l in req.split(b"\r\n")
               if l.lower().startswith(b"sec-websocket-key"))
    acc = base64.b64encode(hashlib.sha1(
        key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()).decode()
    s.sendall(f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
              f"Connection: Upgrade\r\nSec-WebSocket-Accept: {acc}\r\n\r\n".encode())
    buf = b""
    while True:
        d = s.recv(65536)
        if not d:
            return
        buf += d
        while len(buf) >= 2:
            n, off = buf[1] & 0x7F, 2
            if n == 126:
                n = struct.unpack(">H", buf[2:4])[0]; off = 4
            elif n == 127:
                n = struct.unpack(">Q", buf[2:10])[0]; off = 10
            masked = buf[1] & 0x80
            need = off + (4 if masked else 0) + n
            if len(buf) < need:
                break
            m = buf[off:off + 4] if masked else b"\x00\x00\x00\x00"
            body = bytes(c ^ m[i % 4] for i, c in
                         enumerate(buf[off + 4:off + 4 + n] if masked
                                   else buf[off:off + n]))
            buf = buf[need:]
            hdr = b"\x81" + (bytes([len(body)]) if len(body) < 126
                             else b"\x7e" + struct.pack(">H", len(body)))
            s.sendall(hdr + body)          # server frames are unmasked


def probe(port):
    return E.probe_proxy("127.0.0.1", port, "127.0.0.1", 80, MARKER, timeout=3)


def main():
    # --- the probe decision table -------------------------------------
    v, d = probe(serve(http_relay))
    assert v == "RELAY", f"forward proxy must be RELAY, got {v} {d}"

    v, d = probe(serve(fake_200))
    assert v != "RELAY", f"200-to-CONNECT must NOT be RELAY, got {v} {d}"

    v, d = probe(serve(socks5(relay=True)))
    assert v == "RELAY", f"relaying SOCKS5 must be RELAY, got {v} {d}"

    v, d = probe(serve(socks5(relay=False)))
    assert v == "GATED", f"refusing SOCKS5 must be GATED, got {v} {d}"

    # --- preflight: the oracle must be validated before it is trusted ---
    # A reachable target serving the marker => usable. Anything else => not,
    # because an unreachable oracle turns every open relay into a clean result.
    port = serve(http_relay_root)
    assert E.preflight("127.0.0.1", port, MARKER) is True
    assert E.preflight("127.0.0.1", port, "marker-that-is-absent") is False
    assert E.preflight("127.0.0.1", 1, MARKER) is False, "closed port must fail"

    # --- beacon detection ---------------------------------------------
    t0 = 1_700_000_000
    assert E.find_beacon([t0 + i * 300 for i in range(40)])[0] == 300
    jitter = [0, 7, 301, 904, 1500, 1501, 4000, 9999, 10001, 23000, 40000, 70000, 70001]
    assert E.find_beacon([t0 + x for x in jitter]) is None, "irregular must not beacon"
    assert E.find_beacon([t0, t0 + 300]) is None, "too few samples"

    # --- domain matching ----------------------------------------------
    assert E.proxyware_hit("tm-sdk.brightdata.com") == "brightdata.com"
    assert E.proxyware_hit("BRIGHTDATA.COM") == "brightdata.com"
    assert E.proxyware_hit("notbrightdata.com") is None, "must not substring-match"
    assert E.proxyware_hit("example.com") is None

    # --- mac helpers ---------------------------------------------------
    assert E.norm_mac("0:1:2:a:bb:c") == "00:01:02:0A:BB:0C"
    assert E.is_randomized("02:00:5E:00:53:0A") is True
    assert E.is_randomized("00:00:5E:00:53:0A") is False

    # --- log parsing + end to end --------------------------------------
    log = "\n".join(
        [f"0{d}.10.2026 19:1{d}:29 ERR DNS 0 DNS name resolution failure (ok.example.com)"
         for d in range(1, 6)] +
        [f"03.10.2026 {h:02d}:05:00 ERR DNS 0 DNS name resolution failure (x.getgrass.io)"
         for h in range(24)] +
        ["03.10.2026 22:35:19 ERR WIFI 0 A device failed to connect to SSID "
         "(02:00:5E:00:53:0A) because it provided incorrect login information."])
    r = E.analyse_log(log)
    assert r["records"] == 30, r["records"]
    assert [h[1] for h in r["proxyware"]] == ["getgrass.io"], r["proxyware"]
    assert len(r["wifi_auth_failures"]) == 1
    assert any(dom == "x.getgrass.io" and abs(p - 3600) < 1 for dom, _, p, _ in r["beacons"])

    # --- publisher flagging: vendor/appId only, never the title ----------
    assert E.flag_app({"title": "Pac-Man", "vendor": "PlayWorks Digital",
                       "id": "com.playworks.app.pacman"})[0] == "playworks"
    assert E.flag_app({"title": "X", "vendor": "Bright Data Ltd",
                       "id": "com.x"})[0] == "bright data"
    assert E.flag_app({"title": "Netflix", "vendor": "LG", "id": "netflix"})[0] is None
    # a title must never trigger a flag on its own
    assert E.flag_app({"title": "Massive Attack Radio", "vendor": "Indie Label",
                       "id": "com.indie.radio"})[0] is None, "title must not match"
    assert E.flag_app({"title": "Honeygain", "vendor": "", "id": ""})[0] is None

    # --- websocket client: handshake + masked frame round trip -----------
    port = serve(ws_echo)
    w = E.WS("127.0.0.1", port, "/", timeout=10)
    w.send({"hello": "tv"})
    assert w.recv() == {"hello": "tv"}
    big = {"pad": "x" * 500}          # exercises the 16-bit length path
    w.send(big)
    assert w.recv() == big
    w.close()

    # --- ratio heuristic -------------------------------------------------
    assert E.ratio_verdict(20_000_000_000, 2_000_000_000)[0] == "normal"
    assert E.ratio_verdict(1_000_000_000, 1_200_000_000)[0] == "suspect"
    assert E.ratio_verdict(1_000_000_000, 600_000_000)[0] == "watch"
    assert E.ratio_verdict(1000, 1000)[0] == "idle"

    print("all checks passed")


if __name__ == "__main__":
    main()
