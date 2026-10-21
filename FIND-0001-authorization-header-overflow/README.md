# Pre-Authentication Buffer Overflow in the Authorization Header Handler of D-Link DSL-2740R (RomPager HTTP Server)

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

## Summary

A buffer overflow vulnerability was discovered in D-Link DSL-2740R firmware EU_1.17. The handler
for the HTTP `Authorization:` header, registered in the header dispatch table of the embedded
Allegro RomPager 4.07 web server, base64-decodes the Basic credential and then copies the username
and password with an **unbounded `strcpy`** into two connection-structure fields located only
**32 bytes apart**. An unauthenticated remote attacker can overwrite adjacent connection-state
fields with up to ~255 bytes of arbitrary (non-NUL) data using a single HTTP request to any URL,
causing denial of service.

## Affected Product

- Vendor: D-Link
- Product: DSL-2740R (Hardware Revision A)
- Firmware: EU_1.17 — **the latest publicly released firmware** for this model (product EOL since 2020).
  Firmware MD5 `780553118fec108509855bd6b4a82e4d`, obtained from the official mirror ftp.dlink.de.
- Affected range (inferred, not binary-verified): EU_1.15 and older. EU_1.15 is a 2010-03-01 build
  that predates all RomPager security fixes, so it is expected to be affected with high confidence.

## Vulnerability Details

- Type: CWE-787 (Out-of-bounds Write) / CWE-120 (Classic Buffer Overflow)
- Location: `FUN_801573ec` @ firmware offset 0x801573ec — the `authorization` header handler
  registered by `FUN_80157764` in the RomPager header dispatch table (table @ 0x80381328).
- Root cause: the handler enforces a 340-character limit on the base64 token. That limit is the
  vendor-applied fix for CVE-2014-9223 and only protects the 256-byte **stack** decoding buffer.
  After decoding, the username and password are copied into the heap-like per-connection structure
  with an unbounded copy primitive (`FUN_8025c7d0`, confirmed to be a plain strcpy), into fields
  at `conn+0x3d60` (username) and `conn+0x3d80` (password), spaced only 0x20 (32) bytes apart.
  Any username longer than 32 bytes overflows into the password field and beyond.

Cleaned decompilation of the vulnerable tail of `FUN_801573ec`:

```c
param_2 = param_2 + (param_3 & 0xffff) + 1;      // skip the "Basic " scheme word
uVar1 = strlen_(param_2);
if (0x154 < uVar1) {                             // 340-char check == CVE-2014-9223 fix
    log_("ProcessAuthorization: theToken too long (%u)");
    return;                                      // protects ONLY the stack buffer below
}
base64_decode(param_2, uVar1, acStack_108);      // 256-byte stack buffer (bounded by the check)
iVar2 = strchr_(acStack_108, ':');               // 0x3a
pcVar3 = acStack_108 + iVar2;                    // -> password
if (iVar2 != 0) { acStack_108[iVar2] = '\0'; }
strcpy(param_1 + 0x3d60, acStack_108);           // username -> conn+0x3d60  *** UNBOUNDED ***
strcpy(param_1 + 0x3d80, pcVar3);                // password -> conn+0x3d80  *** UNBOUNDED ***
```

The dispatch convention was confirmed statically: the header dispatcher `FUN_801566fc` invokes
`handler(conn, value_start, first_word_length)`, and header handlers run during header parsing —
**before** the authentication check (state 9 of the request state machine `FUN_80157c90`) and
independently of the request URL or method.

## Proof of Concept (non-destructive)

A single HTTP request with an over-long Basic username (kept ≤ 340 base64 characters so it passes
the CVE-2014-9223 length check):

```bash
python3 -c "import base64;print(base64.b64encode(b'U'*200+b':p').decode())"
# -> 270 chars, decodes to 202 bytes: a 200-byte username + ":p"

curl -v -H "Authorization: Basic <token>" http://<router-ip>/
```

Expected (vulnerable): the username copy writes 200 bytes into a 32-byte field, overflowing
137 bytes past `conn+0x3da0` with attacker-controlled data; the corrupted connection state
(parser error-code word at `conn+0x3dd8`, content-type buffer at `conn+0x3da0`, and following
fields) breaks the httpd request state machine — the web service stops responding / the device
reboots. A normal-length credential (`admin:admin`) is processed without any overflow (control
group).

A ready-made non-destructive script is provided: [`poc_find0001.py`](poc_find0001.py). It performs
a liveness probe, sends one overflow request, and probes again; it writes nothing to flash and
changes no configuration.

### Verification evidence (function-level emulation of the original firmware code)

The overflow was verified dynamically by executing the unmodified firmware function
`FUN_801573ec` under Unicorn Engine 2.1.4 (MIPS32 BE), with an instrumented connection-structure
memory region. 5/5 test cases confirmed the overflow:

| Case (decoded user:pass) | Result |
|---|---|
| `admin:admin` (11 B) | Normal write, no overflow (designed behavior) |
| `'A'*64 : short` (70 B) | 1 byte overflows past `conn+0x3da0` |
| `'U'*200 : p` (202 B) | **137 bytes overflow past `conn+0x3da0`, up to `conn+0x3E29`, fully controlled** |
| `admin : 'P'*150` (156 B) | **119 bytes overflow, up to `conn+0x3E17`, fully controlled** |
| `'X'*230 : 'Y'*12` (243 B) | **167 bytes overflow, up to `conn+0x3E47`, fully controlled** |

Theoretical maximum: a 340-character base64 token decodes to ≤ 255 bytes, covering up to
`conn+0x3E5F`; base64 transport permits any byte value except NUL.

**Honesty note:** no physical device was available. All dynamic evidence comes from function-level
emulation of the original firmware machine code; the full socket-to-dispatcher chain was not
emulated, and a device-level crash was not observed.

## Impact

- Attacker profile: unauthenticated, adjacent network (LAN). Reachable from the internet only if
  remote management is enabled (disabled by default on this class of device).
- Prerequisites: none (the header handler runs before authentication; any URL, any method).
- Consequence: remote memory corruption of the httpd connection state. The overwritten region
  contains the form-parser error-code word (`conn+0x3dd8`) and parser working storage; corruption
  deterministically disrupts request processing → **denial of service** (web service crash /
  device reboot). Escalation analysis showed the corrupted fields hold no exploitable pointers and
  the only read-back paths of the error-code field are dead code, so information disclosure and
  code execution are assessed as not reachable via this overflow.
- Distinct from CVE-2014-9223: same function, **different buffer, different missing check**
  (CVE-2014-9223 was a Digest-authentication overflow fixed by the 340-character limit; this issue
  is the post-fix unbounded strcpy into 32-byte-spaced structure fields).

## CVSS 3.1

**6.5** — `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

Justification: adjacent-network, unauthenticated, single-request trigger with demonstrated
availability-affecting memory corruption on the original firmware code. Scored on demonstrated
impact (DoS); confidentiality/integrity impact not claimed (no exploitable pointer in the overflow
region, read-back paths are dead code). Device-level crash was not observed on hardware
(no physical device available); if scored strictly on hardware-observed effects only, the
conservative alternative is `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` (3.5).

## Discovery

Discovered by Zimo-666 on 2026-10-12 via static reverse engineering (Ghidra) and function-level
dynamic verification (Unicorn Engine) of the official EU_1.17 firmware image.
Vendor notified: pending (see repository timeline).
