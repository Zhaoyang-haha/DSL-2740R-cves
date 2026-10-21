# VulDB Submission Sheet — DSL-2740R-cves

> Each vulnerability is submitted **separately** (one form per entry). Description is plain text
> (VulDB disables markup) — copy the fenced block verbatim, without the fence.

## Shared fields

| Field | Value |
|---|---|
| Vendor | `D-Link` (select the existing entry) |
| Product | `DSL-2740R` |
| Version or Commit | `EU_1.17` (latest released firmware; EOL) |

---

## Entry 1 — `Authorization` header buffer overflow (RomPager)

| Field | Value |
|---|---|
| Vulnerability | `Buffer Overflow (CWE-787)` |
| Advisory / Exploit URL | https://github.com/Zhaoyang-haha/DSL-2740R-cves/tree/main/FIND-0001-authorization-header-overflow |
| Request a CVE | ☑ checked |
| Vendor contacted beforehand | ☑ checked (only after the vendor e-mail is actually sent) |

**Description (paste as plain text):**

```
A buffer overflow vulnerability was discovered in D-Link DSL-2740R firmware EU_1.17 (the latest publicly released firmware for this model; product EOL). The Authorization HTTP header handler of the embedded RomPager web server base64-decodes the Basic credential and copies the username and password with an unbounded strcpy into two connection-structure fields located only 32 bytes apart. The existing 340-character token length check (the vendor fix for CVE-2014-9223) protects only the stack decoding buffer, not these structure fields. A username longer than 32 bytes overwrites adjacent connection state with attacker-controlled data (any byte except NUL, up to about 255 decoded bytes). Reproduction: send a single request to any URL with the header 'Authorization: Basic <base64 of a 200-byte username + ":p">' (270 base64 characters, passing the length check); the overflow corrupts the httpd parser state and denial of service results. An unauthenticated attacker on the LAN (or WAN if remote management is enabled) can trigger this with one request, regardless of URL or HTTP method, because the header handler runs before authentication. The issue was confirmed by function-level CPU emulation (Unicorn Engine) of the original, unmodified firmware code: 5/5 test cases showed controlled overwrites reaching up to 167 bytes past the field boundary. No physical device was tested and no device-level crash was observed; escalation analysis showed the corrupted fields contain no exploitable pointers and the only read-back paths are dead code, so the impact is denial of service. This is distinct from CVE-2014-9223: same function, different buffer, different missing check. Firmware MD5 780553118fec108509855bd6b4a82e4d. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (6.5). Discovered by Zimo-666 via static reverse engineering and function-level emulation.
```

---

## Entry 2 — `Content-Type` multipart boundary buffer overflow (RomPager)

| Field | Value |
|---|---|
| Vulnerability | `Buffer Overflow (CWE-787)` |
| Advisory / Exploit URL | https://github.com/Zhaoyang-haha/DSL-2740R-cves/tree/main/FIND-0003-content-type-multipart-boundary-overflow |
| Request a CVE | ☑ checked |
| Vendor contacted beforehand | ☑ checked (only after the vendor e-mail is actually sent) |

**Description (paste as plain text):**

```
A buffer overflow vulnerability was discovered in D-Link DSL-2740R firmware EU_1.17 (the latest publicly released firmware for this model; product EOL). The Content-Type HTTP header handler of the embedded RomPager web server copies the value of the boundary parameter of multipart/form-data content types with an unbounded strcpy into a connection-structure field designed to hold 70 bytes (the RFC 2046 boundary limit). The code performs no length check; the only constraint is the 641-byte header line buffer, so a boundary of up to about 595 bytes is accepted, overwriting about 530 bytes of the multipart parser working storage with attacker-controlled data (any byte except NUL, CR, LF). Reproduction: send a single request to any URL with the header 'Content-Type: multipart/form-data; boundary=' followed by 400 'A' characters; the parser then operates on corrupted state during body parsing of the same request and denial of service results. An unauthenticated attacker on the LAN (or WAN if remote management is enabled) can trigger this with one request, regardless of URL or HTTP method, because the header handler runs before authentication. The issue was confirmed by function-level CPU emulation (Unicorn Engine) of the original, unmodified firmware code: 4/4 test cases, with a 600-byte boundary shown to overflow 531 bytes past the field boundary under full attacker control. No physical device was tested and no device-level crash was observed; the overflowed region contains only data buffers (no pointers), and the file-write path behind multipart parsing requires authentication, so the impact is denial of service and parser-state confusion with low code-execution likelihood. Firmware MD5 780553118fec108509855bd6b4a82e4d. Proposed CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (6.5). Discovered by Zimo-666 via static reverse engineering and function-level emulation.
```

---

> **Evidence note.** Both issues were confirmed by function-level emulation of the original firmware
> code; no physical device was tested and no device-level crash was observed. The advisories and the
> descriptions state this limitation explicitly, and the CVSS scores reflect only the proven impact.
