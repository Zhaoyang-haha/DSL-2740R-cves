# DSL-2740R Security Advisories

> **Status:** CVE: Not assigned (identifier requested). Vendor notification: pending. Repository published for coordinated disclosure.

Public disclosure repository for security vulnerabilities independently discovered in the
**D-Link DSL-2740R (Hardware Revision A)** ADSL2+ gateway, firmware **EU_1.17**
(the latest and final publicly released firmware for this model; the product is EOL since 2020).

All findings were verified by executing the original, unmodified firmware machine code under
function-level CPU emulation (Unicorn Engine, MIPS32 big-endian). No physical device was tested;
this limitation is stated explicitly in each advisory.

| # | Advisory | Component | Type | Auth required | Status |
|---|----------|-----------|------|---------------|--------|
| 1 | [Authorization header buffer overflow](FIND-0001-authorization-header-overflow/) | RomPager HTTP header handler (FUN_801573ec) | CWE-787 Out-of-bounds Write | No (pre-auth) | Vendor notification pending |
| 2 | [multipart boundary buffer overflow](FIND-0003-content-type-multipart-boundary-overflow/) | RomPager HTTP header handler (FUN_80156a98) | CWE-787 Out-of-bounds Write | No (pre-auth) | Vendor notification pending |

## Affected firmware

- **EU_1.17** (confirmed, MD5 `780553118fec108509855bd6b4a82e4d`, obtained from the official
  D-Link FTP mirror ftp.dlink.de) — latest available version.
- **EU_1.15** and older: inferred affected with high confidence (EU_1.15 is a 2010-03-01 build,
  predating all RomPager security fixes); **not binary-verified** — the legacy image could not be
  obtained from any public mirror.

## Timeline

- 2026-10-12 — Vulnerabilities discovered and verified via emulation.
- 2026-10-13 — Public disclosure repository prepared; vendor notification pending.
- CVE identifiers requested via VulDB (CNA) — pending.

## Researcher

**Zimo-666** — independent security researcher.

All testing was performed in an isolated, authorized environment. The proof-of-concept scripts are
non-destructive and intended for authorized testing only.

> This repository is published and maintained by [@Zhaoyang-haha](https://github.com/Zhaoyang-haha)
on behalf of the research team. Research credit belongs to the discoverer named above.

---

## Repository files

| Path | Content |
|---|---|
| `FIND-0001-authorization-header-overflow/` | Advisory + `poc_find0001.py` — `Authorization` header overflow |
| `FIND-0003-content-type-multipart-boundary-overflow/` | Advisory + `poc_find0003.py` — `Content-Type` multipart boundary overflow |

The scripts perform a liveness probe, send one overflow request, then probe again. They write
nothing to flash and change no configuration. Authorized testing only.
