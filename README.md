# browser-credential-theft-lab

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│   ███████╗██╗██████╗ ███████╗███████╗ ██████╗ ██╗  ██╗                         │
│   ██╔════╝██║██╔══██╗██╔════╝██╔════╝██╔═══██╗██║ ██╔╝                         │
│   █████╗  ██║██████╔╝█████╗  █████╗  ██║   ██║█████╔╝                          │
│   ██╔══╝  ██║██╔══██╗██╔══╝  ██╔══╝  ██║   ██║██╔═██╗                          │
│   ██║     ██║██║  ██║███████╗███████╗╚██████╔╝██║  ██╗                         │
│   ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝                         │
│                                                                              │
│   ██████╗ ██████╗ ███████╗██████╗ ███████╗     ██╗      █████╗ ██████╗        │
│   ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝     ██║     ██╔══██╗██╔══██╗       │
│   ██████╔╝██████╔╝█████╗  ██║  ██║███████╗     ██║     ███████║██████╔╝       │
│   ██╔══██╗██╔══██╗██╔══╝  ██║  ██║╚════██║     ██║     ██╔══██║██╔══██╗       │
│   ██║  ██║██████╔╝███████╗██████╔╝███████║     ███████╗██║  ██║██████╔╝       │
│   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚═════╝ ╚══════╝     ╚══════╝╚═╝  ╚═╝╚═════╝        │
│                                                                              │
│          Browser credential storage internals · localhost-only lab           │
│                  DPAPI · AES-GCM (v10/v1) · NSS / PK11SDR                    │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

An educational study tool that explains **how browsers store your credentials**
— and what happens when a real credential stealer reads them — entirely on your
**own machine**. It dumps **session cookies** and **saved logins** from
**Firefox** (zero dependencies) and **Chrome / Edge** (pycryptodome) on your own
account, plus a single-file lab that emulates the **harvest → phone-home**
chain a real stealer uses — **without ever sending a secret off your machine**.

> ⚠️ **AUTHORIZED USE ONLY.** Only run this on machines you own or are
> explicitly authorized to test. A cookie dump is the same thing a
> credential-stealing malware does on a victim's machine — the only lawful
> difference is whose machine it is. Never replay a harvested session on an
> account that isn't yours. Delete report files when you're done with them.

---

## What you'll learn

1. **Why session cookies are the real prize.** A logged-in site stores its
   session token in a cookie (e.g. Facebook `c_user` + `xs`, GitHub
   `user_session`, LinkedIn `li_at`). The cookie value *is* the session — it's a
   **bearer token** that works on its own.
2. **How each browser protects them — and where the protection stops:**

   | Fact | Consequence |
   |------|-------------|
   | Firefox persists every cookie to `cookies.sqlite` in **plaintext**. | No key, no password, no login needed — read the file, read the sessions. |
   | Firefox saved logins are encrypted by NSS (`PK11SDR_Decrypt`). | The profile's own key material unwraps them; a Primary Password gates it. |
   | Chrome/Edge encrypt cookies/logins with **DPAPI + AES-GCM**, but the key is unwrappable by the same Windows user. | On your own account the key unwraps transparently — that's the whole point of DPAPI. |
   | The dump is **fully offline** (disk-only, no network). | The browser doesn't need to be open or logged in at harvest time. |
   | `HttpOnly` only stops *JavaScript* (XSS) from reading cookies. | It does nothing against direct database access. |
   | Steal the cookie → paste it into your own browser profile. | The site accepts it and you're logged in as the victim. |

3. **The exact crypto.** Chrome/Edge "v10" keys use AES-256-GCM
   (12-byte nonce, 16-byte tag), "v1" keys use AES-128-CBC (16-byte IV) — the
   layouts the `test_chrome_crypto` suite pins down. Firefox logins go through
   the browser's own NSS library rather than re-implementing `key4.db` unwrap.

### The cookie ≠ password distinction
- **Session cookies** (this tool's main event): exist for every logged-in site,
  harvested with zero crypto (Firefox) or OS-key crypto (Chrome/Edge).
- **Saved logins** (`logins.json` / `Login Data`): only exist if the user chose
  "remember password".

This is why stolen session cookies are sold/abused: a cookie dump is a
one-step account takeover that leaves no password behind.

---

## Quickstart

### Firefox (no `pip install` needed — stdlib only)

```bash
python3 creds_dumper.py                          # all profiles, masked previews
python3 creds_dumper.py --list                   # show discovered profiles
python3 creds_dumper.py --plain                  # full values on console too
python3 creds_dumper.py --profile /path/to/profile --out /tmp/out
```

**Close the browser you're dumping BEFORE running.** Both Firefox and Chrome
file-lock their SQLite databases and keep session-only cookies in memory until
a clean shutdown — dumping after exit gets the *complete* set.

### Chrome / Edge

```bash
pip install -r requirements.txt                  # pycryptodome
python3 creds_dumper.py --browser chrome
python3 creds_dumper.py --browser all
```

On Windows, Chrome's key is protected by DPAPI, which unwraps under the
*same Windows user* that created it (your own account — exactly how the tool
is meant to be used). On Linux/macOS the key is an `AES-256-GCM`-wrapped secret
in `Local State` and decrypts with the `v10`/`v1` scheme the `test_chrome_crypto`
suite verifies. Edge/Brave/Opera follow the same Chromium layout and are
covered for free via `--browser edge`.

### Primary Password (Firefox)

If a profile has a Primary Password, the script prompts for it
(`--password` to pass it on the CLI). No password = logins skipped,
cookies still dumped.

## Output handling (safe by default)

- Console prints **masked previews** (`value[0:8]…`); full secrets go only to a
  local JSON report in `report/creds_<timestamp>.json` (gitignored).
- `--plain` prints full values to the console too (fine on your own box).

---

## The localhost C2 simulation

`docs/C2-LAB.md` walks through the full **stealer chain** — a single-file
Windows deliverable (`c2_sim.cmd`) that harvests **Firefox + Chrome + Edge**
cookies and logins (pure PowerShell, zero installs — Firefox via NSS, Chrome/
Edge via DPAPI + AES-GCM over `bcrypt.dll`) and POSTs the report over
**Windows loopback** to a receiver on the *same physical host*
(`kali_receiver.py`, WSL2 localhost forwarding).

**The exfil target is hard-gated to localhost** — the payload refuses to send
anything anywhere except `http://127.0.0.1` / `http://localhost`. Nothing
leaves the machine, no internet is involved.

| File | What it is |
|------|-----------|
| `c2_sim.cmd` | One-file localhost lab: self-extracts a PowerShell payload, exfils over loopback. |
| `c2_payload.ps1` | The embedded payload itself — runnable directly with flags. Dumps Firefox + Chrome + Edge cookies/logins. |
| `kali_receiver.py` | Loopback receiver (run on the Kali/WSL side of the same machine). |
| `docs/C2-LAB.md` | Full lab walkthrough + real-world exfil-channel study notes. |

---

## Project layout

```
creds_dumper.py          # entry point: profile discovery + dump (all browsers)
lib/
  profiles.py            # profiles.ini parsing (Win %APPDATA%, Linux ~/.mozilla)
  firefox_cookies.py     # plaintext cookie dump + high-value session tagging
  nss.py                 # ctypes bridge to NSS (PK11SDR_Decrypt) for logins
  firefox_logins.py      # logins.json -> NSS decrypt
  chrome_crypto.py       # DPAPI unwrap + v10 AES-GCM / v1 AES-CBC decrypt
  chrome_profiles.py     # Chromium User Data / profile discovery
  chrome_cookies.py      # Chrome/Edge Cookies DB read + decrypt
  chrome_logins.py       # Chrome/Edge Login Data read + decrypt
  report.py              # masked console + local JSON report
tests/
  test_profiles.py       # Firefox discovery against a LIVE profile
  test_cookies.py        # Firefox cookie dump against a LIVE profile
  test_nss.py            # decrypt REAL Firefox 59 + 144 fixtures (bundled)
  test_chrome_crypto.py  # v10/v1 AES roundtrip + wrong-key rejection (CI-safe)
  test_chrome_profiles.py# discovery against a synthetic User Data tree (CI-safe)
```

## Tests

CI-safe suites (run in CI; no live browser needed):

```bash
python3 tests/test_nss.py              # decrypts bundled real firefox_decrypt fixtures
python3 tests/test_chrome_crypto.py    # v10 GCM + v1 CBC roundtrip, wrong-key/prefix rejection
python3 tests/test_chrome_profiles.py  # synthetic profile discovery
```

Live-profile suites (need a real browser install on the test box):

```bash
python3 tests/test_profiles.py         # discovery against profiles.ini
python3 tests/test_cookies.py          # dump against a live cookies.sqlite
```

`test_nss.py` needs `libnss3` on Linux (`apt install libnss3`), `nss3.dll` on
Windows (any modern Firefox install provides it), or the dylib from the macOS
Firefox bundle. `test_chrome_crypto.py` needs `pycryptodome`. The DPAPI unwrap
step itself is Windows-only and validated manually on the target Windows box —
everything downstream of the key is covered by the CI suites.

## Supported OS / browser matrix

| OS | Firefox cookies | Firefox logins | Chrome/Edge cookies | Chrome/Edge logins |
|----|-----------------|----------------|---------------------|--------------------|
| Windows 11 | ✅ | ✅ (nss3.dll) | ✅ (DPAPI) | ✅ (DPAPI) |
| Linux | ✅ | ✅ (libnss3) | ✅ (Local State key) | ✅ (Local State key) |
| macOS | ✅ | ✅ (libnss3.dylib) | ✅ | ✅ |

---

## License

MIT — see [LICENSE](LICENSE). This is an **educational** project: a study aid
for learning how session hijacking and credential-stealing work, meant for
your own machines and authorized labs. The authors are not responsible for
misuse.
