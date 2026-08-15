"""Output: redacted console preview + full local report file.

Security-by-default for a credential harvester:
  * Console shows metadata and MASKED secrets (host, cookie name,
    first-8-char preview, flags, expiry) so you can see what was found
    without splashing tokens all over your terminal / logs.
  * Full secrets go ONLY to a local JSON report file.
  * --plain on the CLI overrides and prints full values too (fine on a
    machine you own, and helpful while learning).
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Any

from .firefox_cookies import Cookie
from .firefox_logins import Login


def mask(value: str, keep: int = 8, cap: int = 16) -> str:
    """Preview: first `keep` chars + capped run of asterisks.

    Avoids flooding the terminal when a cookie value is 400+ chars.
    """
    if len(value) <= keep:
        return value
    tail = "*" * min(cap, len(value) - keep)
    return value[:keep] + "…" + tail


def mask_login(value: str) -> str:
    if not value:
        return value
    return value[0] + "*" * (len(value) - 1)


def print_cookie_console(c: Cookie, plain: bool) -> None:
    value = c.value if plain else mask(c.value)
    flags = "".join(
        ["S" if c.is_secure else "-", "H" if c.is_http_only else "-"]
    )
    tag = f"[{c.category}]" if c.category else ""
    print(f"  {c.host:<45} {c.name:<32} {value:<30} {flags} {c.expiry_hint():<10} {tag}")


def print_login_console(l: Login, plain: bool) -> None:
    user = l.username if plain else mask_login(l.username)
    pwd = l.password if plain else mask_login(l.password)
    print(f"  {l.hostname:<55} user={user:<25} pass={pwd}")


def write_report(profiles: list[dict[str, Any]], out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    fname = f"creds_{datetime.datetime.now():%Y%m%d_%H%M%S}.json"
    path = os.path.join(out_dir, fname)
    payload = {
        "tool": "browser-credential-theft-lab",
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "note": "Authorized-machines only. Full secrets are in this file; "
                "keep it safe and delete it when done.",
        "profiles": profiles,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return path
