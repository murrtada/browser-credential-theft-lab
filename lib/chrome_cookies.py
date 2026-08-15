"""Chromium (Chrome / Edge) cookie extraction.

Same goal as firefox_cookies, different obstacle: Chrome encrypts every
cookie value with AES (see chrome_crypto.py). The cookies table columns:

  host_key, name, encrypted_value, value, path, expires_utc,
  is_secure, is_httponly, samesite

Chrome stores times as microseconds since 1601-01-01 (Windows FILETIME),
which we convert to a POSIX-ish second count so the shared Cookie class
can classify it. Values are decrypted with the per-browser AES key.

Like Firefox, the dump works from a COPY of the DB in a temp dir because a
running browser locks the files (and newer Chrome keeps cookies in a
Network/ subfolder).
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from typing import Any

from .chrome_crypto import ChromeDecryptError, ChromeKeyError
from .firefox_cookies import Cookie, classify

_FILETIME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01

# SameSite integer values in Chrome's cookies table.
_SAMESITE = {0: "", 1: "no_restriction", 2: "lax", 3: "strict", 4: "lenient"}


def copy_db(profile_path: str) -> str | None:
    """Copy the Chrome cookies DB (+ WAL) into a temp dir.

    Chrome 114+ moved the DB into a Network/ subfolder; check both.
    Returns the temp directory, or None if the profile has no cookies DB.
    """
    candidates = [
        os.path.join(profile_path, "Cookies"),
        os.path.join(profile_path, "Network", "Cookies"),
    ]
    src = next((c for c in candidates if os.path.isfile(c)), None)
    if src is None:
        return None
    tmp = tempfile.mkdtemp(prefix="chrome-cookies-")
    dst = os.path.join(tmp, "Cookies")
    shutil.copy2(src, dst)
    wal = src + "-wal"
    if os.path.isfile(wal):
        try:
            shutil.copy2(wal, dst + "-wal")
        except OSError:
            pass
    return tmp


def _decrypt_or_placeholder(encrypted_value: bytes, value: str, key: bytes) -> str:
    """Decrypt a cookie value, falling back to plaintext for unencrypted rows.

    Some cookies are stored without encryption (encrypted_value empty); the
    plaintext lives in the `value` column. If decryption fails, we report a
    marker instead of crashing the whole dump.
    """
    if encrypted_value:
        try:
            return decrypt_value_text(encrypted_value, key)
        except (ChromeDecryptError, ChromeKeyError):
            return "*** decryption failed ***"
    return value


def decrypt_value_text(encrypted_value: bytes, key: bytes) -> str:
    """Thin wrapper so dump_cookies stays readable."""
    from .chrome_crypto import decrypt_value

    return decrypt_value(encrypted_value, key)


def dump_cookies(profile_path: str, key: bytes) -> list[Cookie]:
    """Extract every cookie from a Chromium profile, decrypted + tagged."""
    tmp = copy_db(profile_path)
    if tmp is None:
        return []
    try:
        db = os.path.join(tmp, "Cookies")
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT host_key, name, encrypted_value, value, path, "
                "expires_utc, is_secure, is_httponly, samesite "
                "FROM cookies ORDER BY host_key, name"
            ).fetchall()
        finally:
            conn.close()

        cookies: list[Cookie] = []
        for r in rows:
            host = r["host_key"]
            name = r["name"]
            enc = bytes(r["encrypted_value"] or b"")
            value = _decrypt_or_placeholder(enc, r["value"] or "", key)
            high, cat = classify(host, name)
            expiry = _chrome_epoch_to_unix(r["expires_utc"])
            cookies.append(
                Cookie(
                    host=host,
                    name=name,
                    value=value,
                    path=r["path"] or "",
                    expiry=expiry,
                    is_secure=bool(r["is_secure"]),
                    is_http_only=bool(r["is_httponly"]),
                    same_site=_SAMESITE.get(r["samesite"], ""),
                    high_value=high,
                    category=cat,
                )
            )
        return cookies
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _chrome_epoch_to_unix(expires_utc: Any) -> int:
    """Chrome expiry is microseconds since 1601-01-01; return seconds since 1970."""
    try:
        value = int(expires_utc or 0)
    except (TypeError, ValueError):
        return 0
    if value <= 0:
        return 0
    return int(value / 1_000_000 - _FILETIME_EPOCH_OFFSET)
