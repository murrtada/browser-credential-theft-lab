"""Chrome/Chromium credential decryption (the crypto core).

Contrast with Firefox: Chrome encrypts EVERYTHING. Cookies and saved
passwords are AES-encrypted blobs in SQLite; the AES key itself is
wrapped by the operating system. So Chrome decrypt is a two-step OS-bound
process instead of a plaintext file read -- this is the whole point of the
technique you're studying here.

Step 1 - get the AES key.
  * The key is stored (DPAPI-encrypted, on Windows) in the "Local State"
    JSON file at the browser's User Data root, under
    `os_crypt.encrypted_key` (base64, "DPAPI" prefix).
  * `CryptUnprotectData` unwraps it back to the 32-byte AES key. DPAPI
    binds the key to the Windows user + login session: decryption only
    works on the same machine, as the same user. That is a real security
    property of Chrome on Windows (a stolen DB is useless without the
    user's DPAPI context).

Step 2 - decrypt the cookie / login value.
  * Chrome < 80:  `v1` prefix, AES-128-CBC (first 16 bytes of the key),
                 IV = 16 bytes after the prefix, PKCS7 padding.
  * Chrome >= 80: `v10` prefix, AES-256-GCM (full 32-byte key),
                 nonce = 12 bytes after the prefix, 16-byte auth tag.

Linux / macOS note: there the key is held by the OS keyring (Secret
Service / Keychain) rather than DPAPI. This module raises a clear error
for those paths; see README.md for the supported matrix.
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes
import json
import os
import platform
import sys

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover - exercised when pycryptodome is absent
    _HAS_CRYPTO = False

SYSTEM = platform.system()


class ChromeKeyError(Exception):
    """Could not recover the AES key (unsupported OS or missing Local State)."""


class ChromeDecryptError(Exception):
    """A value blob could not be decrypted with the recovered key."""


class _DataBlob(ctypes.Structure):
    """Windows DATA_BLOB: { DWORD cbData; BYTE *pbData; }."""

    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def dpapi_unprotect(blob: bytes) -> bytes:
    """Unwrap a DPAPI-protected blob via CryptUnprotectData (Windows only)."""
    if not (sys.platform.startswith("win") or SYSTEM == "Windows"):
        raise ChromeKeyError(
            "DPAPI-wrapped key found, but this is not Windows. "
            "On Linux the Chrome key lives in the Secret Service keyring, "
            "on macOS in the Keychain -- not supported by this module yet."
        )
    if not _HAS_CRYPTO:
        raise ChromeKeyError(
            "pycryptodome is required for Chrome support: pip install -r requirements.txt"
        )

    buf = ctypes.create_string_buffer(blob, len(blob))
    src = _DataBlob(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
    dst = _DataBlob()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(src),  # pDataIn
        None,               # ppszDataDescr
        None,               # pOptionalEntropy
        None,               # pvReserved
        None,               # pPromptStruct
        0,                  # dwFlags
        ctypes.byref(dst),  # pDataOut
    )
    try:
        if not ok:
            raise ChromeKeyError(
                "CryptUnprotectData failed (code %s). Chrome key is bound to "
                "the Windows user/session -- run this as the same user." % ctypes.windll.kernel32.GetLastError()
            )
        out = ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        if dst.pbData:
            ctypes.windll.kernel32.LocalFree(dst.pbData)
    return out


def local_state_path(root: str) -> str:
    """Path to the browser's Local State file (sibling of the profile dirs)."""
    return os.path.join(root, "Local State")


def load_local_state(root: str) -> dict:
    """Read the browser root's Local State JSON."""
    path = local_state_path(root)
    if not os.path.isfile(path):
        raise ChromeKeyError(f"Local State not found at {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def unwrap_wrapped_key(raw: bytes) -> bytes:
    """Unwrap an `os_crypt.encrypted_key` value (already base64-decoded).

    Windows layout: ``b"DPAPI" + <DPAPI-wrapped key>``. Anything else is a
    Linux keyring / macOS Keychain layout, which this module does not support.
    """
    if raw.startswith(b"DPAPI"):
        return dpapi_unprotect(raw[len(b"DPAPI"):])
    raise ChromeKeyError(
        "Unsupported encrypted_key scheme (prefix %r). Only the Windows "
        "DPAPI layout is supported; Linux keyring / macOS Keychain are not."
        % raw[:5]
    )


def get_key(root: str) -> bytes:
    """Recover the 32-byte AES key for a Chrome user-data root.

    Windows: DPAPI-unwrap `os_crypt.encrypted_key`.
    """
    state = load_local_state(root)
    enc = state.get("os_crypt", {}).get("encrypted_key", "")
    if not enc:
        raise ChromeKeyError("No os_crypt.encrypted_key in Local State")
    return unwrap_wrapped_key(base64.b64decode(enc))


def decrypt_value(encrypted: bytes, key: bytes) -> str:
    """Decrypt one Chrome cookie/password value blob into UTF-8 text."""
    if not _HAS_CRYPTO:
        raise ChromeDecryptError("pycryptodome is required for Chrome support")

    try:
        if encrypted.startswith(b"v10"):
            # Chrome >= 80: AES-256-GCM. Layout: v10(3) | nonce(12) | ct | tag(16).
            nonce = encrypted[3:15]
            ciphertext = encrypted[15:-16]
            tag = encrypted[-16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plain = cipher.decrypt_and_verify(ciphertext, tag)
            return plain.decode("utf-8")

        if encrypted.startswith(b"v1"):
            # Chrome < 80: AES-128-CBC. Layout: v1(2) | iv(16) | ct (PKCS7).
            iv = encrypted[2:18]
            ciphertext = encrypted[18:]
            cipher = AES.new(key[:16], AES.MODE_CBC, iv=iv)
            return unpad(cipher.decrypt(ciphertext), 16).decode("utf-8")

        raise ChromeDecryptError(
            f"Unrecognized Chrome encryption prefix: {encrypted[:4]!r}"
        )
    except (ValueError, UnicodeDecodeError) as exc:
        # pycryptodome raises bare ValueError on MAC/padding failures and on
        # decode errors when the key does not match. Surface it as our type.
        raise ChromeDecryptError(
            f"Decryption failed (likely wrong key or tampered blob): {exc}"
        ) from exc
