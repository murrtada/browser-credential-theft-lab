"""NSS bridge -- the only piece of real crypto in this project.

Firefox encrypts saved passwords (logins.json) with the "Software
Security Device" (a token inside Firefox's own NSS crypto library).
The encryption is SDR (Software Development Randomizer -- a legacy name
for the NSS "slot default" encryption): a random key lives in the
profile's key4.db and is used to encrypt each password with 3DES/AES.

Two ways to decrypt:
  1. Reimplement the key4.db ASN.1 unwrap in pure Python.
     Fragile: the key-derivation byte layout changes between NSS
     versions (we found a newer schema variant in the test profile).
  2. Ask NSS itself to decrypt (what firefox_decrypt does): load the
     NSS shared library (nss3.dll on Windows / libnss3.so on Linux),
     point it at the profile folder with NSS_Init, then call
     PK11SDR_Decrypt. NSS does the key management for us and it works
     for every Firefox version AND honours the Primary Password.

We use option 2. The price is a ctypes wrapper around a handful of
NSS functions -- which is exactly how production tools do it.

This file needs no third-party packages (stdlib ctypes only).
"""

from __future__ import annotations

import ctypes as ct
import os
import platform
import shutil
import sys
from base64 import b64decode, b64encode

SYSTEM = platform.system()
DEFAULT_ENCODING = "utf-8"


class NSSNotFoundError(Exception):
    pass


class NSSDecryptError(Exception):
    pass


def _candidates() -> list[str]:
    """Where NSS could live, per OS. We want the user's own Firefox lib."""
    env = os.environ.get("NSS_LIB_PATH")
    cands: list[str] = [env] if env else []
    if SYSTEM == "Windows":
        name = "nss3.dll"
        roots = [
            os.path.expanduser(r"~\\AppData\\Local\\Mozilla Firefox"),
            r"C:\\Program Files\\Mozilla Firefox",
            r"C:\\Program Files (x86)\\Mozilla Firefox",
            r"C:\\Program Files\\Firefox Developer Edition",
            r"C:\\Program Files (x86)\\Firefox Developer Edition",
            r"C:\\Program Files\\Mozilla Thunderbird",
            r"C:\\Program Files (x86)\\Mozilla Thunderbird",
            "",  # current dir / PATH
        ]
    elif SYSTEM == "Darwin":
        name = "libnss3.dylib"
        roots = [
            "/Applications/Firefox.app/Contents/MacOS",
            "/usr/local/lib",
            "/opt/homebrew/lib",
            "",
        ]
    else:
        name = "libnss3.so"
        roots = [
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib64",
            "/usr/lib64/nss",
            "/usr/lib",
            "/usr/lib/nss",
            "/usr/local/lib",
            "",
        ]
    for root in roots:
        if root:
            cands.append(os.path.join(root, name))
        else:
            cands.append(name)
    return cands


def load_nss() -> ct.CDLL:
    """Locate and load the NSS shared library."""
    errors: list[str] = []
    for cand in _candidates():
        try:
            lib = ct.CDLL(cand)
            return lib
        except OSError as exc:
            errors.append(f"{cand}: {exc}")
    raise NSSNotFoundError(
        "Could not locate NSS. On Windows install Firefox, or set "
        "NSS_LIB_PATH to the folder holding nss3.dll.\nTried:\n  "
        + "\n  ".join(errors)
    )


class NSS:
    """Thin ctypes wrapper around the NSS functions we need.

    For fun/learning, compare with the OS-level routine these wrap:
      PK11SDR_Decrypt   -> crypto/softoken's SDR, AES/3DES + PKCS7 padding
      PK11_NeedLogin    -> checks whether a Primary Password protects the token
    """

    class SECItem(ct.Structure):
        """{ SECItemType type; unsigned char *data; unsigned int len; }"""
        _fields_ = [
            ("type", ct.c_uint),
            ("data", ct.c_char_p),
            ("len", ct.c_uint),
        ]

    class PK11SlotInfo(ct.Structure):
        """Opaque PKCS#11 slot handle."""

    def __init__(self) -> None:
        self.libnss = load_nss()
        SlotPtr = ct.POINTER(self.PK11SlotInfo)
        ItemPtr = ct.POINTER(self.SECItem)

        # Declare signatures so ctypes converts args/returns for us.
        self._declare(ct.c_int, "NSS_Init", ct.c_char_p)
        self._declare(ct.c_int, "NSS_Shutdown")
        self._declare(SlotPtr, "PK11_GetInternalKeySlot")
        self._declare(None, "PK11_FreeSlot", SlotPtr)
        self._declare(ct.c_int, "PK11_NeedLogin", SlotPtr)
        self._declare(ct.c_int, "PK11_CheckUserPassword", SlotPtr, ct.c_char_p)
        self._declare(ct.c_int, "PK11SDR_Decrypt", ItemPtr, ItemPtr, ct.c_void_p)
        # Encrypt is only used by the round-trip test to build real NSS data.
        self._declare(ct.c_int, "PK11SDR_Encrypt", ItemPtr, ItemPtr, ct.c_void_p)
        self._declare(None, "SECITEM_ZfreeItem", ItemPtr, ct.c_int)
        # Error introspection (NSPR), useful for debugging.
        self._declare(ct.c_int, "PORT_GetError")
        self._declare(ct.c_char_p, "PR_ErrorToName", ct.c_int)
        self._declare(ct.c_char_p, "PR_ErrorToString", ct.c_int, ct.c_uint32)

    def _declare(self, restype, name, *argtypes):
        fn = getattr(self.libnss, name)
        fn.argtypes = argtypes
        fn.restype = restype
        setattr(self, f"_fn_{name}", fn)

    # ------------------------------------------------------------------ #
    # Lifecycle                                                          #
    # ------------------------------------------------------------------ #
    def initialize(self, profile_path: str) -> None:
        """Point NSS at a Firefox profile folder.

        The "sql:" prefix tells NSS the cert/key database is the SQLite
        variant (cert9.db/key4.db) used by every modern Firefox.
        """
        profile = f"sql:{profile_path}".encode(DEFAULT_ENCODING)
        status = self._fn_NSS_Init(profile)
        if status:
            raise NSSDecryptError(f"NSS_Init failed (code {status}) for {profile_path}")

    def shutdown(self) -> None:
        try:
            self._fn_NSS_Shutdown()
        except (AttributeError, OSError):
            pass

    # ------------------------------------------------------------------ #
    # Primary password handling                                          #
    # ------------------------------------------------------------------ #
    def needs_login(self) -> bool:
        slot = self._fn_PK11_GetInternalKeySlot()
        if not slot:
            raise NSSDecryptError("Could not retrieve the internal key slot")
        try:
            return bool(self._fn_PK11_NeedLogin(slot))
        finally:
            self._fn_PK11_FreeSlot(slot)

    def unlock(self, password: str) -> None:
        slot = self._fn_PK11_GetInternalKeySlot()
        try:
            status = self._fn_PK11_CheckUserPassword(slot, password.encode(DEFAULT_ENCODING))
            if status:
                raise NSSDecryptError("Primary password is not correct")
        finally:
            self._fn_PK11_FreeSlot(slot)

    def last_error(self) -> str:
        """Human-readable description of the most recent NSS/NSPR error."""
        code = self._fn_PORT_GetError()
        name = self._fn_PR_ErrorToName(code)
        if name:
            return f"{code} {name.decode()} {self._fn_PR_ErrorToString(code, 0).decode()}"
        return f"code {code}"

    # ------------------------------------------------------------------ #
    # The actual decrypt                                                 #
    # ------------------------------------------------------------------ #
    def decrypt(self, data64: str) -> str:
        """Decrypt one base64-encoded SDR blob -> UTF-8 string."""
        data = b64decode(data64)
        inp = self.SECItem(0, data, len(data))
        out = self.SECItem(0, None, 0)
        status = self._fn_PK11SDR_Decrypt(ct.byref(inp), ct.byref(out), None)
        try:
            if status:
                raise NSSDecryptError(
                    "SDR decrypt failed: "
                    f"{self.last_error()} (credentials damaged or cert/key mismatch)"
                )
            return ct.string_at(out.data, out.len).decode(DEFAULT_ENCODING)
        finally:
            self._fn_SECITEM_ZfreeItem(ct.byref(out), 0)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt with SDR -- only used to build self-test fixtures."""
        data = plaintext.encode(DEFAULT_ENCODING)
        inp = self.SECItem(0, data, len(data))
        out = self.SECItem(0, None, 0)
        status = self._fn_PK11SDR_Encrypt(ct.byref(inp), ct.byref(out), None)
        if status:
            raise NSSDecryptError(f"SDR encrypt failed: {self.last_error()}")
        try:
            return b64encode(ct.string_at(out.data, out.len)).decode()
        finally:
            self._fn_SECITEM_ZfreeItem(ct.byref(out), 0)
