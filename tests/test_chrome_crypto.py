#!/usr/bin/env python3
"""Chrome AES decryption tests with synthetic known-key fixtures.

Run: python3 tests/test_chrome_crypto.py

This exercises the exact AES code path used for Chrome >= 80 (v10 AES-256-GCM)
and Chrome < 80 (v1 AES-128-CBC) against self-built fixtures with a known key,
so the crypto logic is verifiable on any OS / in CI without a real Chrome
profile. The Windows-only DPAPI unwrap step cannot run off-Windows; it is
validated manually on the target Windows box (see README.md).

DPAPI itself is intentionally NOT in this test: it needs a live Windows
user/session. What IS tested is everything downstream of the key -- exactly
the 95% of the code that is OS-independent.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from lib import chrome_crypto  # noqa: E402

KEY32 = bytes(range(32))  # a deterministic 32-byte AES key
PLAINTEXT = b"session=8f2c1ab0edf94c3d;user=root"


def _make_v10() -> bytes:
    """Build a Chrome >= 80 blob: b'v10' + nonce(12) + ct + tag(16)."""
    nonce = b"\x01" * 12
    cipher = AES.new(KEY32, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(PLAINTEXT)
    return b"v10" + nonce + ct + tag


def _make_v1() -> bytes:
    """Build a Chrome < 80 blob: b'v1' + iv(16) + PKCS7-padded ct."""
    iv = b"\x02" * 16
    cipher = AES.new(KEY32[:16], AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(PLAINTEXT, 16))
    return b"v1" + iv + ct


def main() -> int:
    # v10 (Chrome 80+): AES-256-GCM, full 32-byte key.
    v10 = _make_v10()
    assert chrome_crypto.decrypt_value(v10, KEY32) == PLAINTEXT.decode()
    print("[i] v10 AES-256-GCM roundtrip OK")

    # v1 (Chrome < 80): AES-128-CBC, first 16 bytes of key, PKCS7.
    v1 = _make_v1()
    assert chrome_crypto.decrypt_value(v1, KEY32) == PLAINTEXT.decode()
    print("[i] v1 AES-128-CBC roundtrip OK")

    # Wrong key must fail closed (GCM tag verification).
    try:
        chrome_crypto.decrypt_value(v10, bytes(32))
        raise AssertionError("wrong key should have failed GCM auth")
    except chrome_crypto.ChromeDecryptError:
        print("[i] wrong key correctly rejected (GCM tag mismatch)")

    # Unknown prefix must raise, never guess.
    try:
        chrome_crypto.decrypt_value(b"v99\x00\x01\x02\x03", KEY32)
        raise AssertionError("unknown prefix should have raised")
    except chrome_crypto.ChromeDecryptError:
        print("[i] unknown prefix correctly rejected")

    # Local State key unwrap: a fake DPAPI-wrapped key on a non-Windows box
    # must give the clear "not Windows" error, not a crash.
    if chrome_crypto.SYSTEM != "Windows":
        try:
            chrome_crypto.unwrap_wrapped_key(b"DPAPI" + b"\x00" * 32)
            raise AssertionError("non-Windows DPAPI should have raised")
        except chrome_crypto.ChromeKeyError as e:
            assert "not Windows" in str(e)
            print("[i] DPAPI on non-Windows correctly refused")

        # Unknown key layout (e.g. Linux 'v10' raw key) must raise too.
        try:
            chrome_crypto.unwrap_wrapped_key(b"v10" + b"\x00" * 32)
            raise AssertionError("unknown key layout should have raised")
        except chrome_crypto.ChromeKeyError as e:
            assert "Unsupported" in str(e)
            print("[i] unknown key layout correctly refused")
    else:
        print("[i] skipping non-Windows DPAPI check (running on Windows)")

    print("[PASS] chrome_crypto")
    return 0


if __name__ == "__main__":
    sys.exit(main())
