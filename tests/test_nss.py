#!/usr/bin/env python3
"""NSS + logins decrypt tests against REAL Firefox databases.

Run: python3 tests/test_nss.py

Uses bundled firefox_decrypt fixtures (see tests/fixtures/README.txt):
  - test_profile_firefox_nopassword_59  -> no Primary Password, 4 valid logins
  - test_profile_firefox_144            -> Primary Password protected,
                                           unlock then decrypt 4 logins

This exercises the exact code path shipped to Windows (NSS_Init ->
PK11SDR_Decrypt) against real-world NSS data with known plaintexts.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import firefox_logins, nss  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

# From firefox_decrypt tests/test_data/users/complex.user
EXPECTED = [
    ("https://github.com", "doesntexist", "xrbSDzYf94gfk"),
    ("https://github.com", "onemore", "}]¢öðæ[{"),
    ("https://github.com", "cömplex", "сЮЛОажс$4vz*VçàhxpfCbmwo"),
    ("https://github.com", "jãmïe", "Apassword\twithtabs,;colonandsemi'\"andquotes"),
]


def check(logins, label):
    got = [(l.hostname, l.username, l.password) for l in logins]
    for host, user, pwd in EXPECTED:
        assert (host, user, pwd) in got, f"{label}: missing {host} {user}"
    print(f"[i] {label}: {len(logins)} login(s), all {len(EXPECTED)} known plaintexts match")


def main() -> int:
    # Case 1: no primary password
    s1 = nss.NSS()
    prof59 = os.path.join(FIXTURES, "test_profile_firefox_nopassword_59")
    s1.initialize(prof59)
    try:
        assert s1.needs_login() is False, "59 profile must not need a password"
        check(firefox_logins.dump_logins(prof59, s1), "firefox 59 (no password)")
    finally:
        s1.shutdown()

    # Case 2: primary password
    s2 = nss.NSS()
    prof144 = os.path.join(FIXTURES, "test_profile_firefox_144")
    s2.initialize(prof144)
    try:
        assert s2.needs_login() is True, "144 profile must need a password"
        pw = open(os.path.join(FIXTURES, "master_password.txt"), encoding="utf-8").read().strip()
        s2.unlock(pw)
        check(firefox_logins.dump_logins(prof144, s2), "firefox 144 (primary password)")
    finally:
        s2.shutdown()

    # Case 3: wrong primary password must raise
    s3 = nss.NSS()
    s3.initialize(prof144)
    try:
        try:
            s3.unlock("wrong-password")
            raise AssertionError("wrong password should have raised")
        except nss.NSSDecryptError:
            print("[i] wrong primary password correctly rejected")
    finally:
        s3.shutdown()

    print("[PASS] nss + logins")
    return 0


if __name__ == "__main__":
    sys.exit(main())
