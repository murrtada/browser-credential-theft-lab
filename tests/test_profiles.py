#!/usr/bin/env python3
"""Profile discovery tests -- run: python3 tests/test_profiles.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import profiles  # noqa: E402


def main() -> int:
    base = profiles.firefox_root()
    print(f"[i] Firefox root: {base}")
    found = profiles.discover_profiles()
    print(f"[i] {len(found)} profile(s):")
    with_cookies = 0
    for p in found:
        print(f"    {p.name:<20} {p.path}")
        assert os.path.isdir(p.path), f"missing dir {p.path}"
        if os.path.isfile(os.path.join(p.path, "cookies.sqlite")):
            with_cookies += 1
    assert with_cookies >= 1, "expected at least one profile with cookies"

    assert len(found) >= 1, "expected at least one local profile"
    print("[PASS] profiles")
    return 0


if __name__ == "__main__":
    sys.exit(main())
