#!/usr/bin/env python3
"""Cookie extraction tests -- run: python3 tests/test_cookies.py"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import firefox_cookies as fc  # noqa: E402
from lib import profiles  # noqa: E402


def main() -> int:
    found = profiles.discover_profiles()
    assert found, "no local profiles to test against"
    target = next(
        (p for p in found if os.path.isfile(os.path.join(p.path, "cookies.sqlite"))),
        None,
    )
    assert target, "no profile with cookies.sqlite available"

    cookies = fc.dump_cookies(target.path)
    print(f"[i] Dumped {len(cookies)} cookies from {target.name}")
    assert len(cookies) > 0, "expected cookies on the live profile"

    # Sanity: every cookie we read is a real row with a value.
    for c in cookies[:10]:
        print(f"    {c.host:<40} {c.name:<28} len={len(c.value)} sec={c.is_secure} "
              f"httponly={c.is_http_only} hv={c.high_value} {c.category}")
        assert isinstance(c.value, str)

    # Classification sanity checks.
    assert fc.classify("www.facebook.com", "xs") == (True, "facebook")
    assert fc.classify("www.linkedin.com", "li_at") == (True, "linkedin")
    assert fc.classify("example.com", "sessionid") == (True, "generic")
    assert fc.classify("example.com", "foo") == (False, "")
    assert fc.classify("www.google.com", "__Secure-1PSID") == (True, "google")

    # The copy must not leave litter behind.
    import tempfile
    tmp = fc.copy_db(target.path)
    assert os.path.isdir(tmp)
    fc.shutil.rmtree(tmp, ignore_errors=True)

    print("[PASS] cookies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
