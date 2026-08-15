#!/usr/bin/env python3
"""Chrome profile discovery tests against a synthetic user-data tree.

Run: python3 tests/test_chrome_profiles.py

Builds a fake User Data root with one real-looking profile (has a Cookies DB)
and a few non-profiles, then checks discover_profiles() only returns the one.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import chrome_profiles  # noqa: E402


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "User Data")

        # Real profile folders (would hold Cookies / Login Data).
        default = os.path.join(root, "Default")
        profile1 = os.path.join(root, "Profile 1")
        os.makedirs(default)
        os.makedirs(profile1)
        # Chrome 114+ keeps cookies under a Network/ subfolder.
        os.makedirs(os.path.join(default, "Network"))
        open(os.path.join(default, "Network", "Cookies"), "w").close()
        open(os.path.join(profile1, "Login Data"), "w").close()

        # Non-profiles that must be ignored.
        os.makedirs(os.path.join(root, "Guest Profile"))
        os.makedirs(os.path.join(root, "SharedProto"))
        os.makedirs(os.path.join(root, "Local State"))
        os.makedirs(os.path.join(root, "Crashpad"))

        found = chrome_profiles.discover_profiles("chrome", root_dir=root)
        names = sorted(p.name for p in found)
        assert names == ["Default", "Profile 1"], f"unexpected profiles: {names}"
        assert all(p.root == os.path.abspath(root) for p in found)
        assert all(p.browser == "chrome" for p in found)
        print(f"[i] discovered {len(found)} profiles, non-profiles skipped")

        # Empty / missing root -> nothing found, no crash.
        assert chrome_profiles.discover_profiles("chrome", root_dir=os.path.join(tmp, "nope")) == []
        print("[i] missing root handled cleanly")

        # Unknown browser must raise.
        try:
            chrome_profiles.user_data_roots("brave")
            raise AssertionError("unknown browser should have raised")
        except ValueError:
            print("[i] unknown browser correctly rejected")

    print("[PASS] chrome_profiles")
    return 0


if __name__ == "__main__":
    sys.exit(main())
