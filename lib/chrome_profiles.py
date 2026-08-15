"""Chromium (Chrome / Edge) profile discovery.

Chrome and Edge keep a set of profile folders under a shared "User Data"
root, e.g.

  Windows: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default
  Linux:   ~/.config/google-chrome/Default
  macOS:   ~/Library/Application Support/Google/Chrome/Default

Each profile folder holds the per-profile SQLite databases:
  * Cookies    -> cookies (encrypted values)
  * Login Data -> saved logins (encrypted passwords)
The AES key is shared for the whole browser and lives one level up, in the
User Data root's "Local State" file -- see chrome_crypto.py.

Profiles are discovered by listing the User Data root for folders that
contain a Cookies or Login Data database. The "Default" profile plus any
"Profile N" folders are the normal ones.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass


@dataclass
class ChromiumProfile:
    """A discovered Chrome/Edge profile."""

    name: str
    path: str            # absolute path to the profile folder
    root: str            # absolute path to the browser's User Data root (has Local State)
    browser: str         # "chrome" or "edge"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "root": self.root,
            "browser": self.browser,
        }


def user_data_roots(browser: str = "chrome") -> list[str]:
    """Candidate User Data roots for a Chromium browser on this OS."""
    if browser not in ("chrome", "edge"):
        raise ValueError(f"browser must be 'chrome' or 'edge', got {browser!r}")

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    home = os.path.expanduser("~")

    if sys.platform.startswith("win"):
        rels = {
            "chrome": [r"Google\Chrome\User Data"],
            "edge": [r"Microsoft\Edge\User Data"],
        }
        base = local_app_data or home
        return [os.path.join(base, rel) for rel in rels[browser]]

    if sys.platform == "darwin":
        rels = {
            "chrome": ["Library/Application Support/Google/Chrome"],
            "edge": ["Library/Application Support/Microsoft Edge"],
        }
        return [os.path.join(home, rel) for rel in rels[browser]]

    # Linux
    rels = {
        "chrome": [".config/google-chrome", ".config/chromium"],
        "edge": [".config/microsoft-edge"],
    }
    return [os.path.join(home, rel) for rel in rels[browser]]


def _is_profile_dir(path: str) -> bool:
    """A profile folder has a Cookies and/or Login Data SQLite DB.

    Chrome 114+ moved the cookies DB into a ``Network/`` subfolder, so that
    location is checked too.
    """
    if os.path.isfile(os.path.join(path, "Cookies")) or os.path.isfile(
        os.path.join(path, "Login Data")
    ):
        return True
    return os.path.isfile(os.path.join(path, "Network", "Cookies"))


def discover_profiles(browser: str = "chrome", root_dir: str | None = None) -> list[ChromiumProfile]:
    """Return every Chromium profile folder under the User Data root(s).

    Skips non-profile subfolders (SharedProto, Guest Profile, etc.) by
    requiring a Cookies / Login Data database.
    """
    roots = [root_dir] if root_dir else user_data_roots(browser)
    found: list[ChromiumProfile] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for entry in sorted(os.listdir(root)):
            folder = os.path.join(root, entry)
            if os.path.isdir(folder) and _is_profile_dir(folder):
                found.append(
                    ChromiumProfile(
                        name=entry,
                        path=os.path.abspath(folder),
                        root=os.path.abspath(root),
                        browser=browser,
                    )
                )
    found.sort(key=lambda p: p.name.lower())
    return found
