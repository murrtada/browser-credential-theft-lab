"""Firefox profile discovery.

Firefox keeps a profiles.ini index in its root folder
(Windows:  %APPDATA%\\Mozilla\\Firefox\\profiles.ini
 Linux:    ~/.mozilla/firefox/profiles.ini)
and stores each profile in its own subfolder. Cookies and logins live
inside the profile folder, so this module exists only to answer:
"which folders should we scan?"

The important thing for session harvesting is that ALL cookies for every
site (Facebook, LinkedIn, ...) live in each profile's cookies.sqlite, and
the per-site auth cookies are dumped from there without any encryption.
"""

from __future__ import annotations

import configparser
import os
import sys
from dataclasses import dataclass


@dataclass
class Profile:
    """A discovered Firefox profile."""

    name: str
    path: str  # absolute path to the profile folder


def firefox_root() -> str:
    """Return the base folder that contains profiles.ini for this OS."""
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA", "")
        return os.path.join(base, "Mozilla", "Firefox")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/Firefox")
    return os.path.expanduser("~/.mozilla/firefox")


def discover_profiles(base_dir: str | None = None) -> list[Profile]:
    """Parse profiles.ini and return every profile as an absolute path.

    Handles:
      - IsRelative=1 (default): path is relative to the base_dir
      - IsRelative=0          : path is absolute
    Profiles whose folder is missing are skipped (safe-guard).
    """
    base_dir = base_dir or firefox_root()
    ini_path = os.path.join(base_dir, "profiles.ini")

    if not os.path.isfile(ini_path):
        # If we were handed a profile folder directly (not a root), accept it.
        if os.path.isdir(base_dir) and os.path.isfile(
            os.path.join(base_dir, "cookies.sqlite")
        ):
            return [Profile(name=os.path.basename(base_dir), path=base_dir)]
        raise FileNotFoundError(f"profiles.ini not found under {base_dir}")

    parser = configparser.ConfigParser()
    parser.read(ini_path, encoding="utf-8")

    profiles: list[Profile] = []
    for section in parser.sections():
        if not section.startswith("Profile"):
            continue
        name = parser.get(section, "Name", fallback=section)
        rel = parser.get(section, "Path", fallback="")
        is_relative = parser.getboolean(section, "IsRelative", fallback=True)
        path = os.path.join(base_dir, rel) if is_relative else rel
        if os.path.isdir(path):
            profiles.append(Profile(name=name, path=os.path.abspath(path)))

    # Deterministic order so reports are stable.
    profiles.sort(key=lambda p: p.name.lower())
    return profiles
