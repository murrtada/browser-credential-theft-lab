"""browser-credential-theft-lab: a learning-oriented browser credential harvester.

Modules:
  profiles         - Firefox profile discovery (profiles.ini)
  firefox_cookies  - plaintext session-cookie dump (the session-hijack core)
  nss              - NSS library bridge for decrypting logins.json
  firefox_logins   - saved-login decryption via NSS
  chrome_profiles  - Chrome/Edge profile discovery (User Data root)
  chrome_crypto    - Chrome/Edge AES key recovery + value decryption (DPAPI)
  chrome_cookies   - Chrome/Edge cookie dump (decrypted)
  chrome_logins    - Chrome/Edge saved-login dump (decrypted)
  report           - redacted console + local report file
"""

__all__ = [
    "profiles",
    "firefox_cookies",
    "nss",
    "firefox_logins",
    "chrome_profiles",
    "chrome_crypto",
    "chrome_cookies",
    "chrome_logins",
    "report",
]
