"""Looks up a cookie in the user's own Firefox profiles.

FileOpen publishers that work with web logins expect the reader to present the
session cookie of the publisher's site. Firefox keeps persistent cookies in
``cookies.sqlite`` and session-only cookies in its session store; both are read
here, read-only, from copies.
"""

import configparser
import contextlib
import json
import logging
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

log = logging.getLogger("ineptpdf")

_MOZLZ4_MAGIC = b"mozLz40\0"
_SESSION_FILES = ("sessionstore-backups/recovery.jsonlz4", "sessionstore.jsonlz4")


def firefox_roots() -> list[Path]:
    """Directories that may hold a Firefox ``profiles.ini`` on this system."""
    home = Path.home()
    if sys.platform == "win32":
        return [Path(os.environ.get("APPDATA", home)) / "Mozilla" / "Firefox"]
    if sys.platform == "darwin":
        return [home / "Library" / "Application Support" / "Firefox"]
    return [
        home / ".mozilla" / "firefox",
        home / "snap" / "firefox" / "common" / ".mozilla" / "firefox",
        home / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox",
    ]


def firefox_profiles(roots: list[Path] | None = None) -> list[Path]:
    profiles = []
    for root in firefox_roots() if roots is None else roots:
        config = configparser.ConfigParser(interpolation=None)
        try:
            config.read(root / "profiles.ini", encoding="utf-8")
        except (OSError, configparser.Error):
            continue
        for section in config.sections():
            if path := config[section].get("Path"):
                relative = config[section].get("IsRelative", "1") == "1"
                profile = root / path if relative else Path(path)
                if profile.is_dir() and profile not in profiles:
                    profiles.append(profile)
    return profiles


def find_cookie(name: str, site: str, roots: list[Path] | None = None) -> str | None:
    """Value of the most recently used cookie ``name`` that Firefox holds for ``site``.

    ``site`` may be a host name or a URL. Cookies set for a parent domain match too.
    """
    host = _host(site)
    if not name or not host:
        return None
    found: list[tuple[int, str]] = []  # (freshness, value)
    for profile in firefox_profiles(roots):
        found += _persistent_cookies(profile, name, host)
        found += _session_cookies(profile, name, host)
    if not found:
        return None
    return max(found)[1]


def _host(site: str) -> str:
    host = urlsplit(site if "://" in site else "//" + site).hostname or ""
    return host.lower().strip(".")


def _matches(cookie_host: str, host: str) -> bool:
    cookie_host = cookie_host.lower().lstrip(".")
    return bool(cookie_host) and (host == cookie_host or host.endswith("." + cookie_host))


def _persistent_cookies(profile: Path, name: str, host: str) -> list[tuple[int, str]]:
    database = profile / "cookies.sqlite"
    if not database.is_file():
        return []
    # Firefox keeps the database locked while it runs, so query a copy.
    with tempfile.TemporaryDirectory() as scratch:
        try:
            for suffix in ("", "-wal"):
                source = database.with_name(database.name + suffix)
                if source.is_file():
                    shutil.copy(source, Path(scratch) / source.name)
            with contextlib.closing(sqlite3.connect(Path(scratch) / database.name)) as connection:
                rows = connection.execute(
                    "SELECT host, value, lastAccessed FROM moz_cookies WHERE name = ?", (name,)
                ).fetchall()
        except (OSError, sqlite3.Error) as exc:
            log.info("Cannot read Firefox cookies in %s: %s", profile, exc)
            return []
    return [(used or 0, value) for cookie_host, value, used in rows if _matches(cookie_host, host)]


def _session_cookies(profile: Path, name: str, host: str) -> list[tuple[int, str]]:
    for relative in _SESSION_FILES:
        try:
            store = json.loads(read_mozlz4((profile / relative).read_bytes()))
        except (OSError, ValueError, IndexError):
            continue
        cookies = store.get("cookies") if isinstance(store, dict) else None
        freshness = int(store.get("session", {}).get("lastUpdate", 0)) * 1000 if cookies else 0
        return [
            (freshness, str(cookie.get("value", "")))
            for cookie in cookies or []
            if isinstance(cookie, dict)
            and cookie.get("name") == name
            and _matches(str(cookie.get("host", "")), host)
        ]
    return []


def read_mozlz4(data: bytes) -> bytes:
    """Decodes Mozilla's ``.jsonlz4`` container: a header and one LZ4 block."""
    if not data.startswith(_MOZLZ4_MAGIC):
        raise ValueError("not a mozLz4 file")
    return _lz4_block(memoryview(data)[len(_MOZLZ4_MAGIC) + 4 :])


def _lz4_block(source: memoryview) -> bytes:
    out = bytearray()
    pos, end = 0, len(source)

    def extended(length: int) -> int:
        nonlocal pos
        if length == 15:
            while True:
                byte = source[pos]
                pos += 1
                length += byte
                if byte != 255:
                    break
        return length

    while pos < end:
        token = source[pos]
        pos += 1
        literals = extended(token >> 4)
        out += source[pos : pos + literals]
        pos += literals
        if pos >= end:
            break  # the last sequence has literals only
        offset = source[pos] | source[pos + 1] << 8
        pos += 2
        length = extended(token & 15) + 4
        if not 0 < offset <= len(out):
            raise ValueError("corrupt LZ4 data")
        chunk = out[-offset:]
        if offset < length:  # overlapping match: the chunk repeats
            chunk = (chunk * (length // offset + 1))[:length]
        out += chunk[:length]
    return bytes(out)
