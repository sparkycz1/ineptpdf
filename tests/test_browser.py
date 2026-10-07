import json
import sqlite3

import pytest
from conftest import build_pdf  # noqa: F401  (keeps conftest importable the same way)
from test_fileopen import KEY, fileopen_pdf, key_for, options
from test_fileopen import server as server  # noqa: F401  (fixture)

from ineptpdf import DecryptionError, browser
from ineptpdf.browser import find_cookie, read_mozlz4
from ineptpdf.cli import main


def mozlz4(payload: bytes) -> bytes:
    """Stores ``payload`` as one literal-only LZ4 sequence, which is valid LZ4."""
    length = len(payload)
    token, extra = min(length, 15) << 4, b""
    if length >= 15:
        rest = length - 15
        extra = b"\xff" * (rest // 255) + bytes([rest % 255])
    return b"mozLz40\0" + length.to_bytes(4, "little") + bytes([token]) + extra + payload


@pytest.fixture
def firefox(tmp_path):
    """A fake Firefox installation with two profiles."""
    root = tmp_path / "firefox"
    for profile in ("abc.default", "xyz.work"):
        (root / profile / "sessionstore-backups").mkdir(parents=True)
    (root / "profiles.ini").write_text(
        "[Profile0]\nName=default\nIsRelative=1\nPath=abc.default\n\n"
        "[Profile1]\nName=work\nIsRelative=1\nPath=xyz.work\n\n[General]\nVersion=2\n"
    )
    database = sqlite3.connect(root / "abc.default" / "cookies.sqlite")
    database.execute("CREATE TABLE moz_cookies (name, value, host, lastAccessed)")
    database.executemany(
        "INSERT INTO moz_cookies VALUES (?, ?, ?, ?)",
        [
            ("SID", "old", "shop.example", 100),
            ("SID", "new", ".example", 200),
            ("SID", "other-site", "evil-example", 900),
            ("name", "jane", "login.example", 1),
            ("pass", "s3cret", "login.example", 1),
        ],
    )
    database.commit()
    database.close()
    store = {
        "session": {"lastUpdate": 5},
        "cookies": [{"host": "norms.example", "name": "ASPSESSION", "value": "from-session"}],
    }
    (root / "xyz.work" / "sessionstore-backups" / "recovery.jsonlz4").write_bytes(
        mozlz4(json.dumps(store).encode())
    )
    return [root]


def test_lz4_with_matches():
    # "abc", then a 9-byte overlapping match at distance 3, then the literal "d".
    block = bytes([0x35]) + b"abc" + bytes([3, 0]) + bytes([0x10]) + b"d"
    assert read_mozlz4(b"mozLz40\0" + bytes(4) + block) == b"abcabcabcabcd"
    long = bytes(range(256)) * 3
    assert read_mozlz4(mozlz4(long)) == long
    with pytest.raises(ValueError):
        read_mozlz4(b"{}")


def test_find_cookie(firefox):
    assert find_cookie("SID", "shop.example", firefox) == "new"  # most recently used
    assert find_cookie("SID", "https://www.shop.example:8443/x", firefox) == "new"
    assert find_cookie("SID", "example", firefox) == "new"
    assert find_cookie("SID", "elsewhere.test", firefox) is None
    assert find_cookie("ASPSESSION", "norms.example", firefox) == "from-session"
    assert find_cookie("missing", "shop.example", firefox) is None
    assert find_cookie("SID", "shop.example", []) is None


def test_session_cookie_is_taken_from_firefox(server, firefox):  # noqa: F811
    pdf = fileopen_pdf(server.url, "SEMO=1;CSES=ASPSESSION;CURL=http://norms.example/")
    lookup = lambda name, site: find_cookie(name, site, firefox)  # noqa: E731
    asked = []

    def confirm(question):
        asked.append(question)
        return True

    assert key_for(pdf, options(find_cookie=lookup, confirm=confirm)) == KEY
    assert server.named("DocPerm")[0]["Session"] == "from-session"
    assert "norms.example" in asked[0] and "127.0.0.1" in asked[0]

    assert key_for(pdf, options(find_cookie=lookup, session="explicit")) == KEY
    assert server.named("DocPerm")[1]["Session"] == "explicit"


def test_foreign_cookie_is_not_sent_without_consent(server, firefox):  # noqa: F811
    # A hostile PDF names someone else's site as the cookie source.
    pdf = fileopen_pdf(server.url, "SEMO=1;CSES=SID;CURL=shop.example")
    lookup = lambda name, site: find_cookie(name, site, firefox)  # noqa: E731
    for confirm in (None, lambda question: False):
        with pytest.raises(DecryptionError, match="asks for"):
            key_for(pdf, options(find_cookie=lookup, confirm=confirm))
    assert server.named("DocPerm") == []


def test_cookie_of_the_licence_server_itself_needs_no_consent(server):  # noqa: F811
    pdf = fileopen_pdf(server.url, "SEMO=1;CSES=SID;CURL=shop.example")
    lookup = lambda name, site: "mine" if site == "127.0.0.1" else None  # noqa: E731
    assert key_for(pdf, options(find_cookie=lookup)) == KEY
    assert server.named("DocPerm")[0]["Session"] == "mine"


def test_login_cookies_are_taken_from_firefox(server, firefox):  # noqa: F811
    pdf = fileopen_pdf(server.url, "SEMO=2;CSES=x;CURL=login.example")
    lookup = lambda name, site: find_cookie(name, site, firefox)  # noqa: E731
    assert key_for(pdf, options(find_cookie=lookup, confirm=lambda question: True)) == KEY
    request = server.named("DocPerm")[0]
    assert (request["UserName"], request["UserPass"]) == ("jane", "s3cret")


def test_cli_uses_firefox_and_info(tmp_path, server, firefox, capsys, monkeypatch):  # noqa: F811
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(browser, "firefox_roots", lambda: firefox)
    info = "SEMO=1;CSES=ASPSESSION;CURL=norms.example"
    (tmp_path / "norm.pdf").write_bytes(fileopen_pdf(server.url, info))

    assert main(["norm.pdf", "--info"]) == 0
    shown = capsys.readouterr().out
    assert "Protection: FOPN_foweb" in shown and "CSES = ASPSESSION" in shown
    assert server.requests == []

    assert main(["norm.pdf", "--no-browser-cookies"]) == 1
    assert "'ASPSESSION' cookie from norms.example" in capsys.readouterr().err

    assert main(["norm.pdf"]) == 1  # not a terminal: nobody to confirm a foreign cookie
    capsys.readouterr()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda question: "y")
    assert main(["norm.pdf", "--force"]) == 0
    assert "from Firefox" in capsys.readouterr().err
    assert server.named("DocPerm")[-1]["Session"] == "from-session"
