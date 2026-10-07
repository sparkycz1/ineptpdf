"""FileOpen tests, run against a local stand-in for the publisher's licence server."""

import base64
import sys
import threading
from hashlib import md5
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import pytest
from conftest import CONTENT, build_pdf, pinned_machine, wrap
from test_decrypt import check_readable

from ineptpdf import DecryptionError, UnsupportedError, decrypt_file
from ineptpdf.cli import main
from ineptpdf.crypto import Decryptor, rc4
from ineptpdf.fileopen import (
    FileOpenOptions,
    Machine,
    _machine_fields,
    decrypt_plugin_value,
    fetch_key,
    id_from_bytes,
    probe_machine,
)
from ineptpdf.objects import Name

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
INFO_KEY = md5(bytes.fromhex("a4da49de82") + bytes.fromhex("ec8d6c5807")).digest()[:10]
MAC = bytes.fromhex("0a1b2c3d4e5f")


class LicenceServer:
    """Answers from a script of replies and records every request it receives."""

    def __init__(self):
        self.requests: list[dict[str, str]] = []
        self.agents: list[str] = []
        self.replies: dict[str, list[str]] = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                query = dict(parse_qsl(urlsplit(self.path).query, keep_blank_values=True))
                query["_path"] = urlsplit(self.path).path
                outer.requests.append(query)
                outer.agents.append(self.headers["User-Agent"])
                queue = outer.replies[query["Request"]]
                body = (queue.pop(0) if len(queue) > 1 else queue[0]).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body + b"\r\n")

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def named(self, request: str) -> list[dict[str, str]]:
        return [r for r in self.requests if r["Request"] == request]


@pytest.fixture
def server():
    server = LicenceServer()
    server.replies = {"Setting": ["RetVal=1"], "DocPerm": [f"RetVal=1&Code={KEY.hex()}"]}
    yield server
    server.httpd.shutdown()
    server.httpd.server_close()


def fileopen_pdf(server_url: str, info_extra: str = "", key: bytes = KEY) -> bytes:
    info = f"SVID=acme/1;DUID=doc 42;PURL={server_url};DPRM=perm.asp;VERS=0x3;{info_extra}"
    encrypt = {
        "Filter": Name("FOPN_foweb"),
        "V": 1,
        "Length": 128,
        "VEID": b"2.5",
        "BUILD": b"0922",
        "SVID": b"acme/1",
        "DUID": b"doc 42",
        "INFO": base64.b64encode(rc4(INFO_KEY, info.encode())),
    }
    return wrap(build_pdf(), Decryptor(key), encrypt)


def linux() -> Machine:
    return pinned_machine()


def options(**kwargs) -> FileOpenOptions:
    return FileOpenOptions(path="/books/a b.pdf", machine=linux(), **kwargs)


def key_for(pdf: bytes, opts: FileOpenOptions) -> bytes:
    from ineptpdf import Document

    return fetch_key(Document(pdf).encrypt, opts, timeout=5)


def test_decrypt_file(tmp_path, server):
    source, target = tmp_path / "doc.pdf", tmp_path / "out.pdf"
    source.write_bytes(fileopen_pdf(server.url))
    assert CONTENT not in source.read_bytes()

    decrypt_file(source, target)

    check_readable(target)
    assert [r["Request"] for r in server.requests] == ["Setting", "DocPerm"]
    request = server.named("DocPerm")[0]
    assert request["_path"] == "/perm.asp"
    assert request["ServiceID"] == "acme/1"
    assert request["DocumentID"] == "doc 42"
    assert request["EncrVer"] == "0x3"
    assert request["DocPathUrl"] == f"file:///{source}"
    assert len(request["Machine"]) == 8
    assert server.agents == ["Windows NT 6.0"] * 2


def test_query_order_and_custom_agent(server):
    key_for(fileopen_pdf(server.url, "AGEN=Acme Reader"), options())
    assert list(server.named("DocPerm")[0])[:6] == [
        "Request",
        "Stamp",
        "Mode",
        "ServiceID",
        "DocumentID",
        "DocStrFmt",
    ]
    assert server.agents[0] == "Acme Reader"


def test_raw_sixteen_character_key(server):
    raw = b"0123456789abcdef"
    server.replies["DocPerm"] = ["RetVal=1&Code=" + raw.decode()]
    assert key_for(fileopen_pdf(server.url), options()) == raw


def test_server_asks_for_login(server):
    server.replies["Setting"] = ["RetVal=0&Reason=AskUnp&ServerSessionData=abc"]
    pdf = fileopen_pdf(server.url)
    assert key_for(pdf, options(username="jane doe", password="p&ss")) == KEY
    request = server.named("DocPerm")[0]
    assert (request["UserName"], request["UserPass"]) == ("jane doe", "p&ss")
    assert request["ServerSessionData"] == "abc"

    with pytest.raises(DecryptionError, match="asks for: user name"):
        key_for(pdf, options())


def test_bad_password_is_asked_again(server):
    server.replies["DocPerm"] = [
        "RetVal=0&Reason=BadUserPwd&DocumentSessionData=xyz",
        f"RetVal=1&Code={KEY.hex()}",
    ]
    asked = []

    def prompt(question, secret):
        asked.append((question, secret))
        return "typed"

    assert key_for(fileopen_pdf(server.url), options(prompt=prompt)) == KEY
    assert asked == [("user name", False), ("password", True)]
    assert server.named("DocPerm")[1]["UserName"] == "typed"
    assert server.named("DocPerm")[1]["DocumentSessionData"] == "xyz"


def test_session_cookie(server):
    pdf = fileopen_pdf(server.url, "SEMO=1;CSES=ASPSESSION;CURL=shop.example")
    assert key_for(pdf, options(session="s3ss=ion")) == KEY
    assert server.named("DocPerm")[0]["Session"] == "s3ss=ion"
    with pytest.raises(DecryptionError, match="'ASPSESSION' cookie from shop.example"):
        key_for(pdf, options())


def test_refusal(server):
    server.replies["DocPerm"] = ["RetVal=0&Error=Document expired"]
    with pytest.raises(DecryptionError, match="refused the request: Document expired"):
        key_for(fileopen_pdf(server.url), options())


def test_unreachable_and_non_http_servers(tmp_path):
    with pytest.raises(DecryptionError, match="cannot reach"):
        key_for(fileopen_pdf("http://127.0.0.1:9"), options())
    secret = tmp_path / "secret.txt"
    secret.write_text("Code=00")
    with pytest.raises(DecryptionError, match="no usable licence server"):
        key_for(fileopen_pdf(f"file://{secret}"), options())


def test_plugin_bound_document_needs_windows(server):
    with pytest.raises(UnsupportedError, match="only on Windows"):
        key_for(fileopen_pdf(server.url, "I4ID=77"), options())
    assert server.requests == []


def test_cli_reports_the_server(tmp_path, server, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "doc.pdf").write_bytes(fileopen_pdf(server.url))
    assert main(["doc.pdf"]) == 0
    assert urlsplit(server.url).netloc in capsys.readouterr().err
    check_readable(tmp_path / "doc.decrypted.pdf")


# -- identifiers -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (bytes(5), "22222222"),
        (b"\xff" * 5, "ZZZZZZZZ"),
        (b"\x01\0\0\0\0", "32222222"),
        (b"\0\0\0\0\x01", "22222262"),  # the fifth byte lands two bits up: index 4
    ],
)
def test_id_from_bytes(data, expected):
    assert id_from_bytes(data) == expected


def plugin_blob(value: str, user: bytes) -> bytes:
    """Encrypts ``value`` as the FileOpen plug-in would store it for ``user``."""
    salt = bytes.fromhex("37A4DA49DE82064939A60B1D8D7B5F0F8873B6D93E")
    return rc4(
        md5(salt[:3] + user[:13] + salt[: 13 - len(user)]).digest(), b"ec20" + value.encode()
    )


def test_decrypt_plugin_value():
    blob = plugin_blob("the-uuid", b"jane")
    assert decrypt_plugin_value([b"noise", blob], "Jane") == "the-uuid"
    assert decrypt_plugin_value([blob], "john") is None


def test_windows_machine_fields():
    machine = Machine(
        windows=True,
        user="Jane",
        mac=MAC,
        hostname="PC7",
        disk_id=bytes.fromhex("78563412") + b"\x4a\x02",
        sid="S-1-5-21-1-2-3-1001",
        uuid_blobs=[plugin_blob("the-uuid", b"jane")],
        madi_blobs=[plugin_blob("OLDMACH1" + id_from_bytes(bytes.fromhex("785634124a")), b"jane")],
        volume={"VolType": "Fixed", "VolSN": "305419896"},
    )
    fields = _machine_fields({"LILA": "Yes", "LIFF": "Yes1"}, machine, r"C:\b\a.pdf")
    assert fields["OSType"] == "Windows"
    assert fields["Uuid"] == "the-uuid"
    assert fields["PrevMach"] == "OLDMACH1"
    assert "PrevDisk" not in fields
    assert (fields["User"], fields["SaUser"], fields["SaSID"]) == ("jane", "Jane", machine.sid)
    assert fields["PhysHostname"] == "PC7"
    assert fields["VolType"] == "Fixed"

    machine.uuid_blobs = []
    with pytest.raises(DecryptionError, match="Adobe Reader"):
        _machine_fields({}, machine, "x.pdf")


@pytest.mark.skipif(sys.platform != "win32", reason="probes the Windows API")
def test_probe_windows_for_real(tmp_path, monkeypatch):
    monkeypatch.undo()  # drop the pinned machine
    machine = probe_machine(str(tmp_path / "x.pdf"))
    assert machine.windows and machine.user and len(machine.mac) == 6
    assert machine.disk_id is not None and len(machine.disk_id) == 6
    assert len(id_from_bytes(machine.disk_id)) == 8
    assert machine.volume["VolType"] in ("Fixed", "Remote", "RamDisk", "Removable")
    assert machine.volume["VolSN"].isdigit() and machine.volume["FSName"]
    assert machine.sid is None or machine.sid.startswith("S-1-")
