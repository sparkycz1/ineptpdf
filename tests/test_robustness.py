"""Cipher detection, damaged files and the diagnostic trail."""

import logging
import os

import pytest
from conftest import build_pdf, wrap
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from test_decrypt import check_readable
from test_fileopen import KEY, fileopen_pdf
from test_fileopen import server as server  # noqa: F401  (fixture)

from ineptpdf import DecryptionError, decrypt_file
from ineptpdf.crypto import Decryptor


class AesEncryptor:
    """The inverse of an AES ``Decryptor``, for building test files."""

    def __init__(self, key: bytes, direct_key: bool = False):
        self.keys = Decryptor(key, "aes", "aes", direct_key=direct_key)

    def _encrypt(self, num: int, gen: int, data: bytes) -> bytes:
        padder = padding.PKCS7(128).padder()
        iv = os.urandom(16)
        key = self.keys._object_key(num, gen, "aes")
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return iv + encryptor.update(padder.update(data) + padder.finalize()) + encryptor.finalize()

    def decrypt_string(self, num, gen, data):
        return self._encrypt(num, gen, data)

    def decrypt_stream(self, num, gen, stream):
        return self._encrypt(num, gen, stream.raw)


@pytest.mark.parametrize(
    ("key", "direct"),
    [(KEY, False), (KEY, True), (KEY + KEY, True)],
    ids=["aes128-md5", "aes128-direct", "aes256-direct"],
)
def test_fileopen_with_aes(tmp_path, server, key, direct):  # noqa: F811
    server.replies["DocPerm"] = [f"RetVal=1&Code={key.hex()}"]
    template = fileopen_pdf(server.url)  # only to borrow its encryption dictionary
    from ineptpdf import Document

    encrypt = Document(template).encrypt
    source, target = tmp_path / "doc.pdf", tmp_path / "out.pdf"
    source.write_bytes(wrap(build_pdf(modern=True), AesEncryptor(key, direct), encrypt))
    decrypt_file(source, target)
    check_readable(target)


def test_key_that_does_not_fit_is_reported(tmp_path, server):  # noqa: F811
    server.replies["DocPerm"] = ["RetVal=1&Code=" + "ab" * 16]
    template = fileopen_pdf(server.url)
    from ineptpdf import Document

    source = tmp_path / "doc.pdf"
    source.write_bytes(wrap(build_pdf(modern=True), Decryptor(KEY), Document(template).encrypt))
    with pytest.raises(DecryptionError, match="does not decrypt the contents"):
        decrypt_file(source, tmp_path / "out.pdf")
    assert not (tmp_path / "out.pdf").exists()


def test_adept_key_schedule_is_detected(tmp_path, adept):
    # The dictionary says V=4 (plain schedule) but the book uses the obfuscated one.
    encrypted = adept.encrypt(build_pdf(modern=True), version=3).replace(b"/V 3", b"/V 4")
    source, target = tmp_path / "book.pdf", tmp_path / "out.pdf"
    source.write_bytes(encrypted)
    decrypt_file(source, target, key=adept.key_der)
    check_readable(target)


def test_damaged_object_is_left_out(tmp_path, adept, caplog):
    encrypted = adept.encrypt(build_pdf())
    free = b"0000000000 65535 f \n"
    head, tail = encrypted.split(free, 1)  # the first free entry is object 0
    assert free in tail
    source, target = tmp_path / "book.pdf", tmp_path / "out.pdf"
    source.write_bytes(head + free + tail.replace(free, b"0099999999 00000 n \n", 1))

    with caplog.at_level(logging.WARNING, logger="ineptpdf"):
        damaged = decrypt_file(source, target, key=adept.key_der)

    assert damaged == [7]
    assert "object 7: unexpected end of data" in caplog.text
    check_readable(target)


def test_debug_trail_has_no_secrets(tmp_path, server, caplog):  # noqa: F811
    server.replies["Setting"] = ["RetVal=0&Reason=AskUnp"]
    source = tmp_path / "doc.pdf"
    source.write_bytes(fileopen_pdf(server.url))
    with caplog.at_level(logging.DEBUG, logger="ineptpdf"):
        decrypt_file(source, tmp_path / "out.pdf", username="jane.doe", password="hunter2")
    assert "DocumentID" in caplog.text and "RetVal" in caplog.text
    assert "cipher candidates" in caplog.text
    for secret in ("jane.doe", "hunter2", KEY.hex()):
        assert secret not in caplog.text


def test_gui_details(tmp_path, adept, monkeypatch):
    tk = pytest.importorskip("tkinter")
    from ineptpdf import gui

    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    root.withdraw()
    try:
        app = gui.App(root)
        source = tmp_path / "book.pdf"
        source.write_bytes(adept.encrypt(build_pdf()))
        app.set_source(str(source))
        assert app.save() is None  # no key given
        report = app.copy_details()
        assert "EBX_HANDLER" in report and "DecryptionError" in report
        assert root.clipboard_get() == report

        monkeypatch.setattr(gui.App, "_run", lambda *args: 1 / 0)
        assert app.save() is None
        assert "Unexpected error (ZeroDivisionError" in app.status.get()
        assert "ZeroDivisionError" in app.copy_details()
    finally:
        root.destroy()
