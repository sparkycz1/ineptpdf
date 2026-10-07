import io

import pytest
from conftest import CONTENT, TEXT, TITLE, build_pdf
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from pypdf import PdfReader, PdfWriter

from ineptpdf import DecryptionError, Document, IneptError, UnsupportedError, decrypt_file
from ineptpdf.cli import main
from ineptpdf.crypto import Decryptor, rc4

LAYOUTS = [{}, {"modern": True}, {"modern": True, "predictor": True}]


def check_readable(path) -> None:
    """The output must open, without a password, in an independent PDF library."""
    reader = PdfReader(path, strict=True)
    assert not reader.is_encrypted
    assert reader.pages[0].extract_text() == TEXT
    assert reader.metadata.title == TITLE
    assert reader.metadata.author == "Ča"


# -- ADEPT ---------------------------------------------------------------------


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize("xref", ["auto", "table", "stream"])
@pytest.mark.parametrize(
    "scheme",
    [{"version": 4}, {"version": 3}, {"version": 1, "key_prefix": b"\x02"}],
    ids=["v4", "v3-obfuscated", "v1-prefixed"],
)
def test_adept(tmp_path, adept, layout, xref, scheme):
    source, target = tmp_path / "book.pdf", tmp_path / "out.pdf"
    source.write_bytes(adept.encrypt(build_pdf(**layout), **scheme))
    assert CONTENT not in source.read_bytes()
    assert Document(source.read_bytes()).encryption_filter == "EBX_HANDLER"

    decrypt_file(source, target, key=adept.key_der, xref=xref)

    assert b"EBX_HANDLER" not in target.read_bytes()
    check_readable(target)


def test_adept_key_as_path_and_pkcs8(tmp_path, adept):
    source, target, key = tmp_path / "book.pdf", tmp_path / "out.pdf", tmp_path / "key.der"
    source.write_bytes(adept.encrypt(build_pdf()))
    key.write_bytes(
        adept.private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    )
    decrypt_file(source, target, key=key)
    check_readable(target)


def test_adept_wrong_key_leaves_no_output(tmp_path, adept):
    source, target = tmp_path / "book.pdf", tmp_path / "out.pdf"
    source.write_bytes(adept.encrypt(build_pdf()))
    other = rsa.generate_private_key(public_exponent=65537, key_size=1024).private_bytes(
        Encoding.DER, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    )
    for key, message in (
        (other, "does not open"),
        (b"junk", "RSA private key"),
        (None, "key file"),
    ):
        with pytest.raises(DecryptionError, match=message):
            decrypt_file(source, target, key=key)
    assert list(tmp_path.iterdir()) == [source]


def test_obfuscated_key_schedule_matches_the_original_formula():
    # Transcribed from genkey_v3() of ineptpdf 8.4.51.
    import hashlib
    import struct

    key, num, gen = bytes(range(16)), 0x123456, 7
    objid = struct.pack("<L", num ^ 0x3569AC)
    genno = struct.pack("<L", gen ^ 0xCA96)
    material = key + objid[0:1] + genno[0:1] + objid[1:2] + genno[1:2] + objid[2:3] + b"sAlT"
    expected = hashlib.md5(material).digest()[:16]
    assert Decryptor(key, obfuscated=True)._object_key(num, gen, "rc4") == expected


def test_rc4_fallback_agrees_with_openssl_and_rfc_vector():
    assert rc4(b"Key", b"Plaintext").hex() == "bbf316e8d940af0ad3"  # 3-byte key: pure Python
    key = bytes(range(16))
    assert rc4(key + b"\0", rc4(key + b"\0", b"round trip")) == b"round trip"


# -- password-protected PDFs, encrypted by pypdf --------------------------------


def password_protected(algorithm: str) -> bytes:
    writer = PdfWriter(clone_from=io.BytesIO(build_pdf()))
    writer.encrypt("user-pw", "owner-pw", algorithm=algorithm)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


@pytest.mark.parametrize("algorithm", ["RC4-40", "RC4-128", "AES-128"])
@pytest.mark.parametrize("password", ["user-pw", "owner-pw"])
def test_password(tmp_path, algorithm, password):
    source, target = tmp_path / "locked.pdf", tmp_path / "out.pdf"
    source.write_bytes(password_protected(algorithm))
    assert CONTENT not in source.read_bytes()
    decrypt_file(source, target, password=password)
    check_readable(target)


def test_wrong_password(tmp_path):
    source = tmp_path / "locked.pdf"
    source.write_bytes(password_protected("AES-128"))
    with pytest.raises(DecryptionError, match="incorrect password"):
        decrypt_file(source, tmp_path / "out.pdf", password="nope")


def test_aes256_is_reported_as_unsupported(tmp_path):
    source = tmp_path / "locked.pdf"
    source.write_bytes(password_protected("AES-256"))
    with pytest.raises(UnsupportedError, match="qpdf"):
        decrypt_file(source, tmp_path / "out.pdf", password="user-pw")


@pytest.mark.parametrize("handler", ["FOPN_fLock", "Adobe.APS", "Mystery"])
def test_other_handlers_are_rejected(tmp_path, adept, handler):
    source = tmp_path / "book.pdf"
    source.write_bytes(adept.encrypt(build_pdf()).replace(b"EBX_HANDLER", handler.encode()))
    with pytest.raises(UnsupportedError, match=handler):
        decrypt_file(source, tmp_path / "out.pdf", key=adept.key_der)


# -- damaged and unusual input ---------------------------------------------------


def test_unencrypted_input_is_refused(tmp_path):
    source = tmp_path / "plain.pdf"
    source.write_bytes(build_pdf())
    with pytest.raises(IneptError, match="not encrypted"):
        decrypt_file(source, tmp_path / "out.pdf")


def test_not_a_pdf(tmp_path):
    source = tmp_path / "x.pdf"
    source.write_bytes(b"hello")
    with pytest.raises(IneptError, match="not a PDF"):
        decrypt_file(source, tmp_path / "out.pdf")


@pytest.mark.parametrize(
    "damage",
    [
        lambda pdf: pdf[: pdf.rindex(b"startxref")] + b"startxref\n17\n%%EOF\n",
        lambda pdf: pdf[: pdf.rindex(b"startxref")],
        lambda pdf: pdf.replace(b"0000000000 65535 f", b"0000000000 65535 f garbage"),
    ],
    ids=["bad-offset", "no-startxref", "bad-table"],
)
def test_damaged_xref_is_rebuilt(tmp_path, adept, damage):
    source, target = tmp_path / "book.pdf", tmp_path / "out.pdf"
    source.write_bytes(damage(adept.encrypt(build_pdf())))
    decrypt_file(source, target, key=adept.key_der)
    check_readable(target)


def test_wrong_stream_length_is_tolerated(tmp_path, adept):
    source, target = tmp_path / "book.pdf", tmp_path / "out.pdf"
    plain = build_pdf().replace(b"8 0 obj\n%d\n" % len(CONTENT), b"8 0 obj\n%d\n" % 99)
    source.write_bytes(adept.encrypt(plain))
    decrypt_file(source, target, key=adept.key_der)
    check_readable(target)


# -- command line ----------------------------------------------------------------


def test_cli(tmp_path, adept, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "book.pdf").write_bytes(adept.encrypt(build_pdf(modern=True)))
    (tmp_path / "adeptkey.der").write_bytes(adept.key_der)

    assert main(["book.pdf"]) == 0  # picks up ./adeptkey.der
    check_readable(tmp_path / "book.decrypted.pdf")
    assert "book.decrypted.pdf" in capsys.readouterr().out

    assert main(["book.pdf"]) == 1
    assert "already exists" in capsys.readouterr().err
    assert main(["book.pdf", "--force", "-k", "adeptkey.der"]) == 0
    assert main(["book.pdf", "-o", "book.pdf", "-f"]) == 1
    assert "different files" in capsys.readouterr().err
    assert main(["missing.pdf"]) == 1
