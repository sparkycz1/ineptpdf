"""Hand-built sample PDFs, so the tests do not depend on copyrighted books."""

import base64
import io
import zlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ineptpdf import Document, write_pdf
from ineptpdf.crypto import Decryptor
from ineptpdf.document import InUse
from ineptpdf.fileopen import Machine
from ineptpdf.objects import Name

TEXT = "Hello (inept) world"
TITLE = "A Sample \\ Book"
CONTENT = b"BT /F1 24 Tf 72 720 Td (Hello \\(inept\\) world) Tj ET"
OBJECTS = {
    1: b"<</Type/Catalog/Pages 2 0 R>>",
    2: b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
    3: b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792.0]/Contents 5 0 R"
    b"/Resources<</Font<</F1 4 0 R>>>>>>",
    4: b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
    6: b"<</Title(A Sample \\\\ Book)/Author<FEFF010C0061>>>",
}


def _png_up(data: bytes, width: int) -> bytes:
    out, prev = bytearray(), bytes(width)
    for start in range(0, len(data), width):
        row = data[start : start + width]
        out += b"\x02" + bytes((a - b) & 0xFF for a, b in zip(row, prev, strict=True))
        prev = row
    return bytes(out)


def build_pdf(*, modern: bool = False, predictor: bool = False) -> bytes:
    """A one-page PDF. ``modern`` uses an object stream and a cross-reference stream."""
    out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}

    def add(num: int, body: bytes) -> None:
        offsets[num] = len(out)
        out.extend(b"%d 0 obj\n%s\nendobj\n" % (num, body))

    stream = b"<</Length 8 0 R>>\nstream\n%s\nendstream" % CONTENT
    if not modern:
        for num, body in OBJECTS.items():
            add(num, body)
        add(5, stream)
        add(8, b"%d" % len(CONTENT))
        startxref = len(out)
        out += b"xref\n0 9\n0000000000 65535 f \n"
        for num in range(1, 9):
            out += (
                b"%010d 00000 n \n" % offsets[num] if num in offsets else b"0000000000 00000 f \n"
            )
        out += b"trailer\n<</Size 9/Root 1 0 R/Info 6 0 R/ID[<AABB><AABB>]>>\n"
    else:
        header = b" ".join(
            b"%d %d" % (num, offset)
            for num, offset in zip(
                OBJECTS,
                (sum(len(b) + 1 for b in list(OBJECTS.values())[:i]) for i in range(5)),
                strict=True,
            )
        )
        packed = zlib.compress(header + b" " + b" ".join(OBJECTS.values()))
        add(
            7,
            b"<</Type/ObjStm/N 5/First %d/Filter/FlateDecode/Length %d>>\nstream\n%s\nendstream"
            % (len(header) + 1, len(packed), packed),
        )
        add(5, stream)
        add(8, b"%d" % len(CONTENT))
        startxref = len(out)
        rows = bytearray(4)
        for num in range(1, 10):
            if num in OBJECTS:
                rows += bytes((2, 0, 7, list(OBJECTS).index(num)))
            else:
                rows += b"\x01" + offsets.get(num, startxref).to_bytes(2) + b"\0"
        parms = b""
        if predictor:
            rows, parms = _png_up(bytes(rows), 4), b"/DecodeParms<</Predictor 12/Columns 4>>"
        packed = zlib.compress(bytes(rows))
        out += (
            b"9 0 obj\n<</Type/XRef/Size 10/W[1 2 1]/Root 1 0 R/Info 6 0 R/ID[<AABB><AABB>]"
            b"/Filter/FlateDecode%s/Length %d>>\nstream\n%s\nendstream\nendobj\n"
            % (parms, len(packed), packed)
        )
    out += b"startxref\n%d\n%%%%EOF\n" % startxref
    return bytes(out)


class AdeptBook:
    """Wraps :func:`build_pdf` output in ADEPT encryption, the way a bookshop would."""

    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        self.key_der = self.private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.TraditionalOpenSSL,  # the adeptkey.der format
            serialization.NoEncryption(),
        )
        self.book_key = bytes(range(1, 17))

    def encrypt(self, plain: bytes, *, version: int = 4, key_prefix: bytes = b"") -> bytes:
        wrapped = self.private_key.public_key().encrypt(
            key_prefix + self.book_key, padding.PKCS1v15()
        )
        rights = (
            '<adept:rights xmlns:adept="http://ns.adobe.com/adept"><licenseToken>'
            f"<adept:encryptedKey>{base64.b64encode(wrapped).decode()}</adept:encryptedKey>"
            "</licenseToken></adept:rights>"
        ).encode()
        deflater = zlib.compressobj(wbits=-15)
        license_ = base64.b64encode(deflater.compress(rights) + deflater.flush())

        return wrap(
            plain,
            Decryptor(self.book_key, obfuscated=version == 3),
            {
                "Filter": Name("EBX_HANDLER"),
                "V": version,
                "Length": 128,
                "EBX_ENCRYPTIONTYPE": 6,
                "ADEPT_LICENSE": license_,
            },
        )


def wrap(plain: bytes, cipher: Decryptor, encrypt: dict) -> bytes:
    """Encrypts ``plain`` and attaches ``encrypt`` as its encryption dictionary."""
    # RC4 is symmetric, so "decrypting" a plain document encrypts it.
    doc = Document(plain)
    doc.decryptor = cipher
    encrypt_num = max(doc.xref) + 1
    doc.xref[encrypt_num] = InUse(0)
    doc._cache[encrypt_num] = encrypt
    out = io.BytesIO()
    write_pdf(doc, out)
    marker = b"/Type /XRef" if doc.uses_xref_streams else b"trailer\n<<"
    encrypted = out.getvalue()
    assert encrypted.count(marker) == 1
    return encrypted.replace(marker, marker + b"/Encrypt %d 0 R " % encrypt_num)


@pytest.fixture(scope="session")
def adept() -> AdeptBook:
    return AdeptBook()


def pinned_machine() -> Machine:
    return Machine(windows=False, user="jane", mac=bytes.fromhex("0a1b2c3d4e5f"))


@pytest.fixture(autouse=True)
def same_machine_everywhere(monkeypatch):
    """decrypt_file() and the CLI probe the computer; pin that to a known answer."""
    monkeypatch.setattr("ineptpdf.fileopen.probe_machine", lambda path="": pinned_machine())
