"""Serialises a (decrypted) document back into a PDF file."""

import re
import zlib
from typing import BinaryIO, Literal

from .document import Compressed, Document
from .objects import Keyword, Name, PDFObject, Real, Ref, Stream

type XRefMode = Literal["auto", "table", "stream"]

_NAME_IRREGULAR = re.compile(rb"[^!-~]|[#()<>\[\]{}/%]")
_STRING_SPECIAL = re.compile(rb"[\\()\r\n]")
_STRING_ESCAPES = {b"\\": b"\\\\", b"(": b"\\(", b")": b"\\)", b"\r": b"\\r", b"\n": b"\\n"}
# Trailer keys that describe the *old* cross-reference data or encryption.
_STALE_TRAILER_KEYS = frozenset(
    ("Prev", "XRefStm", "Encrypt", "Type", "W", "Index", "Length", "Filter", "DecodeParms", "DP")
)


def serialize(obj: PDFObject) -> bytes:
    match obj:
        case None:
            return b"null"
        case bool():
            return b"true" if obj else b"false"
        case int():
            return b"%d" % obj
        case Real(text) | Keyword(text):
            return text.encode("latin-1")
        case Name(value):
            escaped = _NAME_IRREGULAR.sub(lambda m: b"#%02x" % m[0][0], value.encode("latin-1"))
            return b"/" + escaped
        case bytes():
            return b"(" + _STRING_SPECIAL.sub(lambda m: _STRING_ESCAPES[m[0]], obj) + b")"
        case Ref(num):
            return b"%d 0 R" % num  # every object is written with generation 0
        case list():
            return b"[" + b" ".join(map(serialize, obj)) + b"]"
        case dict():
            if "ResFork" in obj and "Subtype" not in obj and isinstance(obj.get("Type"), int):
                # Malformed Mac OS resource forks: /Type should have been /Subtype.
                obj = {("Subtype" if k == "Type" else k): v for k, v in obj.items()}
            items = (serialize(Name(k)) + b" " + serialize(v) for k, v in obj.items())
            return b"<<" + b" ".join(items) + b">>"
        case Stream(dic, raw):
            head = serialize(dic | {"Length": len(raw)})
            return head + b"\nstream\n" + raw + b"\nendstream"
    raise TypeError(f"cannot serialise {type(obj).__name__}")


def write_pdf(doc: Document, out: BinaryIO, xref: XRefMode = "auto") -> None:
    """Writes every object of ``doc`` to ``out``, without the encryption dictionary.

    ``xref`` selects the cross-reference format: ``"stream"`` keeps object streams
    intact (smaller output, PDF 1.5+), ``"table"`` unpacks them into a classic
    table, and ``"auto"`` follows whatever the input used.
    """
    use_stream = doc.uses_xref_streams if xref == "auto" else xref == "stream"
    position = 0

    def emit(chunk: bytes) -> None:
        nonlocal position
        out.write(chunk)
        position += len(chunk)

    emit(doc.header + b"\n%\xe2\xe3\xcf\xd3\n")
    entries: dict[int, int | Compressed] = {}
    for num in sorted(doc.xref):
        entry = doc.xref[num]
        if num == 0 or num == doc.encrypt_num or entry is None:
            continue
        if use_stream and isinstance(entry, Compressed):
            entries[num] = entry  # stays inside its object stream
            continue
        obj = doc.getobj(num)
        if obj is None:
            continue
        if isinstance(obj, Stream) and (
            obj.type == "XRef" or (obj.type == "ObjStm" and not use_stream)
        ):
            continue  # superseded by the cross-reference data written below
        entries[num] = position
        emit(b"%d 0 obj\n" % num + serialize(obj) + b"\nendobj\n")

    trailer = {k: v for k, v in doc.trailer.items() if k not in _STALE_TRAILER_KEYS}
    size = max(entries, default=0) + 1
    startxref = position
    if use_stream:
        entries[size] = startxref  # the cross-reference stream describes itself
        size += 1
        width2 = max(1, (max(startxref, size).bit_length() + 7) // 8)
        indexes = [e.index for e in entries.values() if isinstance(e, Compressed)]
        width3 = max(1, (max(indexes, default=0).bit_length() + 7) // 8)
        rows = bytearray()
        for num in range(size):
            match entries.get(num):
                case None:
                    fields = (0, 0, 0)
                case Compressed(stream_num, index):
                    fields = (2, stream_num, index)
                case offset:
                    fields = (1, offset, 0)
            rows += fields[0].to_bytes(1) + fields[1].to_bytes(width2) + fields[2].to_bytes(width3)
        trailer |= {
            "Type": Name("XRef"),
            "Size": size,
            "W": [1, width2, width3],
            "Filter": Name("FlateDecode"),
        }
        emit(b"%d 0 obj\n" % (size - 1))
        emit(serialize(Stream(trailer, zlib.compress(bytes(rows)))) + b"\nendobj\n")
    else:
        emit(b"xref\n0 %d\n" % size)
        for num in range(size):
            offset = entries.get(num)
            emit(b"%010d 00000 n \n" % offset if offset is not None else b"0000000000 65535 f \n")
        emit(b"trailer\n" + serialize(trailer | {"Size": size}) + b"\n")
    emit(b"startxref\n%d\n%%%%EOF\n" % startxref)
