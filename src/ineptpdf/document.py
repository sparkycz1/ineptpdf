"""Random-access view of a PDF file: cross-reference data and object loading."""

import re
import zlib
from dataclasses import dataclass

from . import filters
from .errors import IneptError, PDFSyntaxError
from .objects import Keyword, Name, PDFObject, Ref, Stream
from .parser import KW_STREAM, EndOfData, Parser

_HEADER = re.compile(rb"%PDF-\d\.\d")
_ENDSTREAM = re.compile(rb"[\x00\t\n\x0c\r ]*endstream")
_OBJ = re.compile(rb"(?<![0-9])(\d+)[\x00\t\n\x0c\r ]+(\d+)[\x00\t\n\x0c\r ]+obj\b")
_DAMAGED = (IneptError, ArithmeticError, LookupError, TypeError, ValueError, zlib.error)


@dataclass(frozen=True, slots=True)
class InUse:
    """Cross-reference entry for an object stored at a byte offset."""

    offset: int
    gen: int = 0


@dataclass(frozen=True, slots=True)
class Compressed:
    """Cross-reference entry for an object stored inside an object stream."""

    stream_num: int
    index: int


class Document:
    def __init__(self, data: bytes):
        header = _HEADER.search(data, 0, 1024)
        if not header:
            raise PDFSyntaxError("not a PDF file")
        self.data = data
        self.header: bytes = header[0]
        self.xref: dict[int, InUse | Compressed | None] = {}
        self.trailer: dict = {}
        self.uses_xref_streams = False
        self.decryptor = None  # set by crypto.unlock()
        self._cache: dict[int, PDFObject] = {}
        self._object_streams: dict[int, list] = {}

        try:
            self._read_xref_chain(self._find_startxref())
        except _DAMAGED:
            self._rebuild_xref()
        if "Root" not in self.trailer:
            raise PDFSyntaxError("no /Root object - is this really a PDF?")

        encrypt = self.trailer.get("Encrypt")
        self.encrypt_num: int | None = encrypt.num if isinstance(encrypt, Ref) else None
        self.encrypt: dict | None = self.resolve_all(encrypt)
        ids = self.resolve_all(self.trailer.get("ID"))
        self.doc_id: bytes = ids[0] if isinstance(ids, list) and ids else b""

    # -- object access --------------------------------------------------------

    def getobj(self, num: int) -> PDFObject:
        """Loads (and, once unlocked, decrypts) indirect object ``num``."""
        if num in self._cache:
            return self._cache[num]
        match self.xref.get(num):
            case InUse(offset):
                _, gen, obj = self._read_indirect(offset)
                if self.decryptor and num != self.encrypt_num:
                    obj = self._decrypt(obj, num, gen)
            case Compressed(stream_num, index):
                objects = self._object_stream(stream_num)
                obj = objects[index] if index < len(objects) else None
            case _:
                obj = None
        if not isinstance(obj, Stream):  # streams can be huge; don't hold on to them
            self._cache[num] = obj
        return obj

    def resolve(self, obj: PDFObject) -> PDFObject:
        """Follows indirect references until a direct object is reached."""
        for _ in range(32):
            if not isinstance(obj, Ref):
                return obj
            obj = self.getobj(obj.num)
        raise PDFSyntaxError("circular indirect reference")

    def resolve_all(self, obj: PDFObject, depth: int = 8) -> PDFObject:
        """Like :meth:`resolve`, but also resolves nested arrays and dictionaries."""
        obj = self.resolve(obj)
        if depth:
            if isinstance(obj, list):
                return [self.resolve_all(v, depth - 1) for v in obj]
            if isinstance(obj, dict):
                return {k: self.resolve_all(v, depth - 1) for k, v in obj.items()}
        return obj

    def _read_indirect(self, offset: int) -> tuple[int, int, PDFObject]:
        parser = Parser(self.data, offset)
        num, gen = parser.parse_indirect_header()
        obj = parser.parse_object()
        if isinstance(obj, dict):
            try:
                is_stream = parser.next_token() == KW_STREAM
            except EndOfData:
                is_stream = False
            if is_stream:
                obj = Stream(obj, self._stream_payload(obj, parser.pos))
        return num, gen, obj

    def _stream_payload(self, dic: dict, pos: int) -> bytes:
        data = self.data
        if data[pos : pos + 2] == b"\r\n":
            pos += 2
        elif data[pos : pos + 1] in (b"\n", b"\r"):
            pos += 1
        try:
            length = self.resolve(dic.get("Length"))
        except PDFSyntaxError:
            length = None
        if isinstance(length, int) and length >= 0 and _ENDSTREAM.match(data, pos + length):
            return data[pos : pos + length]
        # /Length is missing or wrong: take everything up to "endstream".
        end = data.find(b"endstream", pos)
        if end < 0:
            raise PDFSyntaxError(f"unterminated stream at offset {pos}")
        raw = data[pos:end]
        if raw.endswith(b"\r\n"):
            return raw[:-2]
        return raw[:-1] if raw.endswith((b"\n", b"\r")) else raw

    def _decrypt(self, obj: PDFObject, num: int, gen: int) -> PDFObject:
        dec = self.decryptor

        def walk(value):
            match value:
                case bytes():
                    return dec.decrypt_string(num, gen, value)
                case list():
                    return [walk(v) for v in value]
                case dict():
                    return {k: walk(v) for k, v in value.items()}
                case Stream(type="XRef"):
                    return value  # cross-reference streams are never encrypted
                case Stream():
                    return Stream(walk(value.dict), dec.decrypt_stream(num, gen, value))
            return value

        return walk(obj)

    def _object_stream(self, num: int) -> list:
        if num not in self._object_streams:
            stream = self.getobj(num)
            if not isinstance(stream, Stream):
                raise PDFSyntaxError(f"object {num} is not an object stream")
            count = self.resolve(stream.dict.get("N"))
            first = self.resolve(stream.dict.get("First"))
            if not isinstance(count, int) or not isinstance(first, int):
                raise PDFSyntaxError(f"object stream {num} lacks /N or /First")
            parser = Parser(filters.decode(stream))
            offsets = [(parser.next_token(), parser.next_token())[1] for _ in range(count)]
            objects = []
            for offset in offsets:
                parser.pos = first + offset
                objects.append(parser.parse_object())
            self._object_streams[num] = objects
        return self._object_streams[num]

    # -- cross-reference data -------------------------------------------------

    def _find_startxref(self) -> int:
        pos = self.data.rfind(b"startxref")
        if pos < 0:
            raise PDFSyntaxError("startxref not found")
        offset = Parser(self.data, pos + len(b"startxref")).next_token()
        if not isinstance(offset, int):
            raise PDFSyntaxError("invalid startxref")
        return offset

    def _read_xref_chain(self, start: int) -> None:
        # Newest section first; whatever is seen first wins.
        pending, seen = [start], set()
        while pending:
            pos = pending.pop(0)
            if pos in seen:
                continue
            seen.add(pos)
            trailer = self._read_xref_section(pos)
            for key, value in trailer.items():
                self.trailer.setdefault(key, value)
            pending[:0] = [
                trailer[k] for k in ("XRefStm", "Prev") if isinstance(trailer.get(k), int)
            ]

    def _read_xref_section(self, pos: int) -> dict:
        parser = Parser(self.data, pos)
        if parser.next_token() == Keyword("xref"):
            return self._read_xref_table(parser)
        _, _, stream = self._read_indirect(pos)
        if not isinstance(stream, Stream) or stream.type != "XRef":
            raise PDFSyntaxError(f"no cross-reference data at offset {pos}")
        self.uses_xref_streams = True
        self._read_xref_stream(stream)
        return stream.dict

    def _read_xref_table(self, parser: Parser) -> dict:
        while (token := parser.next_token()) != Keyword("trailer"):
            count = parser.next_token()
            if not isinstance(token, int) or not isinstance(count, int):
                raise PDFSyntaxError("malformed cross-reference table")
            for num in range(token, token + count):
                offset, gen, kind = parser.next_token(), parser.next_token(), parser.next_token()
                if not isinstance(offset, int) or not isinstance(gen, int):
                    raise PDFSyntaxError("malformed cross-reference entry")
                self.xref.setdefault(num, InUse(offset, gen) if kind == Keyword("n") else None)
        trailer = parser.parse_object()
        if not isinstance(trailer, dict):
            raise PDFSyntaxError("malformed trailer")
        return trailer

    def _read_xref_stream(self, stream: Stream) -> None:
        w1, w2, w3 = stream.dict["W"]
        index = stream.dict.get("Index") or [0, stream.dict["Size"]]
        data = filters.decode(stream)
        pos = 0
        for first, count in zip(index[::2], index[1::2], strict=True):
            for num in range(first, first + count):
                kind = int.from_bytes(data[pos : pos + w1]) if w1 else 1
                f2 = int.from_bytes(data[pos + w1 : pos + w1 + w2])
                f3 = int.from_bytes(data[pos + w1 + w2 : pos + w1 + w2 + w3])
                pos += w1 + w2 + w3
                match kind:
                    case 1:
                        entry = InUse(f2, f3)
                    case 2:
                        entry = Compressed(f2, f3)
                    case _:
                        entry = None
                self.xref.setdefault(num, entry)

    def _rebuild_xref(self) -> None:
        """Fallback for damaged files: scan for ``N G obj`` and ``trailer``."""
        self.xref = {int(m[1]): InUse(m.start(), int(m[2])) for m in _OBJ.finditer(self.data)}
        self.trailer = {}
        self.uses_xref_streams = False
        for m in re.finditer(rb"\btrailer\b", self.data):
            try:
                trailer = Parser(self.data, m.end()).parse_object()
            except PDFSyntaxError:
                continue
            if isinstance(trailer, dict):
                self.trailer.update(trailer)
        if not self.xref or "Root" not in self.trailer:
            raise PDFSyntaxError("cross-reference data is damaged beyond repair")
        self.trailer.pop("Prev", None)
        self.trailer.pop("XRefStm", None)

    @property
    def encryption_filter(self) -> str | None:
        """Name of the security handler, or ``None`` for an unencrypted file."""
        if self.encrypt is None:
            return None
        name = self.encrypt.get("Filter")
        return name.value if isinstance(name, Name) else "?"
