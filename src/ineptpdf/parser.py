"""Tokenizer and recursive-descent parser for PDF syntax, working on a bytes buffer."""

import re

from .errors import PDFSyntaxError
from .objects import Keyword, Name, PDFObject, Real, Ref

_SKIP = re.compile(rb"(?:[\x00\t\n\x0c\r ]+|%[^\r\n]*)*")
_REGULAR = re.compile(rb"[^\x00\t\n\x0c\r ()<>\[\]{}/%]*")
_INT = re.compile(rb"[+-]?\d+\Z")
_REAL = re.compile(rb"[+-]?(?:\d+\.\d*|\.\d+)\Z")
_NAME_ESCAPE = re.compile(rb"#([0-9a-fA-F]{2})")
_STRING_SPECIAL = re.compile(rb"[()\\\r]")
_NOT_HEX = re.compile(rb"[^0-9a-fA-F]")
_ESCAPES = {
    ord("n"): b"\n",
    ord("r"): b"\r",
    ord("t"): b"\t",
    ord("b"): b"\b",
    ord("f"): b"\f",
}

ARRAY_BEGIN = Keyword("[")
ARRAY_END = Keyword("]")
DICT_BEGIN = Keyword("<<")
DICT_END = Keyword(">>")
KW_R = Keyword("R")
KW_OBJ = Keyword("obj")
KW_STREAM = Keyword("stream")
_TERMINATORS = {ARRAY_END, DICT_END, Keyword("endobj"), Keyword("endstream"), KW_OBJ}


class EndOfData(PDFSyntaxError):
    """The buffer ended in the middle of an object."""


class Parser:
    """Reads PDF objects from ``data`` starting at ``pos``."""

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    # -- tokens ---------------------------------------------------------------

    def next_token(self) -> PDFObject:
        data = self.data
        self.pos = pos = _SKIP.match(data, self.pos).end()
        if pos >= len(data):
            raise EndOfData("unexpected end of data")
        char = data[pos : pos + 1]
        match char:
            case b"/":
                end = _REGULAR.match(data, pos + 1).end()
                self.pos = end
                raw = _NAME_ESCAPE.sub(lambda m: bytes.fromhex(m[1].decode()), data[pos + 1 : end])
                return Name(raw.decode("latin-1"))
            case b"(":
                return self._literal_string()
            case b"<":
                if data[pos + 1 : pos + 2] == b"<":
                    self.pos = pos + 2
                    return DICT_BEGIN
                return self._hex_string()
            case b">":
                if data[pos + 1 : pos + 2] == b">":
                    self.pos = pos + 2
                    return DICT_END
                self.pos = pos + 1
                return Keyword(">")
            case b"[" | b"]" | b"{" | b"}" | b")":
                self.pos = pos + 1
                return Keyword(char.decode())
        end = _REGULAR.match(data, pos).end()
        self.pos = end
        token = data[pos:end]
        if _INT.match(token):
            return int(token)
        if _REAL.match(token):
            return Real(token.decode())
        match token:
            case b"true":
                return True
            case b"false":
                return False
            case b"null":
                return None
        return Keyword(token.decode("latin-1"))

    def _literal_string(self) -> bytes:
        data = self.data
        pos = self.pos + 1
        depth = 1
        out = bytearray()
        while True:
            m = _STRING_SPECIAL.search(data, pos)
            if not m:
                raise EndOfData("unterminated string")
            out += data[pos : m.start()]
            pos = m.end()
            match m[0]:
                case b"(":
                    depth += 1
                    out += b"("
                case b")":
                    depth -= 1
                    if not depth:
                        self.pos = pos
                        return bytes(out)
                    out += b")"
                case b"\r":  # an unescaped end-of-line always reads as \n
                    if data[pos : pos + 1] == b"\n":
                        pos += 1
                    out += b"\n"
                case _:  # backslash
                    code = data[pos] if pos < len(data) else 0
                    if code in _ESCAPES:
                        out += _ESCAPES[code]
                        pos += 1
                    elif 0x30 <= code <= 0x37:
                        end = pos + 1
                        while end < pos + 3 and data[end : end + 1] in b"01234567":
                            end += 1
                        out.append(int(data[pos:end], 8) & 0xFF)
                        pos = end
                    elif code == 0x0D:  # line continuation
                        pos += 2 if data[pos + 1 : pos + 2] == b"\n" else 1
                    elif code == 0x0A:
                        pos += 1
                    else:  # \( \) \\ and unknown escapes: keep the character
                        out += data[pos : pos + 1]
                        pos += 1

    def _hex_string(self) -> bytes:
        end = self.data.find(b">", self.pos)
        if end < 0:
            raise EndOfData("unterminated hex string")
        digits = _NOT_HEX.sub(b"", self.data[self.pos + 1 : end])
        self.pos = end + 1
        if len(digits) % 2:
            digits += b"0"
        return bytes.fromhex(digits.decode())

    # -- objects --------------------------------------------------------------

    def parse_object(self) -> PDFObject:
        return self._build(self.next_token())

    def _build(self, token: PDFObject) -> PDFObject:
        if token == ARRAY_BEGIN:
            return self._collect(ARRAY_END)
        if token == DICT_BEGIN:
            items = self._collect(DICT_END)
            return {
                key.value if isinstance(key, Name) else str(key): value
                for key, value in zip(items[::2], items[1::2], strict=False)
            }
        if isinstance(token, int) and not isinstance(token, bool):
            # "12 0 R" is a reference; anything else is just an integer.
            saved = self.pos
            try:
                gen = self.next_token()
                if isinstance(gen, int) and not isinstance(gen, bool) and self.next_token() == KW_R:
                    return Ref(token, gen)
            except EndOfData:
                pass
            self.pos = saved
        return token

    def _collect(self, end: Keyword) -> list:
        items = []
        while True:
            token = self.next_token()
            if token == end:
                return items
            if isinstance(token, Keyword) and token in _TERMINATORS:
                raise PDFSyntaxError(f"unexpected {token.text!r} at offset {self.pos}")
            items.append(self._build(token))

    def parse_indirect_header(self) -> tuple[int, int]:
        """Consumes ``N G obj`` and returns ``(N, G)``."""
        start = self.pos
        num, gen, kw = self.next_token(), self.next_token(), self.next_token()
        if not (isinstance(num, int) and isinstance(gen, int) and kw == KW_OBJ):
            raise PDFSyntaxError(f"no indirect object at offset {start}")
        return num, gen
