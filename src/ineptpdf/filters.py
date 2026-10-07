"""Stream filters needed to read cross-reference and object streams."""

import base64
import zlib

from .errors import PDFSyntaxError, UnsupportedError
from .objects import Name, Stream


def decode(stream: Stream) -> bytes:
    """Returns the fully decoded payload of ``stream``."""
    filters = _as_list(stream.dict.get("Filter"))
    params = _as_list(stream.dict.get("DecodeParms", stream.dict.get("DP")))
    data = stream.raw
    for i, name in enumerate(filters):
        parms = params[i] if i < len(params) and isinstance(params[i], dict) else {}
        match name:
            case Name("FlateDecode" | "Fl"):
                try:
                    data = zlib.decompressobj().decompress(data)
                except zlib.error as exc:
                    raise PDFSyntaxError(f"corrupt FlateDecode stream: {exc}") from exc
                data = _unpredict(data, parms)
            case Name("ASCIIHexDecode" | "AHx"):
                digits = bytes(c for c in data.partition(b">")[0] if not chr(c).isspace())
                data = bytes.fromhex((digits + b"0" * (len(digits) % 2)).decode("ascii"))
            case Name("ASCII85Decode" | "A85"):
                data = base64.a85decode(data.strip().removeprefix(b"<~").partition(b"~>")[0])
            case Name("Crypt"):
                pass  # already handled by the decryptor
            case _:
                raise UnsupportedError(f"unsupported stream filter: {name!r}")
    return data


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _unpredict(data: bytes, parms: dict) -> bytes:
    predictor = parms.get("Predictor", 1)
    if predictor == 1:
        return data
    if predictor < 10:
        raise UnsupportedError(f"unsupported predictor: {predictor}")
    colors = parms.get("Colors", 1)
    bits = parms.get("BitsPerComponent", 8)
    bpp = max(1, colors * bits // 8)
    width = (parms.get("Columns", 1) * colors * bits + 7) // 8
    out = bytearray()
    prev = bytearray(width)
    for start in range(0, len(data), width + 1):
        kind = data[start]
        row = bytearray(data[start + 1 : start + 1 + width])
        for i in range(len(row)):
            left = row[i - bpp] if i >= bpp else 0
            up = prev[i]
            match kind:
                case 0:
                    break
                case 1:
                    row[i] = (row[i] + left) & 0xFF
                case 2:
                    row[i] = (row[i] + up) & 0xFF
                case 3:
                    row[i] = (row[i] + (left + up) // 2) & 0xFF
                case 4:
                    corner = prev[i - bpp] if i >= bpp else 0
                    p = left + up - corner
                    nearest = min((left, up, corner), key=lambda c: abs(p - c))
                    row[i] = (row[i] + nearest) & 0xFF
                case _:
                    raise PDFSyntaxError(f"invalid PNG predictor row type: {kind}")
        out += row
        prev = row.ljust(width, b"\0")
    return bytes(out)
