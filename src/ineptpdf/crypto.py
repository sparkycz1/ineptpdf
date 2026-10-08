"""Security handlers: Adobe ADEPT, the Standard password handler and FileOpen."""

import base64
import binascii
import logging
import zlib
from dataclasses import dataclass
from hashlib import md5
from typing import Literal
from xml.etree import ElementTree

from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_pem_private_key,
)

from .document import Document, InUse
from .errors import DecryptionError, IneptError, UnsupportedError
from .fileopen import FileOpenOptions, fetch_key
from .objects import Name, Stream

log = logging.getLogger("ineptpdf")

type CipherName = Literal["rc4", "aes", "identity"]

_PASSWORD_PADDING = bytes.fromhex(
    "28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a"
)
_ADEPT_KEY_TAG = ".//{http://ns.adobe.com/adept}encryptedKey"
_RC4_KEY_SIZES = {5, 7, 8, 10, 16, 20, 24, 32}  # what the cryptography package accepts


def rc4(key: bytes, data: bytes) -> bytes:
    if len(key) in _RC4_KEY_SIZES:
        return Cipher(ARC4(key), mode=None).decryptor().update(data)
    # Unusual key length: fall back to a (slow) pure-Python implementation.
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    out = bytearray(len(data))
    i = j = 0
    for n, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out[n] = byte ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(out)


def aes_cbc(key: bytes, data: bytes) -> bytes:
    """Decrypts ``IV || ciphertext`` and strips the PKCS#7 padding."""
    if len(data) < 16:
        return data  # not AES output; some writers leave empty strings alone
    body = data[16 : len(data) - len(data) % 16]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(data[:16])).decryptor()
    plain = decryptor.update(body) + decryptor.finalize()
    if plain and 1 <= plain[-1] <= 16:
        plain = plain[: -plain[-1]]
    return plain


@dataclass(frozen=True, slots=True)
class Decryptor:
    """Decrypts the strings and streams of one document."""

    key: bytes
    string_cipher: CipherName = "rc4"
    stream_cipher: CipherName = "rc4"
    obfuscated: bool = False  # ADEPT's alternative per-object key schedule
    direct_key: bool = False  # AES-256 style: the file key is used for every object
    encrypt_metadata: bool = True

    def decrypt_string(self, num: int, gen: int, data: bytes) -> bytes:
        return self._apply(self.string_cipher, num, gen, data)

    def decrypt_stream(self, num: int, gen: int, stream: Stream) -> bytes:
        if stream.type == "Metadata" and not self.encrypt_metadata:
            return stream.raw
        match stream.dict.get("Filter"):
            case Name("Crypt") | [Name("Crypt"), *_]:
                parms = stream.dict.get("DecodeParms")
                parms = parms[0] if isinstance(parms, list) and parms else parms
                name = parms.get("Name") if isinstance(parms, dict) else None
                if name in (None, Name("Identity")):
                    return stream.raw
        return self._apply(self.stream_cipher, num, gen, stream.raw)

    def _apply(self, cipher: CipherName, num: int, gen: int, data: bytes) -> bytes:
        match cipher:
            case "rc4":
                return rc4(self._object_key(num, gen, cipher), data)
            case "aes":
                return aes_cbc(self._object_key(num, gen, cipher), data)
        return data

    def _object_key(self, num: int, gen: int, cipher: CipherName) -> bytes:
        if self.direct_key:
            return self.key
        if self.obfuscated:
            n = ((num ^ 0x3569AC) & 0xFFFFFFFF).to_bytes(4, "little")
            g = ((gen ^ 0xCA96) & 0xFFFFFFFF).to_bytes(4, "little")
            material = self.key + bytes((n[0], g[0], n[1], g[1], n[2])) + b"sAlT"
        else:
            material = self.key + num.to_bytes(4, "little")[:3] + gen.to_bytes(4, "little")[:2]
            if cipher == "aes":
                material += b"sAlT"
        return md5(material).digest()[: min(len(self.key) + 5, 16)]


def unlock(
    doc: Document,
    *,
    key: bytes | None = None,
    password: str = "",
    fileopen: FileOpenOptions | None = None,
) -> None:
    """Installs a decryptor on ``doc``. Does nothing for unencrypted documents."""
    match doc.encryption_filter:
        case None:
            return
        case "EBX_HANDLER":
            if key is None:
                raise DecryptionError("this is an ADEPT-protected PDF; a key file is required")
            chosen = _adept(doc.encrypt, key)
            other = Decryptor(chosen.key, obfuscated=not chosen.obfuscated)
            doc.decryptor = _working(doc, [chosen, other], "this book")
        case "Standard":
            doc.decryptor = _standard(doc.encrypt, doc.doc_id, password)
        case "FOPN_foweb":
            options = fileopen or FileOpenOptions(password=password or None)
            doc.decryptor = _working(
                doc,
                _fileopen_ciphers(doc.encrypt, fetch_key(doc.encrypt, options)),
                "this document",
            )
        case "FOPN_fLock" | "Adobe.APS" as name:
            raise UnsupportedError(f"{name} is not supported")
        case name:
            raise UnsupportedError(f"unknown security handler: {name}")


def _working(doc: Document, candidates: list[Decryptor], what: str) -> Decryptor:
    """The first candidate that demonstrably decrypts ``doc``'s compressed streams."""
    verdicts = [_decrypts(doc, candidate) for candidate in candidates]
    log.debug("cipher candidates: %s", list(zip(map(_describe, candidates), verdicts, strict=True)))
    for candidate, verdict in zip(candidates, verdicts, strict=True):
        if verdict:
            return candidate
    if all(verdict is False for verdict in verdicts):
        raise DecryptionError(f"the key does not decrypt the contents of {what}")
    return candidates[0]  # nothing in the file to test against


def _describe(decryptor: Decryptor) -> str:
    schedule = "direct" if decryptor.direct_key else "obfuscated" if decryptor.obfuscated else "md5"
    return f"{decryptor.stream_cipher}/{schedule}/{len(decryptor.key) * 8}-bit"


def _decrypts(doc: Document, candidate: Decryptor) -> bool | None:
    """Whether ``candidate`` turns Flate streams into valid deflate data (None: no sample)."""
    saved = doc.decryptor, dict(doc._cache), dict(doc._object_streams)
    doc.decryptor = candidate
    good = bad = scanned = 0
    try:
        for num, entry in doc.xref.items():
            if good + bad >= 5 or scanned >= 400:
                break
            if not isinstance(entry, InUse) or num == doc.encrypt_num:
                continue
            scanned += 1
            try:
                obj = doc.getobj(num)
            except (IneptError, ValueError):
                continue
            if not isinstance(obj, Stream) or obj.type == "XRef" or not obj.raw:
                continue
            first = obj.dict.get("Filter")
            first = first[0] if isinstance(first, list) and first else first
            if first not in (Name("FlateDecode"), Name("Fl")):
                continue
            try:
                zlib.decompressobj().decompress(obj.raw[:65536])
                good += 1
            except zlib.error:
                bad += 1
    finally:
        doc.decryptor, doc._cache, doc._object_streams = saved
    return None if not good + bad else good > bad


def _fileopen_ciphers(encrypt: dict, key: bytes) -> list[Decryptor]:
    """What the encryption dictionary announces first, then the other known schemes."""
    rc4_md5 = Decryptor(key)  # all that ineptpdf 8.4.51 knew
    aes_md5 = Decryptor(key, "aes", "aes")
    candidates = [rc4_md5, aes_md5]
    if len(key) in (16, 24, 32):
        candidates.append(Decryptor(key, "aes", "aes", direct_key=True))
    if encrypt.get("V", 1) >= 4:
        candidates.reverse()
    return candidates


# -- Adobe ADEPT ---------------------------------------------------------------


def _adept(encrypt: dict, key_data: bytes) -> Decryptor:
    try:
        if key_data.lstrip().startswith(b"-----BEGIN"):
            numbers = load_pem_private_key(key_data, password=None).private_numbers()
        else:
            numbers = load_der_private_key(key_data, password=None).private_numbers()
        modulus = numbers.public_numbers.n
    except (ValueError, TypeError, AttributeError) as exc:
        raise DecryptionError(f"cannot read the key file as an RSA private key: {exc}") from exc

    try:
        rights = zlib.decompress(base64.b64decode(encrypt["ADEPT_LICENSE"]), -15)
        wrapped = base64.b64decode(ElementTree.fromstring(rights).findtext(_ADEPT_KEY_TAG))
    except (KeyError, TypeError, binascii.Error, zlib.error, ElementTree.ParseError) as exc:
        raise DecryptionError("the ADEPT license in this PDF is missing or corrupt") from exc

    # RSA with PKCS#1 v1.5 padding: 00 02 <non-zero padding> 00 <book key>
    size = (modulus.bit_length() + 7) // 8
    block = pow(int.from_bytes(wrapped), numbers.d, modulus).to_bytes(size)
    separator = block.find(b"\0", 2)
    if block[:2] != b"\0\x02" or separator < 0:
        raise DecryptionError(
            "this key does not open this book (was it licensed to a different Adobe ID?)"
        )
    book_key = block[separator + 1 :]

    if encrypt.get("V", 4) == 3:
        version = 3
    elif encrypt.get("V", 4) < 4 or encrypt.get("EBX_ENCRYPTIONTYPE", 6) < 6:
        version, book_key = book_key[0], book_key[1:]
    else:
        version = 2
    length = encrypt.get("Length", 0) // 8
    if not book_key or (length and len(book_key) != length):
        raise DecryptionError("the decrypted book key has an unexpected length")
    return Decryptor(book_key, obfuscated=version == 3)


# -- Standard security handler (revisions 2-4) ---------------------------------


def _standard(encrypt: dict, doc_id: bytes, password: str) -> Decryptor:
    version, revision = encrypt.get("V", 0), encrypt.get("R", 2)
    if version not in (1, 2, 4) or revision not in (2, 3, 4):
        raise UnsupportedError(
            f"password encryption V={version} R={revision} is not supported "
            "(AES-256 files can be opened with qpdf)"
        )
    try:
        owner, user = encrypt["O"], encrypt["U"]
        permissions = (encrypt["P"] & 0xFFFFFFFF).to_bytes(4, "little")
    except (KeyError, TypeError) as exc:
        raise DecryptionError("the encryption dictionary is incomplete") from exc
    encrypt_metadata = encrypt.get("EncryptMetadata", True) is not False
    if version == 1 or revision == 2:
        size = 5
    else:
        size = 16 if version == 4 else encrypt.get("Length", 40) // 8

    def file_key(padded: bytes) -> bytes:
        material = padded + owner + permissions + doc_id
        if revision >= 4 and not encrypt_metadata:
            material += b"\xff\xff\xff\xff"
        key = md5(material).digest()
        if revision >= 3:
            for _ in range(50):
                key = md5(key[:size]).digest()
        return key[:size]

    def opens(key: bytes) -> bool:
        if revision == 2:
            return rc4(key, _PASSWORD_PADDING) == user
        check = rc4(key, md5(_PASSWORD_PADDING + doc_id).digest())
        for i in range(1, 20):
            check = rc4(bytes(b ^ i for b in key), check)
        return check == user[:16]

    def user_password_from_owner(padded: bytes) -> bytes:
        key = md5(padded).digest()
        if revision >= 3:
            for _ in range(50):
                key = md5(key).digest()
        key = key[:size]
        if revision == 2:
            return rc4(key, owner)
        result = owner
        for i in range(19, -1, -1):
            result = rc4(bytes(b ^ i for b in key), result)
        return result

    try:
        raw_password = password.encode("latin-1")
    except UnicodeEncodeError:
        raw_password = password.encode("utf-8")
    padded = (raw_password + _PASSWORD_PADDING)[:32]
    for candidate in (padded, user_password_from_owner(padded)):
        key = file_key(candidate[:32])
        if opens(key):
            break
    else:
        raise DecryptionError("incorrect password")

    if version < 4:
        return Decryptor(key, encrypt_metadata=encrypt_metadata)
    return Decryptor(
        key,
        string_cipher=_crypt_filter(encrypt, "StrF"),
        stream_cipher=_crypt_filter(encrypt, "StmF"),
        encrypt_metadata=encrypt_metadata,
    )


def _crypt_filter(encrypt: dict, which: str) -> CipherName:
    name = encrypt.get(which, Name("Identity"))
    if name == Name("Identity"):
        return "identity"
    filters = encrypt.get("CF")
    spec = filters.get(name.value) if isinstance(filters, dict) and isinstance(name, Name) else None
    method = spec.get("CFM", Name("None")) if isinstance(spec, dict) else None
    match method:
        case Name("V2"):
            return "rc4"
        case Name("AESV2"):
            return "aes"
        case Name("None"):
            return "identity"
    raise UnsupportedError(f"unsupported crypt filter method: {method!r}")
