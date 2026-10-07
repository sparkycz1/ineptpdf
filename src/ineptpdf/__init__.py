"""Decrypt Adobe ADEPT (Adobe Digital Editions), FileOpen and password-protected PDFs."""

import os
import tempfile
from collections.abc import Callable
from pathlib import Path

from .browser import find_cookie
from .crypto import unlock
from .document import Document
from .errors import DecryptionError, IneptError, PDFSyntaxError, UnsupportedError
from .fileopen import FileOpenOptions
from .writer import XRefMode, write_pdf

__version__ = "9.0.0"
__all__ = [
    "DecryptionError",
    "Document",
    "FileOpenOptions",
    "IneptError",
    "PDFSyntaxError",
    "UnsupportedError",
    "decrypt_file",
    "unlock",
    "write_pdf",
]


def decrypt_file(
    source: str | os.PathLike,
    destination: str | os.PathLike,
    *,
    key: bytes | str | os.PathLike | None = None,
    password: str = "",
    username: str | None = None,
    session: str | None = None,
    prompt: Callable[[str, bool], str] | None = None,
    browser_cookies: bool = False,
    confirm: Callable[[str], bool] | None = None,
    xref: XRefMode = "auto",
) -> None:
    """Writes a decrypted copy of ``source`` to ``destination``.

    ``key`` is the ADEPT private key (``adeptkey.der``), given either as a path or
    as its raw bytes; ``password`` is used for password-protected PDFs instead.

    FileOpen PDFs need neither, but their licence server is contacted and may want
    ``username`` and ``password`` or a ``session`` cookie value; anything missing is
    requested through ``prompt(question, secret)`` if given. With ``browser_cookies``
    the cookie is taken from the user's Firefox profile when the server needs one;
    a cookie that belongs to a different site than the server is sent only if
    ``confirm(question)`` returns true.
    The destination only appears once decryption has fully succeeded.
    """
    if key is not None and not isinstance(key, bytes):
        key = Path(key).read_bytes()
    doc = Document(Path(source).read_bytes())
    if doc.encryption_filter is None:
        raise IneptError("the document is not encrypted")
    fileopen = FileOpenOptions(
        path=os.path.abspath(source),
        username=username,
        password=password or None,
        session=session,
        prompt=prompt,
        find_cookie=find_cookie if browser_cookies else None,
        confirm=confirm,
    )
    unlock(doc, key=key, password=password, fileopen=fileopen)

    destination = Path(destination)
    fd, temp_name = tempfile.mkstemp(dir=destination.parent, prefix=destination.name, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as out:
            write_pdf(doc, out, xref)
        os.replace(temp_name, destination)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise
