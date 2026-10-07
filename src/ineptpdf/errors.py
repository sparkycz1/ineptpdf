"""Exception hierarchy."""


class IneptError(Exception):
    """Base class for every error raised by this package."""


class PDFSyntaxError(IneptError):
    """The input is not a PDF file we can parse."""


class DecryptionError(IneptError):
    """The key or password does not open the document."""


class UnsupportedError(IneptError):
    """The document uses a feature this tool does not implement."""
