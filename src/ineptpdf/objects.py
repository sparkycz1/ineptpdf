"""PDF object model.

Python types map onto PDF types as follows: ``bool``, ``int``, ``None`` (null),
``bytes`` (string), ``list`` (array) and ``dict`` with ``str`` keys (dictionary).
The remaining PDF types get the small classes below.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Name:
    """A name object such as ``/Type``, stored without the slash."""

    value: str


@dataclass(frozen=True, slots=True)
class Real:
    """A real number, kept as its source text so it round-trips exactly."""

    text: str


@dataclass(frozen=True, slots=True)
class Keyword:
    """A bare token that is not a value, e.g. ``obj``, ``R`` or ``endstream``."""

    text: str


@dataclass(frozen=True, slots=True)
class Ref:
    """An indirect reference, ``12 0 R``."""

    num: int
    gen: int = 0


@dataclass(slots=True)
class Stream:
    """A stream object: its dictionary and still-encoded (but decrypted) payload."""

    dict: dict
    raw: bytes = field(repr=False)

    @property
    def type(self) -> str | None:
        kind = self.dict.get("Type")
        return kind.value if isinstance(kind, Name) else None


type PDFObject = bool | int | bytes | list | dict | Name | Real | Keyword | Ref | Stream | None
