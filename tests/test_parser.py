import pytest

from ineptpdf.errors import PDFSyntaxError
from ineptpdf.objects import Keyword, Name, Real, Ref
from ineptpdf.parser import Parser
from ineptpdf.writer import serialize


def parse(source: bytes):
    return Parser(source).parse_object()


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (b"42", 42),
        (b"-7 ", -7),
        (b"3.140", Real("3.140")),
        (b"-.5", Real("-.5")),
        (b"true", True),
        (b"null", None),
        (b"/Name", Name("Name")),
        (b"/A#20B#2F", Name("A B/")),
        (b"12 0 R", Ref(12, 0)),
        (b"[1 2 R 3]", [Ref(1, 2), 3]),
        (b"[1 R 3]", [1, Keyword("R"), 3]),
        (b"[1 2 3 0 R]", [1, 2, Ref(3, 0)]),
        (b"(plain)", b"plain"),
        (b"(a(nested)b)", b"a(nested)b"),
        (rb"(\(\)\\\n\101\0619\x)", b"()\\\nA19x"),
        (b"(line\\\r\ncontinued)", b"linecontinued"),
        (b"(raw\r\neol)", b"raw\neol"),
        (b"<48 65 6C6c 6F>", b"Hello"),
        (b"<414>", b"A@"),
        (b"<</A 1/B[/C (d)]/E<</F 2 0 R>>>>", {"A": 1, "B": [Name("C"), b"d"], "E": {"F": Ref(2)}}),
        (b"% comment\n 5", 5),
    ],
)
def test_parse(source, expected):
    assert parse(source) == expected


def test_integer_at_end_of_data_is_not_a_reference():
    assert parse(b"7 0") == 7


@pytest.mark.parametrize("source", [b"(unterminated", b"<</A 1", b"[1 2 endobj", b"<AB"])
def test_malformed(source):
    with pytest.raises(PDFSyntaxError):
        parse(source)


@pytest.mark.parametrize(
    "obj",
    [
        {"Type": Name("A B#/"), "N": [1, -2, Real("0.50"), True, None, Ref(3)]},
        b"bin\x00\xff(\\)\r\n",
        b"",
        [[], {}, [b"x"]],
    ],
)
def test_serialize_round_trip(obj):
    assert parse(serialize(obj)) == obj
