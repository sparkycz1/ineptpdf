"""Command-line interface."""

import argparse
import getpass
import logging
import sys
from pathlib import Path

from . import Document, __version__, decrypt_file
from .errors import DecryptionError, IneptError
from .fileopen import describe

DEFAULT_KEY = Path("adeptkey.der")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ineptpdf",
        description="Decrypt Adobe ADEPT (Adobe Digital Editions), FileOpen and "
        "password-protected PDFs.",
    )
    parser.add_argument("input", type=Path, nargs="?", help="encrypted PDF")
    parser.add_argument("-o", "--output", type=Path, help="default: INPUT.decrypted.pdf")
    parser.add_argument(
        "-k", "--key", type=Path, help=f"ADEPT private key (default: ./{DEFAULT_KEY} if present)"
    )
    parser.add_argument(
        "-p", "--password", help="password (password-protected PDFs, FileOpen login)"
    )
    parser.add_argument("-u", "--username", help="user name, if a FileOpen server asks for one")
    parser.add_argument(
        "--session", help="FileOpen session cookie value (default: looked up in Firefox)"
    )
    parser.add_argument(
        "--no-browser-cookies",
        action="store_true",
        help="never read cookies from the Firefox profile",
    )
    parser.add_argument(
        "--info", action="store_true", help="show how the PDF is protected and exit"
    )
    parser.add_argument(
        "--xref",
        choices=("auto", "table", "stream"),
        default="auto",
        help="cross-reference format of the output (default: same as the input)",
    )
    parser.add_argument("-f", "--force", action="store_true", help="overwrite an existing output")
    parser.add_argument("--gui", action="store_true", help="open the graphical interface")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _prompt(question: str, secret: bool) -> str:
    return getpass.getpass(f"{question}: ") if secret else input(f"{question}: ")


def _confirm(question: str) -> bool:
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")


def _show_info(path: Path) -> int:
    try:
        doc = Document(path.read_bytes())
        print(f"Protection: {doc.encryption_filter or 'none'}")
        if doc.encryption_filter == "FOPN_foweb":
            for name, value in sorted(describe(doc.encrypt).items()):
                print(f"  {name} = {value}")
    except (IneptError, OSError) as exc:
        print(f"ineptpdf: error: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.gui:
        from .gui import run

        return run()
    if args.input is None:
        parser.error("the following arguments are required: input")

    if args.info:
        return _show_info(args.input)
    output = args.output or args.input.with_suffix(".decrypted.pdf")
    key = args.key or (DEFAULT_KEY if DEFAULT_KEY.is_file() else None)
    log = logging.getLogger("ineptpdf")
    progress = logging.StreamHandler(sys.stderr)  # e.g. which licence server is contacted
    log.addHandler(progress)
    log.setLevel(logging.INFO)
    try:
        if output.exists():
            if output.samefile(args.input):
                raise IneptError("input and output must be different files")
            if not args.force:
                raise IneptError(f"{output} already exists (use --force to overwrite)")
        options = {
            "key": key,
            "username": args.username,
            "session": args.session,
            "prompt": _prompt if sys.stdin.isatty() else None,
            "browser_cookies": not args.no_browser_cookies,
            "confirm": _confirm if sys.stdin.isatty() else None,
            "xref": args.xref,
        }
        try:
            decrypt_file(args.input, output, password=args.password or "", **options)
        except DecryptionError as exc:
            if (
                str(exc) != "incorrect password"
                or args.password is not None
                or not options["prompt"]
            ):
                raise
            decrypt_file(args.input, output, password=_prompt("PDF password", True), **options)
    except (IneptError, OSError) as exc:
        print(f"ineptpdf: error: {exc}", file=sys.stderr)
        return 1
    finally:
        log.removeHandler(progress)
    print(f"Decrypted: {output}")
    return 0
