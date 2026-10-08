# ineptpdf

[![build](https://github.com/sparkycz1/ineptpdf/actions/workflows/build.yml/badge.svg)](https://github.com/sparkycz1/ineptpdf/actions/workflows/build.yml)

Opens protected PDF files you are entitled to read, and saves an unprotected copy:

- **Adobe ADEPT** — e-books from Adobe Digital Editions, with your own ADE key.
- **FileOpen** — documents whose publisher's licence server lets you in.
- **Password-protected PDFs** — when you know the password.

This is a Python 3 rewrite of the Python 2 script `ineptpdf 8.4.51`
([original](https://github.com/alaingilbert/ineptpdf)).

Removing copy protection may be restricted by the law of your country or by the
terms under which you got the document. Use this only on documents you have the
right to use this way.

## Download

Ready-made programs are on the
[releases page](https://github.com/sparkycz1/ineptpdf/releases/latest). They need
nothing installed.

| System | File |
| --- | --- |
| Windows | `ineptpdf-windows-x64.exe` |
| Linux | `ineptpdf-linux-x86_64` |

On Linux make the file executable first (`chmod +x ineptpdf-linux-x86_64`).
Windows may warn about an unknown publisher, because the program is not signed.

## The window

Start the program without arguments. With the source code instead:

```bash
uv run ineptpdf_gui.py
```

Choose a PDF; the window shows how it is protected. Then:

- **Open** shows the document in your PDF viewer and keeps no copy.
- **Remove protection and save** writes `name.decrypted.pdf` next to the original.
  Nothing is ever overwritten.

The key field is needed only for Adobe Digital Editions books, the password field
only for password-protected PDFs or a FileOpen login.

If something fails, **Copy details** puts a report about the last attempt on the
clipboard, ready to paste into an issue. It lists how the file is protected and
what was exchanged with a licence server; logins, cookies and keys are replaced by
their length. On the command line `--debug` prints the same.

## Command line

The same program works as a command when given arguments. The downloadable
Windows `.exe` is a window program and prints nothing to a console; for command
line use on Windows install from source (`uv tool install .`).

```bash
ineptpdf book.pdf -k adeptkey.der
```

| Option | Meaning |
| --- | --- |
| `-k KEY` | ADEPT private key (DER or PEM). `./adeptkey.der` is used if present. |
| `-p PASSWORD` | Password: of a password-protected PDF, or your FileOpen login. |
| `-u USERNAME` | User name, if a FileOpen licence server asks for one. |
| `--session VALUE` | FileOpen session cookie value (default: looked up in Firefox). |
| `--no-browser-cookies` | Never read cookies from the Firefox profile. |
| `--info` | Show how the PDF is protected and exit. Contacts nobody. |
| `-o OUTPUT` | Output file (default: `INPUT.decrypted.pdf`). |
| `-f` | Overwrite an existing output file. |
| `--xref table\|stream` | Force the cross-reference format; default follows the input. |
| `--debug` | Print diagnostic details (no logins, cookies or keys). |
| `--gui` | Open the window. |

From Python (`pip install .` or `uv add`):

```python
from ineptpdf import decrypt_file

decrypt_file("book.pdf", "out.pdf", key="adeptkey.der")
```

## Adobe ADEPT

You need `adeptkey.der`, the RSA key of your Adobe Digital Editions activation.
This tool does not extract it. A book opens only with the key of the Adobe ID it
was licensed to.

## FileOpen

A FileOpen PDF holds no key. The key comes from the publisher's licence server,
whose address is inside the PDF. `ineptpdf` shows that server's name and asks it
the way the FileOpen plug-in for Adobe Reader does. The server decides whether to
release the key, so this works only for documents you are entitled to open.

What is sent: the document's identifiers, identifiers derived from your computer
(network card address; on Windows also the system volume serial number, the user
name and what the plug-in stored in the registry) and the login you give.

- **Web logins.** If the publisher works with a web login (a standards portal,
  for example), sign in to its site in Firefox first. `ineptpdf` takes the session
  cookie the server wants from your Firefox profile. If that cookie belongs to a
  different site than the licence server, you are asked before it is sent. With
  another browser, pass the cookie value with `--session`.
- **Documents tied to the plug-in.** Many FileOpen documents are tied to an
  installed FileOpen plug-in. Those work on Windows only, after the PDF has been
  opened once in Adobe Reader with the plug-in. On Linux and macOS they end with
  an error saying so; other documents can be tried on any system.
- **Finding out.** `ineptpdf --info document.pdf` lists the settings stored in the
  PDF. An `Ident4ID` line means the document is tied to the plug-in.

Limits you should know about: the protocol is the one from 2011 (plug-in build
879) and has been tested only against a simulated server, so a current server may
refuse it. The `FOPN_fLock` variant is not supported.

## Password-protected PDFs

Standard security revisions 2-4: RC4 with 40-128 bit keys and AES-128, with the
user or the owner password. AES-256 is not supported; `qpdf` handles those.

## Not supported

Adobe Policy Server (`Adobe.APS`), which the old script handled, was dropped on
purpose. So was the removal of `ciando` reference IDs from links.

## Building the programs

```bash
./build.sh
```

makes `dist/ineptpdf` on Linux or macOS; `build.bat` makes `dist\ineptpdf.exe` on
Windows. Both need [uv](https://docs.astral.sh/uv/). An `.exe` can only be built on
Windows; the `build` workflow does both on every push and attaches them to a
release when a `v*` tag is pushed.

## Development

Requires Python 3.13 or newer.

```bash
uv run pytest
```

```bash
uv run ruff check .
```

The code lives in `src/ineptpdf/`: `parser.py` and `document.py` read PDFs,
`crypto.py` holds the ADEPT and password handlers, `fileopen.py` and `browser.py`
the FileOpen exchange and the Firefox cookie lookup, `writer.py` writes the result,
`cli.py` and `gui.py` are the two front ends.

The tests build their own sample PDFs and run a local stand-in for the FileOpen
licence server, so no real e-book or account is needed. The ADEPT and FileOpen
tests therefore check the code against those formats as the original script
understood them, not against real files or servers.

See [CONTRIBUTING.md](CONTRIBUTING.md), the [Code of Conduct](CODE_OF_CONDUCT.md)
and the [security policy](.github/SECURITY.md).

## License

[GPL v3](LICENSE), like the original script. Its authors are listed in the revision
history at the top of the [original file](https://github.com/alaingilbert/ineptpdf/blob/master/ineptpdf.py).
