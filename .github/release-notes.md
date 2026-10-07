First release of the Python 3 rewrite of `ineptpdf 8.4.51`.

## Download

| System | File |
| --- | --- |
| Windows | `ineptpdf-windows-x64.exe` |
| Linux | `ineptpdf-linux-x86_64` (run `chmod +x` on it first) |

Start the program without arguments for the window, or with arguments as a command (`--help`).

## What it does

- Removes Adobe ADEPT protection from PDF e-books, using your own `adeptkey.der`.
- Opens FileOpen PDFs by asking the publisher's licence server, with the session cookie from Firefox when the server works with a web login.
- Unlocks password-protected PDFs (RC4, AES-128) with the user or owner password.
- A small window with **Open** and **Remove protection and save**, and a command line.

## Changes from 8.4.51

- Python 3.13+, packaged, with a test suite; `cryptography` replaces PyCrypto and pywin32.
- Password-protected PDFs work (that code path was broken), including AES-128 and owner passwords.
- Damaged cross-reference tables are rebuilt; the output appears only after success and never overwrites the input.
- A cookie from a site other than the licence server is sent only after you confirm.
- Dropped: Adobe Policy Server, automatic removal of `ciando` IDs.

## Known limits

- FileOpen: implements the 2011 protocol and is tested against a simulated server only. Documents tied to the FileOpen plug-in work on Windows only.
- ADEPT is tested on generated files, not on books from a real shop.
- The programs are not code-signed.
