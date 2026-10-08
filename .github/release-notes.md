Fixes for real-world files, after the first reports from 9.0.0.

## Download

| System | File |
| --- | --- |
| Windows | `ineptpdf-windows-x64.exe` |
| Linux | `ineptpdf-linux-x86_64` (run `chmod +x` on it first) |

## Changes

- **Cipher detection.** FileOpen documents were always treated as RC4. The key from the licence server is now tried as RC4, AES-128 and AES with a direct key, and the scheme that actually decrypts the document is used. ADEPT books get the same check for their two key schedules. A key that fits nothing is reported as such instead of producing a broken file.
- **Damaged objects.** An object that cannot be read (for example a cross-reference entry pointing past the end of the file) is left out with a warning instead of stopping everything with `unexpected end of data`. Errors now name the object they are about.
- **Copy details.** New button in the window, and `--debug` on the command line: a report of the last attempt to attach to an issue. Logins, cookies and keys are replaced by their length.
- The window now reports unexpected errors instead of silently doing nothing.

## Known limits

- FileOpen: implements the 2011 protocol and is tested against a simulated server only. Documents tied to the FileOpen plug-in work on Windows only.
- ADEPT is tested on generated files, not on books from a real shop.
- The programs are not code-signed.
