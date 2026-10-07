# 🔒 Security Policy

## Supported versions

Only the **latest released version** (the most recent [tag/release](https://github.com/sparkycz1/ineptpdf/releases)) is supported with security fixes. There are no maintained older branches — upgrade to the latest release before reporting an issue, and after a fix ships.

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Anything older | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Instead, open a private draft security advisory: this repository's **Security** tab → **Advisories** → **Report a vulnerability** / **New draft security advisory**.

Include, if known:
- The affected version/commit.
- Steps to reproduce, or a proof of concept. Do not attach a protected PDF, a key file or a cookie; a description or a synthetic file is enough.
- The impact you'd expect (what an attacker could actually do).

## Scope

This is a desktop tool that parses PDF files, which may come from anywhere, and for FileOpen documents talks to a server and reads a browser cookie. The parts worth attacking, and what already guards them:

- **PDF parsing.** The parser is pure Python and reads the whole file into memory. A crafted file that makes it crash is a bug; one that makes it write outside the chosen output file, or run code, is a vulnerability.
- **Licence server address.** A FileOpen PDF names the server that is contacted. Only `http` and `https` addresses are accepted, and the server's name is shown before the request is made. The request carries identifiers of the computer (network card address; on Windows also the system volume serial number and the user name), so opening a FileOpen PDF from an untrusted source tells its server about your machine.
- **Browser cookies.** A FileOpen PDF also names the cookie it wants. A cookie that Firefox itself would send to the licence server is used without asking; a cookie belonging to any other site is sent only after an explicit confirmation, and never in a non-interactive run. `--no-browser-cookies` disables the lookup. A way around that confirmation is a vulnerability.
- **Output.** The unprotected copy is written to a temporary file next to the destination and renamed only on success; the input is never overwritten.

Weaknesses of the protection schemes themselves (ADEPT, FileOpen, RC4) are not vulnerabilities of this project.
