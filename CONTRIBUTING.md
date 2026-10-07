# Contributing

Thanks for taking the time to contribute. This file covers the basics; the
[README](README.md) describes what the tool does and how it is laid out.

Everyone participating is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

For anything beyond a small, obvious fix, **open an issue first** and describe
what you want to change. Some decisions here are deliberate and already settled —
for example, Adobe Policy Server support was dropped on purpose, and cookies are
read from Firefox only — so opening an issue first avoids spending time on a PR
that goes against one of those.

Never attach a protected PDF, a key file, a password or a cookie value to an
issue or a pull request. The output of `ineptpdf --info file.pdf` is usually
enough to describe a file.

**Security vulnerability?** Don't open a public issue — see
[SECURITY.md](.github/SECURITY.md) instead.

## Making a change

1. Fork the repository (or create a branch, if you have push access) and
   make your change.
2. Run the full gate before opening a PR:
   ```bash
   uv sync
   uv run ruff check .
   uv run ruff format --check .
   uv run pytest
   ```
3. Open a pull request with a summary of the change and how you tested it. CI
   runs the same gate on Linux and Windows and builds both executables.

New behaviour needs a test. The tests build their own sample PDFs and run a
local stand-in for a FileOpen licence server; please keep it that way, so the
suite never needs a real book, a real account or network access.

## License

This project is licensed under the
[GNU General Public License v3.0](LICENSE). By submitting a contribution,
you agree it's provided under that same license.
