#!/bin/sh
# Builds a single self-contained executable in dist/ (Linux, macOS).
set -e
cd "$(dirname "$0")"
# uv's Python keeps Tcl/Tk next to itself; PyInstaller has to be told where.
LIBDIR=$(uv run -q python -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")
LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    uv run --with pyinstaller pyinstaller --noconfirm --clean --onefile --windowed \
    --name ineptpdf --paths src ineptpdf_gui.py
echo "Built: dist/ineptpdf"
