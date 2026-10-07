@echo off
rem Builds dist\ineptpdf.exe, a single self-contained program. Needs uv (https://docs.astral.sh/uv/).
cd /d "%~dp0"
uv run --with pyinstaller pyinstaller --noconfirm --clean --onefile --windowed --name ineptpdf --paths src ineptpdf_gui.py
if errorlevel 1 exit /b 1
echo Built: dist\ineptpdf.exe
