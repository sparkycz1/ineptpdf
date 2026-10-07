"""Small Tk window: choose a PDF, then open it or save an unprotected copy."""

import atexit
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import Document, __version__, decrypt_file
from .cli import DEFAULT_KEY
from .errors import IneptError

_PROTECTION_NAMES = {
    None: "none",
    "EBX_HANDLER": "Adobe ADEPT (Adobe Digital Editions)",
    "FOPN_foweb": "FileOpen",
    "Standard": "password",
}


def default_output(source: Path) -> Path:
    """Where the unprotected copy goes: next to the original, never over a file."""
    target = source.with_suffix(".decrypted.pdf")
    counter = 2
    while target.exists():
        target = source.with_suffix(f".decrypted-{counter}.pdf")
        counter += 1
    return target


def open_in_viewer(path: Path) -> None:
    """Opens ``path`` in the system's default PDF viewer."""
    if sys.platform == "win32":
        os.startfile(path)  # noqa: S606
    else:
        subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", str(path)])


class App:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import font, ttk

        self.root = root
        root.title(f"ineptpdf {__version__}")
        root.resizable(True, False)
        frame = ttk.Frame(root, padding=12)
        frame.pack(fill=tk.X, expand=True)
        frame.columnconfigure(1, weight=1)

        self.source = tk.StringVar()
        self.key = tk.StringVar(value=str(DEFAULT_KEY.resolve()) if DEFAULT_KEY.is_file() else "")
        self.password = tk.StringVar()
        self.status = tk.StringVar(value="Choose a PDF file.")

        rows = (
            ("PDF file", self.source, self.choose_source, ""),
            ("ADEPT key", self.key, self.choose_key, ""),
            ("Password", self.password, None, "*"),
        )
        for row, (label, variable, browse, mask) in enumerate(rows):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky=tk.W, padx=(0, 8), pady=2)
            entry = ttk.Entry(frame, textvariable=variable, width=48, show=mask)
            entry.grid(row=row, column=1, sticky=tk.EW)
            if browse:
                button = ttk.Button(frame, text="Browse...", command=browse)
                button.grid(row=row, column=2, padx=(6, 0))
        hint = ttk.Label(
            frame,
            text="The key is needed only for Adobe Digital Editions books, the password "
            "only for password-protected PDFs or a FileOpen login.",
            foreground="gray40",
        )
        hint.grid(row=len(rows), column=0, columnspan=3, sticky=tk.EW, pady=(4, 8))

        buttons = ttk.Frame(frame)
        buttons.grid(row=len(rows) + 1, column=0, columnspan=3)
        ttk.Button(buttons, text="Open", command=self.open).pack(side=tk.LEFT, padx=4)
        ttk.Button(buttons, text="Remove protection and save", command=self.save).pack(
            side=tk.LEFT, padx=4
        )
        # Room for a four-line message, so a long error never falls off the window.
        line_height = font.nametofont("TkDefaultFont").metrics("linespace")
        status_box = ttk.Frame(frame, height=4 * line_height)
        status_box.grid(row=len(rows) + 2, column=0, columnspan=3, sticky=tk.EW, pady=(10, 0))
        status_box.pack_propagate(False)
        self.status_label = ttk.Label(status_box, textvariable=self.status, anchor=tk.NW)
        self.status_label.pack(fill=tk.BOTH, expand=True)

        def rewrap(event) -> None:  # wrap text to the window, whatever the screen scaling
            for label in (hint, self.status_label):
                label.configure(wraplength=max(event.width - 2 * 12, 100))

        initial = font.nametofont("TkDefaultFont").measure("0") * 60
        for label in (hint, self.status_label):
            label.configure(wraplength=initial)
        frame.bind("<Configure>", rewrap)
        root.update_idletasks()
        root.minsize(root.winfo_reqwidth(), root.winfo_reqheight())
        self._scratch: Path | None = None

    # -- actions --------------------------------------------------------------

    def choose_source(self) -> None:
        from tkinter import filedialog

        if path := filedialog.askopenfilename(filetypes=[("PDF", "*.pdf"), ("All files", "*")]):
            self.set_source(path)

    def choose_key(self) -> None:
        from tkinter import filedialog

        if path := filedialog.askopenfilename(
            filetypes=[("Key", "*.der *.pem"), ("All files", "*")]
        ):
            self.key.set(path)

    def set_source(self, path: str) -> None:
        self.source.set(path)
        try:
            kind = Document(Path(path).read_bytes()).encryption_filter
        except (IneptError, OSError) as exc:
            self.status.set(f"Error: {exc}")
            return
        self.status.set(f"Protection: {_PROTECTION_NAMES.get(kind, kind)}")

    def save(self) -> Path | None:
        """Writes the unprotected copy next to the original."""
        source = self._source()
        if source and (target := self._decrypt(source, default_output(source))):
            self.status.set(f"Saved: {target}")
            return target
        return None

    def open(self) -> Path | None:
        """Shows the document in the default viewer without keeping a copy."""
        source = self._source()
        if not source:
            return None
        if self._scratch is None:
            self._scratch = Path(tempfile.mkdtemp(prefix="ineptpdf-"))
            atexit.register(shutil.rmtree, self._scratch, ignore_errors=True)
        target = self._decrypt(source, self._scratch / source.name, allow_plain=True)
        if target:
            try:
                open_in_viewer(target)
            except OSError as exc:
                self.status.set(f"Error: cannot start the PDF viewer ({exc})")
                return None
            self.status.set("Opened in the PDF viewer.")
        return target

    # -- helpers --------------------------------------------------------------

    def _source(self) -> Path | None:
        path = self.source.get().strip()
        if not path or not Path(path).is_file():
            self.status.set("Choose an existing PDF file first.")
            return None
        return Path(path)

    def _decrypt(self, source: Path, target: Path, allow_plain: bool = False) -> Path | None:
        self.status.set("Working...")
        self.root.update_idletasks()
        try:
            if allow_plain and Document(source.read_bytes()).encryption_filter is None:
                return source  # nothing to remove; show the original
            decrypt_file(
                source,
                target,
                key=self.key.get().strip() or None,
                password=self.password.get(),
                browser_cookies=True,
                prompt=self._ask,
                confirm=self._confirm,
            )
        except (IneptError, OSError) as exc:
            self.status.set(f"Error: {exc}")
            return None
        return target

    def _confirm(self, question: str) -> bool:
        from tkinter import messagebox

        return messagebox.askyesno("ineptpdf", question, parent=self.root)

    def _ask(self, question: str, secret: bool) -> str:
        from tkinter import simpledialog

        answer = simpledialog.askstring(
            "ineptpdf",
            f"The licence server asks for: {question}",
            show="*" if secret else "",
            parent=self.root,
        )
        return answer or ""


def run() -> int:
    try:
        import tkinter as tk
    except ImportError:
        print("ineptpdf: error: the GUI needs tkinter, which this Python lacks", file=sys.stderr)
        return 1
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0
