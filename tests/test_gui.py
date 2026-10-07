import pytest
from conftest import build_pdf
from test_decrypt import check_readable

from ineptpdf import gui

tk = pytest.importorskip("tkinter")


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    root.withdraw()
    yield gui.App(root)
    root.destroy()


def test_save_and_open(app, adept, tmp_path, monkeypatch):
    opened = []
    monkeypatch.setattr(gui, "open_in_viewer", opened.append)
    source = tmp_path / "book.pdf"
    source.write_bytes(adept.encrypt(build_pdf()))
    key = tmp_path / "key.der"
    key.write_bytes(adept.key_der)

    app.save()
    assert "Choose an existing" in app.status.get()

    app.set_source(str(source))
    assert "Adobe ADEPT" in app.status.get()
    app.save()
    assert "key file is required" in app.status.get()

    app.key.set(str(key))
    first, second = app.save(), app.save()
    assert first == tmp_path / "book.decrypted.pdf"
    assert second == tmp_path / "book.decrypted-2.pdf"  # never overwrites
    check_readable(first)

    shown = app.open()
    assert opened == [shown] and shown.parent != tmp_path
    check_readable(shown)


def test_open_unprotected_file_shows_the_original(app, tmp_path, monkeypatch):
    opened = []
    monkeypatch.setattr(gui, "open_in_viewer", opened.append)
    source = tmp_path / "plain.pdf"
    source.write_bytes(build_pdf())
    app.set_source(str(source))
    assert "Protection: none" in app.status.get()
    assert app.open() == source and opened == [source]
