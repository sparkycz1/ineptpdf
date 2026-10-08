"""FileOpen (``FOPN_foweb``) support.

A FileOpen PDF does not carry its key. The key is handed out by the publisher's
licence server, which is asked the same way the FileOpen plug-in for Adobe Reader
asks: with the document's identifiers, identifiers of this computer and, if the
server wants them, the user's credentials. This module performs that exchange.

The protocol is the one spoken by ineptpdf 8.4.51 (FileOpen client build 879).
"""

import base64
import binascii
import contextlib
import getpass
import logging
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import md5
from pathlib import Path
from urllib.parse import quote, urlsplit

from .errors import DecryptionError, UnsupportedError

log = logging.getLogger("ineptpdf")

# RC4 key protecting the /INFO entry of the encryption dictionary.
_INFO_KEY = md5(bytes.fromhex("a4da49de82ec8d6c5807")).digest()[:10]
# Salt for the values the plug-in keeps in the registry.
_MACHINE_SALT = bytes.fromhex("37a4da49de82064939a60b1d8d7b5f0f8873b6d93e")
_MACHINE_MAGIC = b"ec20"
_ID_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
_GENERIC_SID = "S-1-5-21-1380067357-584463869-1343024091-1000"
_DEFAULT_USER_AGENT = "Windows NT 6.0"
_SUCCESS = ("1", "2", "Update", "Answer")

_INFO_RENAMES = {
    "SVID": "ServiceID",
    "DUID": "DocumentID",
    "I3ID": "Ident3ID",
    "I4ID": "Ident4ID",
    "VERS": "EncrVer",
    "PRID": "USR",
}
_CLIENT_FIELDS = {
    "Mode": "CNR",
    "DocStrFmt": "ASCII",
    "Language": "ENU",
    "LngLCID": "ENU",
    "LngRFC1766": "en",
    "LngISO4Char": "en-us",
    "ProdVer": "1.8.7.9",
    "FormHFT": "Yes",
    "SelServer": "Yes",
    "AcroCanEdit": "Yes",
    "AcroPrefIDib": "Yes",
    "InBrowser": "Unk",
    "CliAppName": "",
    "DocIsLocal": "Yes",
    "FowpKbd": "Yes",
    "RequestSchema": "Default",
}
_WINDOWS_FIELDS = {
    "OSType": "Windows",
    "OSName": "Vista",
    "OSData": "Service%20Pack%204",
    "AcroProduct": "Reader",
    "AcroReader": "Yes",
    "OSBuild": "7600",
    "AcroVersion": "9.1024",
    "Build": "879",
}
_OTHER_OS_FIELDS = {
    "OSType": "Linux",
    "AcroProduct": "AcroReader",
    "AcroReader": "Yes",
    "AcroVersion": "9.101",
    "FSName": "ext3",
    "Build": "878",
    "ProdVer": "1.8.5.1",
    "OSBuild": "2.6.33",
}
# The order of the query parameters is part of the protocol.
_SETTING_QUERY = [
    "Stamp",
    "Mode",
    "USR",
    "ServiceID",
    "DocumentID",
    "Ident3ID",
    "Ident4ID",
    "DocStrFmt",
    "OSType",
    "OSName",
    "OSData",
    "Language",
    "LngLCID",
    "LngRFC1766",
    "LngISO4Char",
    "Build",
    "ProdVer",
    "EncrVer",
    "Machine",
    "Disk",
    "Uuid",
    "PrevMach",
    "PrevDisk",
    "FormHFT",
    "SelServer",
    "AcroVersion",
    "AcroProduct",
    "AcroReader",
    "AcroCanEdit",
    "AcroPrefIDib",
    "InBrowser",
    "CliAppName",
    "DocIsLocal",
    "DocPathUrl",
    "VolName",
    "VolType",
    "VolSN",
    "FSName",
    "FowpKbd",
    "OSBuild",
    "RequestSchema",
]
_PERMISSION_QUERY = [
    "Stamp",
    "Mode",
    "USR",
    "ServiceID",
    "DocumentID",
    "Ident3ID",
    "Ident4ID",
    "DocStrFmt",
    "OSType",
    "Language",
    "LngLCID",
    "LngRFC1766",
    "LngISO4Char",
    "Build",
    "ProdVer",
    "EncrVer",
    "Machine",
    "Disk",
    "Uuid",
    "PrevMach",
    "PrevDisk",
    "User",
    "SaUser",
    "SaSID",
    "HostIsDomain",
    "PhysHostname",
    "LogiHostname",
    "SaRefDomain",
    "FormHFT",
    "UserName",
    "UserPass",
    "Session",
    "SelServer",
    "AcroVersion",
    "AcroProduct",
    "AcroReader",
    "AcroCanEdit",
    "AcroPrefIDib",
    "InBrowser",
    "CliAppName",
    "DocIsLocal",
    "DocPathUrl",
    "VolName",
    "VolType",
    "VolSN",
    "FSName",
    "ServerSessionData",
    "FowpKbd",
    "OSBuild",
    "DocumentSessionData",
    "RequestSchema",
]


@dataclass
class Machine:
    """What the licence server gets to know about this computer."""

    windows: bool
    user: str
    mac: bytes
    hostname: str = ""
    disk_id: bytes | None = None  # volume serial + CPU type (Windows)
    sid: str | None = None
    uuid_blobs: list[bytes] = field(default_factory=list)  # the plug-in's Fowp3Uuid
    madi_blobs: list[bytes] = field(default_factory=list)  # the plug-in's Fowp3Madi
    volume: dict[str, str] = field(default_factory=dict)  # VolType, VolName, VolSN, FSName


@dataclass
class FileOpenOptions:
    """Caller-supplied answers for the licence server."""

    path: str = ""  # where the PDF lives; reported as DocPathUrl
    username: str | None = None
    password: str | None = None
    session: str | None = None  # value of the publisher's session cookie
    prompt: Callable[[str, bool], str] | None = None  # (question, secret) -> answer
    find_cookie: Callable[[str, str], str | None] | None = None  # (name, site) -> value
    confirm: Callable[[str], bool] | None = None  # yes/no question -> answer
    machine: Machine | None = None  # default: probe this computer

    def answer(self, preset: str | None, question: str, secret: bool = False) -> str:
        if preset:
            return preset
        if self.prompt:
            return self.prompt(question, secret)
        raise DecryptionError(f"the licence server asks for: {question}")


def rc4(key: bytes, data: bytes) -> bytes:
    from .crypto import rc4 as _rc4  # crypto imports this module

    return _rc4(key, data)


def id_from_bytes(data: bytes) -> str:
    """FileOpen's 8-character rendering of a 5-byte hardware identifier."""
    value = int.from_bytes(data[:4], "little")
    chars = []
    for _ in range(6):
        chars.append(_ID_ALPHABET[value & 0x1F])
        value >>= 5
    value |= data[4] << 2
    for _ in range(2):
        chars.append(_ID_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(chars)


def decrypt_plugin_value(blobs: list[bytes], user: str) -> str | None:
    """Decrypts a value the FileOpen plug-in stored for ``user`` (registry or file)."""
    for name in (user, user.lower(), user.upper()):
        for raw in (name, name + "\0"):
            uname = raw.encode("latin-1", "replace")
            for padded in (True, False):
                material = _MACHINE_SALT[:3] + uname[:13]
                if padded and len(uname) < 13:
                    material += _MACHINE_SALT[: 13 - len(uname)]
                key = md5(material).digest()
                for blob in blobs:
                    plain = rc4(key, blob)
                    if plain.startswith(_MACHINE_MAGIC):
                        return plain[len(_MACHINE_MAGIC) :].decode("latin-1")
    return None


def fetch_key(encrypt: dict, options: FileOpenOptions, *, timeout: float = 30) -> bytes:
    """Asks the licence server named in ``encrypt`` for the document key."""
    fields = _document_fields(encrypt)
    fields |= _CLIENT_FIELDS
    fields |= _machine_fields(fields, options.machine or probe_machine(options.path), options.path)
    if "EVER" in fields and _as_float(fields["EVER"]) < 3.8:
        fields["Mode"] = "ICx"

    server = fields.get("UURL") or fields.get("PURL")
    if not server or urlsplit(server).scheme not in ("http", "https"):
        raise DecryptionError("the FileOpen data in this PDF names no usable licence server")
    resource = fields.get("DPRM", "")
    if not resource.startswith("/"):
        resource = "/" + resource
    base = server + resource + ("&" if "?" in resource else "?")
    agent = fields.get("AGEN", _DEFAULT_USER_AGENT)
    log.info("Contacting the FileOpen licence server %s", urlsplit(server).netloc)

    log.debug("FileOpen settings in the PDF: %s", _masked(fields))

    def ask(request: str, names: list[str], *, first_wins: bool = False) -> dict[str, str]:
        sent = {name: fields[name] for name in names if name in fields}
        log.debug("-> %sRequest=%s %s", base, request, _masked(sent))
        query = "".join(f"&{name}={value}" for name, value in sent.items())
        reply = _get(f"{base}Request={request}{query}", agent, timeout, first_wins)
        log.debug("<- %s", _masked(reply))
        return reply

    def ask_credentials(force_prompt: bool = False) -> None:
        user = None if force_prompt else options.username
        secret = None if force_prompt else options.password
        fields["UserName"] = quote(options.answer(user, "user name"), safe="")
        fields["UserPass"] = quote(options.answer(secret, "password", True), safe="")

    settings = ask("Setting", _SETTING_QUERY, first_wins=True)
    for source, target in (
        ("RequestSchema", "RequestSchema"),
        ("ServerSessionData", "ServerSessionData"),
        ("SetScope", "RequestSchema"),
    ):
        if source in settings:
            fields[target] = settings[source]

    session_mode = fields.get("SEMO")
    if session_mode is None and "RetVal" in settings:
        if settings.get("Reason") == "AskUnp" or settings.get("SetTarget") == "UnpDlg":
            ask_credentials()
    elif session_mode in ("1", "2") and fields.get("CSES", "fileopen") != "fileopen":
        site = fields.get("CURL") or fields.get("PHOS") or fields.get("LHOS") or "the publisher"
        server_host = urlsplit(server).hostname or ""

        def lookup(name: str) -> str | None:
            # The PDF chooses both the cookie and the server, so a hostile PDF could ask
            # for some other site's cookie. Cookies the browser itself would send to the
            # licence server are used freely; any other only if the user agrees.
            if not options.find_cookie:
                return None
            if value := options.find_cookie(name, server_host):
                return value
            value = options.find_cookie(name, site)
            question = f"Send your '{name}' cookie of {site} to the licence server {server_host}?"
            if value and options.confirm and options.confirm(question):
                return value
            return None

        if session_mode == "1":
            cookie = None if options.session else lookup(fields["CSES"])
            if cookie:
                log.info("Using the '%s' cookie of %s from Firefox", fields["CSES"], site)
                fields["Session"] = cookie
            else:
                question = f"value of the '{fields['CSES']}' cookie from {site}"
                fields["Session"] = quote(options.answer(options.session, question), safe="")
        else:
            name = None if options.username else lookup("name")
            secret = None if options.username else lookup("pass")
            if name and secret:
                log.info("Using the login cookies of %s from Firefox", site)
                fields["UserName"], fields["UserPass"] = quote(name), quote(secret)
            else:
                ask_credentials()

    reply = ask("DocPerm", _PERMISSION_QUERY)
    wants_login = (
        reply.get("Reason") in ("BadUserPwd", "AskUnp") or reply.get("SwitchTo") == "Dialog"
    )
    if _refused(reply) and wants_login and options.prompt:
        for name in ("ServerSessionData", "DocumentSessionData"):
            if name in reply:
                fields[name] = reply[name]
        ask_credentials(force_prompt=True)
        reply = ask("DocPerm", _PERMISSION_QUERY)
    if _refused(reply):
        reason = reply.get("Error") or reply.get("Reason") or f"RetVal={reply['RetVal']}"
        raise DecryptionError(f"the licence server refused the request: {reason}")

    code = reply.get("Code", reply.get("code"))
    if code is None:
        raise DecryptionError("the licence server sent no document key")
    if len(code) in (5, 16):
        return code.encode("latin-1")
    try:
        return bytes.fromhex(code)
    except ValueError as exc:
        raise DecryptionError("the licence server sent a malformed document key") from exc


def describe(encrypt: dict) -> dict[str, str]:
    """The FileOpen settings stored in the PDF, decoded; nothing is sent anywhere."""
    return _document_fields(encrypt)


def _document_fields(encrypt: dict) -> dict[str, str]:
    fields = {
        name: encrypt[name].decode("latin-1")
        for name in ("VEID", "BUILD", "SVID", "DUID")
        if isinstance(encrypt.get(name), bytes)
    }
    try:
        info = rc4(_INFO_KEY, base64.b64decode(encrypt["INFO"])).decode("latin-1")
    except (KeyError, TypeError, binascii.Error) as exc:
        raise DecryptionError("the FileOpen data in this PDF is missing or corrupt") from exc
    for pair in info.split(";"):
        name, separator, value = pair.partition("=")
        if separator:
            fields[name] = value
    for short, long in _INFO_RENAMES.items():
        if short in fields:
            fields[long] = quote(fields.pop(short), safe="", encoding="latin-1")
    return fields


def _machine_fields(fields: dict[str, str], machine: Machine, path: str) -> dict[str, str]:
    out = dict(_WINDOWS_FIELDS if machine.windows else _OTHER_OS_FIELDS)
    out["Machine"] = id_from_bytes(machine.mac[1:6])
    out["Stamp"] = str(int(time.time()))
    out["DocPathUrl"] = "file%3a%2f%2f%2f" + quote(path)
    if not machine.windows:
        out["Disk"] = out["Machine"]
        if "Ident4ID" in fields:
            raise UnsupportedError(
                "this document is tied to an installed FileOpen plug-in, "
                "which exists only on Windows; decrypt it there"
            )
        out["Uuid"] = str(uuid.uuid1())
        return out

    out["Disk"] = id_from_bytes(machine.disk_id) if machine.disk_id else ""
    if "Yes" in fields.get("LIFF", ""):
        out["HostIsDomain"] = "Yes"
        if "1" in fields["LIFF"]:
            out["PhysHostname"] = out["LogiHostname"] = out["SaRefDomain"] = machine.hostname
    if fields.get("LILA") == "Yes":
        out["SaSID"] = machine.sid or _GENERIC_SID
        if machine.sid:
            out["User"] = quote(machine.user.lower())
            out["SaUser"] = quote(machine.user)
    out |= machine.volume

    if not machine.uuid_blobs or not machine.madi_blobs:
        raise DecryptionError(
            "the FileOpen plug-in has left no trace on this computer; "
            "open the PDF once in Adobe Reader with the plug-in, then try again"
        )
    user = machine.user.lower()
    out["Uuid"] = decrypt_plugin_value(machine.uuid_blobs, user) or str(uuid.uuid1())
    if previous := decrypt_plugin_value(machine.madi_blobs, user):
        if previous[:8] != out["Machine"]:
            out["PrevMach"] = previous[:8]
        if previous[8:] != out["Disk"]:
            out["PrevDisk"] = previous[8:]
    return out


def _get(url: str, agent: str, timeout: float, first_wins: bool) -> dict[str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": agent})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("latin-1")
    except urllib.error.HTTPError as exc:
        raise DecryptionError(f"the licence server answered HTTP {exc.code}") from exc
    except (OSError, ValueError) as exc:
        raise DecryptionError(f"cannot reach the licence server: {exc}") from exc
    reply: dict[str, str] = {}
    if "=" not in text:
        log.debug("unexpected reply (%d characters), starts: %r", len(text), text[:200])
    for pair in text.strip("\r\n").split("&"):
        name, separator, value = pair.partition("=")
        if separator and not (first_wins and name in reply):
            reply[name] = value
    return reply


_SECRET_FIELDS = ("UserName", "UserPass", "Session", "Code", "code")


def _masked(values: dict[str, str]) -> dict[str, str]:
    """``values`` with logins, cookies and keys replaced by their length."""
    return {
        name: f"<{len(value)} characters>" if name in _SECRET_FIELDS else value
        for name, value in values.items()
    }


def _refused(reply: dict[str, str]) -> bool:
    return "RetVal" in reply and reply["RetVal"] not in _SUCCESS


def _as_float(text: str) -> float:
    try:
        return float(text)
    except ValueError:
        return float("inf")


# -- probing this computer -------------------------------------------------------


def probe_machine(path: str = "") -> Machine:
    mac = uuid.getnode().to_bytes(6)
    if sys.platform != "win32":
        return Machine(windows=False, user=getpass.getuser(), mac=mac)
    return _probe_windows(path, mac)


def _probe_windows(path: str, mac: bytes) -> Machine:  # pragma: no cover - Windows only
    import ctypes
    import winreg
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32")

    class SystemInfo(ctypes.Structure):
        _fields_ = [
            ("wProcessorArchitecture", wintypes.WORD),
            ("wReserved", wintypes.WORD),
            ("dwPageSize", wintypes.DWORD),
            ("lpMinimumApplicationAddress", ctypes.c_void_p),
            ("lpMaximumApplicationAddress", ctypes.c_void_p),
            ("dwActiveProcessorMask", ctypes.c_size_t),
            ("dwNumberOfProcessors", wintypes.DWORD),
            ("dwProcessorType", wintypes.DWORD),
            ("dwAllocationGranularity", wintypes.DWORD),
            ("wProcessorLevel", wintypes.WORD),
            ("wProcessorRevision", wintypes.WORD),
        ]

    def volume_information(root: str) -> tuple[str, int, str] | None:
        name = ctypes.create_unicode_buffer(261)
        filesystem = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD()
        found = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root), name, 261, ctypes.byref(serial), None, None, filesystem, 261
        )
        return (name.value, serial.value, filesystem.value) if found else None

    user = os.environ.get("USERNAME") or getpass.getuser()
    machine = Machine(windows=True, user=user, mac=mac, hostname=socket.gethostname())

    if system_volume := volume_information("C:\\"):
        info = SystemInfo()
        kernel32.GetSystemInfo(ctypes.byref(info))
        cpu = info.dwProcessorType
        machine.disk_id = system_volume[1].to_bytes(4, "little") + bytes(
            (cpu & 255, cpu >> 8 & 255)
        )

    root = os.path.splitdrive(os.path.abspath(path))[0] + "\\"
    if document_volume := volume_information(root):
        kinds = ("Unknown", "Invalid", "Removable", "Fixed", "Remote", "CDRom", "RamDisk")
        kind = kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
        machine.volume = {
            "VolType": kinds[kind] if kind < len(kinds) else kinds[0],
            "VolName": quote(document_volume[0]),
            "VolSN": str(document_volume[1]),
            "FSName": document_volume[2],
        }

    try:
        whoami = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=10
        )
        if match := re.search(r"S-1-[\d-]+", whoami.stdout):
            machine.sid = match[0]
    except (OSError, subprocess.SubprocessError):
        pass

    def as_bytes(value) -> bytes:
        return value if isinstance(value, bytes) else str(value).encode("latin-1", "replace")

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Fileopen") as key:
            for name, blobs in (
                ("Fowp3Uuid", machine.uuid_blobs),
                ("Fowp3Madi", machine.madi_blobs),
            ):
                with contextlib.suppress(OSError):
                    blobs.append(as_bytes(winreg.QueryValueEx(key, name)[0]))
    except OSError:
        pass
    try:
        stored = (Path(os.environ["APPDATA"]) / "FileOpen" / "Fowpmadi.txt").read_bytes()
        machine.uuid_blobs.append(stored[:40])
        machine.madi_blobs.append(stored[40:])
    except (KeyError, OSError):
        pass
    return machine
