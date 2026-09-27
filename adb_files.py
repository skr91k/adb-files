#!/usr/bin/env python3
"""
Two-window file browser on localhost: the Mac disk and an Android phone (adb).

    python3 adb_files.py
        http://localhost:8090/         both, split in one window (draggable divider)
        http://localhost:8090/local/   Mac      (starts in ~/BhavAppData/DATA)
        http://localhost:8090/adb/     Android  (starts in .../shakir.bhav.android/files/DATA)

Right-click a row (or its ⋯ menu) -> "Send to Android" / "Send to Mac" copies it
to the same path relative to the other side's launch folder (DATA/x/y -> DATA/x/y).
Folders merge (skipping .DS_Store, ._*, Thumbs.db & co); existing files are never overwritten without asking
(Overwrite / Keep both as "name (01).ext"). Only items inside the launch folder
can be sent.

Standalone: stdlib only, UI in ui.html next to this file (originally taken
from server-code/filebrowser.py, now independent of it).
Env: PORT (8090), HOST (127.0.0.1), LOCAL_START, ADB_START, ANDROID_SERIAL.
Local-only: binds 127.0.0.1, no password.
"""
import hashlib
import json
import os
import posixpath
import shlex
import shutil
import stat as statmod
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
import zlib
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8090"))
LOCAL_START = os.environ.get("LOCAL_START", str(Path.home() / "BhavAppData/DATA")).strip("/")
ADB_START = os.environ.get("ADB_START", "sdcard/Android/data/shakir.bhav.android/files/DATA").strip("/")
CHUNK = 1024 * 1024
WORK_DIR = Path(tempfile.mkdtemp(prefix="adb_files_"))

q = shlex.quote


# ── helpers copied from server-code/filebrowser.py ────────────────────────────

def _fmt(n: int) -> str:
    if n >= 1 << 30:
        return f"{n / (1 << 30):.2f} GB"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} MB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.0f} KB"
    return f"{n} B"


IMAGE_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".bmp": "image/bmp",
    ".ico": "image/x-icon",
    ".avif": "image/avif",
    ".apng": "image/apng",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".svg": "image/svg+xml",
}


def _parse_range(header, size: int):
    """Parse one byte-range. -> (start, end) inclusive, None for no range, or "bad"."""
    if not header or not header.strip().startswith("bytes="):
        return None
    spec = header.strip()[6:].split(",", 1)[0].strip()   # only the first range
    start_s, sep, end_s = spec.partition("-")
    if not sep:
        return "bad"
    try:
        if start_s:
            start = int(start_s)
            end = int(end_s) if end_s else size - 1
        elif end_s:
            start = max(0, size - int(end_s))            # suffix form: bytes=-500
            end = size - 1
        else:
            return "bad"
    except ValueError:
        return "bad"
    end = min(end, size - 1)
    if start > end or start >= size:
        return "bad"
    return start, end


PREVIEW_LIMIT = 200 * 1024


def _decode_with_enc(raw: bytes) -> tuple:
    """Decode preview bytes, reporting which codec worked.

    Only a clean utf-8 read may be edited: a latin-1 or lossy decode would not
    round-trip, so saving it back would silently corrupt the file.
    """
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), "replace"


def _decode_bytes(raw: bytes) -> str:
    return _decode_with_enc(raw)[0]


def _zip_entries(p: Path) -> list:
    with zipfile.ZipFile(p, "r") as zf:
        return [
            {
                "name": info.filename,
                "size": info.file_size,
                "compressed_size": info.compress_size,
                "is_dir": info.filename.endswith("/"),
            }
            for info in zf.infolist()
        ]


_LFH_SIG = b"PK\x03\x04"


def _find_next_sig(data: bytes, start: int) -> int:
    """Index of the next zip record signature at/after `start`, else len(data)."""
    best = len(data)
    for sig in (b"PK\x03\x04", b"PK\x01\x02", b"PK\x07\x08", b"PK\x05\x06"):
        idx = data.find(sig, start)
        if idx != -1:
            best = min(best, idx)
    return best


def _recover_zip_entries(data: bytes) -> list:
    """Scan raw bytes for local file headers, return [(name, file_bytes), ...]."""
    out = []
    n = len(data)
    i = 0
    while True:
        idx = data.find(_LFH_SIG, i)
        if idx == -1 or idx + 30 > n:
            break
        (_sig, _ver, flags, method, _mt, _md, _crc,
         comp_size, _uncomp, fn_len, extra_len) = struct.unpack(
            "<IHHHHHIIIHH", data[idx:idx + 30])
        name_start = idx + 30
        name_end = name_start + fn_len
        if fn_len == 0 or name_end > n:
            i = idx + 4
            continue
        raw_name = data[name_start:name_end]
        try:
            filename = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            filename = raw_name.decode("latin-1", "replace")
        data_start = name_end + extra_len
        i = data_start

        if filename.endswith("/") or "\x00" in filename:
            continue  # directory or garbage match inside compressed data

        content = None
        consumed = 0
        if method == 8:  # deflate
            dobj = zlib.decompressobj(-zlib.MAX_WBITS)
            try:
                content = dobj.decompress(data[data_start:])
                try:
                    content += dobj.flush()
                except zlib.error:
                    pass  # truncated final entry — keep what we decoded
                consumed = (n - data_start) - len(dobj.unused_data)
            except zlib.error:
                content = None
        elif method == 0:  # stored
            has_dd = bool(flags & 0x08)
            if not has_dd and comp_size:
                content = data[data_start:data_start + comp_size]
                consumed = comp_size
            else:
                nxt = _find_next_sig(data, data_start)
                content = data[data_start:nxt]
                consumed = len(content)

        if content is not None and (content or filename):
            out.append((filename, content))
            i = max(i, data_start + max(consumed, 0))
    return out


def _repair_zip_file(p: Path) -> dict:
    """Rebuild a corrupt ZIP in place. Returns {recovered, names}."""
    data = p.read_bytes()
    entries = _recover_zip_entries(data)
    if not entries:
        raise ValueError("No recoverable entries found in archive")

    fd, tmp = tempfile.mkstemp(suffix=".zip", dir=str(p.parent))
    os.close(fd)
    try:
        seen = {}
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, content in entries:
                if name in seen:
                    seen[name] += 1
                    stem, dot, ext = name.rpartition(".")
                    name = (f"{stem}__{seen[name]}{dot}{ext}" if dot
                            else f"{name}__{seen[name]}")
                else:
                    seen[name] = 0
                zf.writestr(name, content)
        # verify the rebuilt archive before overwriting the original
        with zipfile.ZipFile(tmp, "r") as zf:
            if zf.testzip() is not None:
                raise ValueError("Rebuilt archive failed integrity check")
            names = [inf.filename for inf in zf.infolist()]
        os.replace(tmp, p)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return {"recovered": len(names), "names": names}

# ── errors / adb ──────────────────────────────────────────────────────────────

class ApiError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def adb(*args, check=True) -> subprocess.CompletedProcess:
    r = subprocess.run(["adb", *args], capture_output=True)
    if check and r.returncode:
        msg = (r.stderr or r.stdout).decode("utf-8", "replace").strip()
        if "Permission denied" in msg:
            raise ApiError(403, "Permission denied")
        if "no devices" in msg or "device offline" in msg or "not found" in msg and "device" in msg:
            raise ApiError(503, "Android device not connected")
        raise ApiError(500, msg or f"adb exited {r.returncode}")
    return r


def sh(cmd: str, check=True) -> str:
    return adb("shell", cmd, check=check).stdout.decode("utf-8", "replace")


def norm(raw: str) -> str:
    """UI path ('sdcard/DCIM') -> absolute path ('/sdcard/DCIM'); can't escape '/'."""
    return posixpath.normpath("/" + (raw or "").lstrip("/"))


def as_dir(p: str) -> str:
    # trailing slash makes find/pull follow a symlinked dir such as /sdcard
    return p.rstrip("/") + "/"


def kind_of(mode: int) -> str:
    return "dir" if statmod.S_ISDIR(mode) else "file" if statmod.S_ISREG(mode) else "other"


def check_name(name: str) -> str:
    name = (name or "").strip()
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        raise ApiError(400, "Invalid name")
    return name


# ── backends ──────────────────────────────────────────────────────────────────
# Both speak absolute POSIX paths. Endpoints only use this interface, so every
# feature works the same on the Mac and on the phone.

class Backend:
    side = label = start = ""

    def need(self, p: str, kind: str):
        st = self.stat(p)
        if st is None:
            raise ApiError(404, "Path not found")
        if st[0] != kind:
            raise ApiError(400, "Not a directory" if kind == "dir" else "Not a file")
        return st


class LocalBackend(Backend):
    side, label, start = "local", "💻 Mac", LOCAL_START

    def stat(self, p):
        try:
            st = os.stat(p)
        except OSError:
            return None
        return kind_of(st.st_mode), st.st_size, int(st.st_mtime)

    def exists(self, p):
        return os.path.lexists(p)

    def list(self, p):
        try:
            entries = list(os.scandir(p))
        except PermissionError:
            raise ApiError(403, "Permission denied")
        out = []
        for e in entries:
            try:
                st = e.stat()
                out.append((e.name, kind_of(st.st_mode), st.st_size, int(st.st_mtime)))
            except OSError:
                out.append((e.name, "other", 0, None))
        return out

    def iter_range(self, p, start, length):
        with open(p, "rb") as f:
            f.seek(start)
            while length > 0 and (chunk := f.read(min(CHUNK, length))):
                length -= len(chunk)
                yield chunk

    def read_range(self, p, offset, length):
        with open(p, "rb") as f:
            f.seek(offset)
            return f.read(length)

    def md5(self, p):
        h = hashlib.md5()
        with open(p, "rb") as f:
            while chunk := f.read(CHUNK):
                h.update(chunk)
        return h.hexdigest()

    def folder_size(self, p):
        children = len(os.listdir(p))
        total = 0
        for root, _, files in os.walk(p):
            for fname in files:
                try:
                    total += os.lstat(os.path.join(root, fname)).st_size
                except OSError:
                    pass
        return total, children

    def rename(self, p, dest):
        os.rename(p, dest)

    def delete(self, p):
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.unlink(p)

    def clean(self, p):
        names = os.listdir(p)
        for n in names:
            self.delete(os.path.join(p, n))
        return len(names)

    def walk(self, p):
        """{rel: (kind, size)} for p and everything under it ('' is p itself); {} if missing."""
        st = self.stat(p)
        if st is None:
            return {}
        out = {"": (st[0], st[1])}
        if st[0] != "dir":
            return out
        for root, dirs, files in os.walk(p):
            rel = os.path.relpath(root, p)
            prefix = "" if rel == "." else rel + "/"
            for d in dirs:
                if not os.path.islink(os.path.join(root, d)):
                    out[prefix + d] = ("dir", 0)
            for f in files:
                full = os.path.join(root, f)
                if os.path.isfile(full):
                    out[prefix + f] = ("file", os.path.getsize(full))
        return out

    def mkdirs(self, paths):
        for d in paths:
            os.makedirs(d, exist_ok=True)

    def sizes(self, paths):
        """{path: (size, mtime)} for the paths that exist."""
        out = {}
        for p in paths:
            try:
                st = os.stat(p)
                out[p] = (st.st_size, int(st.st_mtime))
            except OSError:
                pass
        return out

    def put(self, local: Path, dest: str):
        """Move a temp file from WORK_DIR to dest."""
        shutil.move(str(local), dest)

    def fetch(self, p: str, tmp: Path) -> Path:
        """A local Path with p's content (for zip work). The file itself here."""
        return Path(p)

    def replace_from(self, local: Path, p: str):
        if Path(p) != local:
            shutil.copyfile(local, p)   # temp dir may be on another volume


class AdbBackend(Backend):
    side, label, start = "adb", "📱 Android", ADB_START

    def stat(self, p):
        r = adb("shell", f"stat -L -c '%f %s %Y' {q(p)}", check=False)
        try:
            mode, size, mtime = r.stdout.split()
            return kind_of(int(mode, 16)), int(size), int(mtime)
        except ValueError:
            if b"no devices" in r.stderr or b"offline" in r.stderr:
                raise ApiError(503, "Android device not connected")
            return None

    def exists(self, p):
        return sh(f"[ -e {q(p)} -o -L {q(p)} ] && echo y", check=False).strip() == "y"

    def list(self, p):
        r = adb("shell", f"find {q(as_dir(p))} -mindepth 1 -maxdepth 1 "
                         f"-exec stat -L -c '%f %s %Y %n' {{}} +", check=False)
        out = r.stdout.decode("utf-8", "replace")
        if not out.strip() and r.returncode:
            err = r.stderr.decode("utf-8", "replace")
            raise ApiError(403 if "Permission denied" in err else 500, err.strip() or "List failed")
        items = []
        for line in out.splitlines():
            parts = line.split(" ", 3)
            if len(parts) != 4:
                continue
            try:
                items.append((posixpath.basename(parts[3]), kind_of(int(parts[0], 16)),
                              int(parts[1]), int(parts[2])))
            except ValueError:
                continue
        return items

    @staticmethod
    def _range_cmd(p, start, length):
        return f"tail -c +{start + 1} {q(p)} | head -c {length}"

    def iter_range(self, p, start, length):
        proc = subprocess.Popen(["adb", "exec-out", self._range_cmd(p, start, length)],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            while chunk := proc.stdout.read(CHUNK):
                yield chunk
        finally:
            proc.kill()
            proc.wait()

    def read_range(self, p, offset, length):
        return adb("exec-out", self._range_cmd(p, offset, length)).stdout

    def md5(self, p):
        return sh(f"md5sum {q(p)}").split()[0]

    def folder_size(self, p):
        d = q(as_dir(p))
        out = sh(f"find {d} -mindepth 1 -maxdepth 1 | wc -l; "
                 f"find {d} -type f -exec stat -c %s {{}} +", check=False).split()
        children = int(out[0]) if out else 0
        return sum(int(x) for x in out[1:] if x.isdigit()), children

    def rename(self, p, dest):
        sh(f"mv {q(p)} {q(dest)}")

    def delete(self, p):
        sh(f"rm -rf {q(p)}")

    def clean(self, p):
        d = q(as_dir(p))
        n = int(sh(f"find {d} -mindepth 1 -maxdepth 1 | wc -l").strip() or 0)
        sh(f"find {d} -mindepth 1 -maxdepth 1 -exec rm -rf {{}} +")
        return n

    def walk(self, p):
        st = self.stat(p)
        if st is None:
            return {}
        out = {"": (st[0], st[1])}
        if st[0] != "dir":
            return out
        base = posixpath.normpath(p)
        r = adb("shell", f"find {q(as_dir(p))} -mindepth 1 -exec stat -c '%f %s %n' {{}} +",
                check=False)
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split(" ", 2)
            if len(parts) != 3:
                continue
            try:
                kind, size = kind_of(int(parts[0], 16)), int(parts[1])
            except ValueError:
                continue
            if kind != "other":
                out[posixpath.relpath(posixpath.normpath(parts[2]), base)] = (kind, size)
        return out

    def mkdirs(self, paths):
        paths = list(paths)
        for i in range(0, len(paths), 100):
            sh("mkdir -p " + " ".join(q(d) for d in paths[i:i + 100]))

    def sizes(self, paths):
        out = {}
        paths = list(paths)
        for i in range(0, len(paths), 100):
            r = sh("stat -c '%s %Y %n' " + " ".join(q(p) for p in paths[i:i + 100]) + " 2>/dev/null",
                   check=False)
            for line in r.splitlines():
                parts = line.split(" ", 2)
                if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
                    out[posixpath.normpath(parts[2])] = (int(parts[0]), int(parts[1]))
        return out

    def put(self, local: Path, dest: str):
        try:
            adb("push", str(local), dest)
        finally:
            local.unlink(missing_ok=True)

    # pulled copies of zips, reused while the device file is unchanged
    _cache: dict = {}
    _lock = threading.Lock()

    def fetch(self, p: str, tmp: Path) -> Path:
        st = self.stat(p)
        if st and st[0] == "file":
            with self._lock:
                hit = self._cache.get(p)
                if hit and hit[:2] == st[1:] and hit[2].exists():
                    return hit[2]
                local = WORK_DIR / f"pull_{abs(hash(p))}{posixpath.splitext(p)[1]}"
                adb("pull", p, str(local))
                self._cache[p] = (st[1], st[2], local)
                return local
        local = tmp / (posixpath.basename(p) or "root")
        adb("pull", as_dir(p), str(local))
        return local

    def replace_from(self, local: Path, p: str):
        adb("push", str(local), p)
        with self._lock:
            self._cache.pop(p, None)


LOCAL, ADB = LocalBackend(), AdbBackend()
BACKENDS = {"local": LOCAL, "adb": ADB}
OTHER = {"local": ADB, "adb": LOCAL}


# ── endpoints (same contract as server /files/api/*) ──────────────────────────

def ep_auth(be, b):
    return {"ok": True}


def ep_list(be, b):
    p = norm(b.get("path"))
    be.need(p, "dir")
    items = [{"name": n, "is_dir": k == "dir", "size": s if k == "file" else None, "mtime": m}
             for n, k, s, m in be.list(p)]
    items.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    return {"path": p.lstrip("/"), "items": items}


def ep_md5(be, b):
    p = norm(b.get("path"))
    be.need(p, "file")
    return {"md5": be.md5(p)}


def ep_folder_size(be, b):
    p = norm(b.get("path"))
    be.need(p, "dir")
    total, children = be.folder_size(p)
    return {"size": total, "fmt": _fmt(total), "children": children}


def ep_rename(be, b):
    p = norm(b.get("path"))
    if not be.exists(p):
        raise ApiError(404, "Not found")
    dest = posixpath.join(posixpath.dirname(p), check_name(b.get("new_name")))
    if be.exists(dest):
        raise ApiError(400, "Name already in use")
    be.rename(p, dest)
    return {"ok": True}


def ep_delete(be, b):
    p = norm(b.get("path"))
    if p == "/":
        raise ApiError(400, "Cannot delete root directory")
    if not be.exists(p):
        raise ApiError(404, "Not found")
    be.delete(p)
    return {"ok": True}


def ep_clean(be, b):
    p = norm(b.get("path"))
    if p == "/":
        raise ApiError(400, "Cannot clean root directory")
    be.need(p, "dir")
    return {"ok": True, "removed": be.clean(p)}


def ep_preview(be, b):
    p = norm(b.get("path"))
    size = be.need(p, "file")[1]
    offset = max(0, min(int(b.get("offset") or 0), size))
    raw = be.read_range(p, offset, PREVIEW_LIMIT) if offset < size else b""
    text, enc = _decode_with_enc(raw)
    return {"content": text, "truncated": size > PREVIEW_LIMIT,
            "size": size, "offset": offset, "page_size": PREVIEW_LIMIT,
            "editable": size <= PREVIEW_LIMIT and enc == "utf-8"}


def ep_save(be, b):
    p = norm(b.get("path"))
    if be.need(p, "file")[1] > PREVIEW_LIMIT:
        raise ApiError(400, "File is larger than 200 KB — too big to edit here")
    data = (b.get("content") or "").encode("utf-8")
    if len(data) > PREVIEW_LIMIT:
        raise ApiError(400, f"Too large to save ({_fmt(len(data))} > 200 KB)")
    fd, tmp = tempfile.mkstemp(dir=WORK_DIR)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    try:
        be.replace_from(Path(tmp), p)
    except ApiError as e:
        raise ApiError(500, f"Save failed: {e.detail}")
    finally:
        Path(tmp).unlink(missing_ok=True)
    return {"ok": True, "size": len(data), "fmt": _fmt(len(data))}


def _zip_local(be, p) -> Path:
    be.need(p, "file")
    return be.fetch(p, WORK_DIR)


def ep_zip_list(be, b):
    try:
        return {"entries": _zip_entries(_zip_local(be, norm(b.get("path"))))}
    except zipfile.BadZipFile:
        raise ApiError(400, "Invalid ZIP file")


def ep_zip_preview(be, b):
    local = _zip_local(be, norm(b.get("zip_path")))
    try:
        with zipfile.ZipFile(local) as zf:
            try:
                info = zf.getinfo(b.get("entry_path"))
            except KeyError:
                raise ApiError(404, "Entry not found in ZIP")
            with zf.open(info) as ef:
                raw = ef.read(PREVIEW_LIMIT)
        return {"content": _decode_bytes(raw),
                "truncated": info.file_size > PREVIEW_LIMIT, "size": info.file_size}
    except zipfile.BadZipFile:
        raise ApiError(400, "Invalid ZIP file")


def ep_zip_repair(be, b):
    p = norm(b.get("path"))
    local = _zip_local(be, p)
    try:
        result = _repair_zip_file(local)
    except ValueError as e:
        raise ApiError(422, str(e))
    be.replace_from(local, p)
    return {"ok": True, **result}


def ep_zip_all(be, b):
    p = norm(b.get("path"))
    be.need(p, "dir")
    names = sorted(n for n, k, _, _ in be.list(p) if k == "file" and not n.lower().endswith(".zip"))
    if not names:
        raise ApiError(400, "No non-zip files found")
    tmp = Path(tempfile.mkdtemp(dir=WORK_DIR))
    try:
        zname = f"{posixpath.basename(p) or 'root'}_{datetime.now():%Y%m%d%H%M%S}.zip"
        zlocal = tmp / zname
        with zipfile.ZipFile(zlocal, "w", zipfile.ZIP_DEFLATED) as zf:
            for n in names:
                zf.write(be.fetch(posixpath.join(p, n), tmp), n)
        size = zlocal.stat().st_size
        be.put(zlocal, posixpath.join(p, zname))
        for n in names:
            be.delete(posixpath.join(p, n))
        return {"ok": True, "zip": zname, "count": len(names), "size": _fmt(size)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _in_start(be, p: str) -> str:
    """Path of p relative to be's launch folder; 403 if p is not strictly inside it."""
    root = "/" + be.start
    if not p.startswith(root.rstrip("/") + "/"):
        raise ApiError(403, f"Only items inside {be.label} launch folder /{be.start} can be sent")
    return posixpath.relpath(p, root)


# OS clutter never sent as part of a folder
JUNK_NAMES = {".DS_Store", ".Spotlight-V100", ".Trashes", ".fseventsd", ".TemporaryItems",
              ".DocumentRevisions-V100", ".localized", "Icon\r", "Thumbs.db", "ehthumbs.db",
              "desktop.ini", "$RECYCLE.BIN"}


def _is_junk(rel: str) -> bool:
    return any(part in JUNK_NAMES or part.startswith("._") for part in rel.split("/"))


def _numbered(rel: str, taken) -> str:
    """'a/b.csv' -> first free 'a/b (01).csv', 'a/b (02).csv', ..."""
    stem, ext = posixpath.splitext(rel)
    n = 1
    while f"{stem} ({n:02d}){ext}" in taken:
        n += 1
    return f"{stem} ({n:02d}){ext}"


def ep_send(be, b):
    """Copy a file/folder to the same path under the other side's launch folder.

    Folders merge. Files that already exist are conflicts: a dry run
    ({dry: true}) reports them, then mode 'overwrite' replaces them and mode
    'rename' keeps both by sending the new one as 'name (01).ext'.
    """
    src = norm(b.get("path"))
    other = OTHER[be.side]
    rel = _in_start(be, src)
    dst = posixpath.join("/" + other.start, rel)
    join = lambda root, r: posixpath.normpath(posixpath.join(root, r))
    st = be.stat(src)
    if st is None:
        raise ApiError(404, "Source not found")
    item_dst = dst
    if st[0] == "dir":
        src_tree, dst_tree = be.walk(src), other.walk(dst)
        src_tree = {r: v for r, v in src_tree.items() if not r or not _is_junk(r)}
    else:
        # a single file: work from its parent so a rename is checked against its siblings
        name = posixpath.basename(src)
        src, dst, rel = posixpath.dirname(src), posixpath.dirname(dst), posixpath.dirname(rel)
        src_tree = {name: ("file", st[1])}
        dst_tree = ({n: (k, s) for n, k, s, _ in other.list(dst)}
                    if other.stat(dst) is not None else {})
    clash = [r for r, (k, _) in src_tree.items() if r in dst_tree and dst_tree[r][0] != k]
    if clash:
        r = clash[0]
        raise ApiError(409, f'/{join(dst, r).lstrip("/")} is a '
                            f'{dst_tree[r][0].replace("dir", "folder")} on {other.label} '
                            f'but a {src_tree[r][0].replace("dir", "folder")} here')
    files = sorted(r for r, (k, _) in src_tree.items() if k == "file")
    conflicts = [r for r in files if r in dst_tree]
    size = sum(src_tree[r][1] for r in files)
    summary = {"dest": item_dst.lstrip("/"), "files": len(files), "fmt": _fmt(size),
               "merge": st[0] == "dir" and bool(dst_tree)}
    if b.get("dry"):
        return {**summary, "conflicts": [join(rel, r) for r in conflicts]}
    mode = b.get("mode")
    if conflicts and mode not in ("overwrite", "rename"):
        raise ApiError(409, f"{len(conflicts)} file(s) already exist — choose overwrite or keep both")

    # create folders (incl. empty ones), then copy files grouped by folder:
    # one adb push/pull per folder, one extra call per renamed file
    dirs = {join(dst, r) for r, (k, _) in src_tree.items() if k == "dir"}
    dirs |= {posixpath.dirname(join(dst, r)) for r in files}
    other.mkdirs(sorted(dirs))
    taken = set(dst_tree) | set(src_tree)
    groups, singles, renamed = {}, [], []
    for r in files:
        s = join(src, r)
        if r in dst_tree and mode == "rename":
            new = _numbered(r, taken)
            taken.add(new)
            singles.append((s, join(dst, new)))
            renamed.append(join(rel, new))
        else:
            groups.setdefault(posixpath.dirname(join(dst, r)), []).append(s)
    op = "push" if be is LOCAL else "pull"
    size_of = {join(src, r): src_tree[r][1] for r in files}
    steps = []   # (adb args, [(target, bytes)])
    for d, srcs in groups.items():
        for i in range(0, len(srcs), 100):
            chunk = srcs[i:i + 100]
            steps.append(([op, *chunk, d + "/" if op == "push" else d],
                          [(posixpath.join(d, posixpath.basename(s)), size_of[s]) for s in chunk]))
    for s, d in singles:
        steps.append(([op, s, d], [(d, size_of[s])]))
    result = {"ok": True, **summary, "sent": len(files),
              "overwritten": len(conflicts) if mode == "overwrite" else 0,
              "renamed": renamed}
    return {"job": start_send_job(other, steps, size, len(files), result), **summary}


# ── send jobs: run in a thread, progress = bytes present at the destination ──

_jobs: dict = {}
_jobs_lock = threading.Lock()


def start_send_job(dest_be, steps, total, nfiles, result) -> str:
    jid = os.urandom(6).hex()
    job = {"dest_be": dest_be, "steps": steps, "total": total, "files": nfiles,
           "result": result, "state": "running", "error": None, "step": 0,
           "done_bytes": 0, "done_files": 0, "t0": time.time(), "t1": None,
           "baseline": {}, "poll": (0.0, 0, "")}

    def run():
        try:
            for i, (args, targets) in enumerate(steps):
                # files being overwritten already exist: only count them once they change
                job["baseline"] = dest_be.sizes([tg for tg, _ in targets])
                job["step"] = i
                adb(*args)
                job["done_bytes"] += sum(n for _, n in targets)
                job["done_files"] += len(targets)
            job["state"] = "done"
        except ApiError as e:
            job["state"], job["error"] = "error", e.detail
        except Exception as e:
            job["state"], job["error"] = "error", f"{type(e).__name__}: {e}"
        finally:
            job["t1"] = time.time()

    with _jobs_lock:
        for old in [k for k, j in _jobs.items() if j["state"] != "running"][:-20]:
            del _jobs[old]
        _jobs[jid] = job
    threading.Thread(target=run, daemon=True).start()
    return jid


def _job_partial(job):
    """(bytes, current file) copied so far inside the running step; polled at most 1/s."""
    now = time.time()
    t, partial, cur = job["poll"]
    if now - t < 0.9:
        return partial, cur
    targets = job["steps"][job["step"]][1] if job["steps"] else []
    seen = {}
    try:
        seen = job["dest_be"].sizes([tg for tg, _ in targets])
    except ApiError:
        pass
    partial, cur = 0, ""
    for tg, n in targets:
        st = seen.get(tg)
        if st and st != job["baseline"].get(tg):
            partial += min(st[0], n)
            if st[0] < n:
                cur = posixpath.basename(tg)
    job["poll"] = (now, partial, cur)
    return partial, cur


def ep_send_status(be, b):
    job = _jobs.get(b.get("job") or "")
    if job is None:
        raise ApiError(404, "Unknown send job")
    if job["state"] == "running":
        partial, cur = _job_partial(job)
        done = min(job["done_bytes"] + partial, job["total"])
    else:
        done, cur = (job["total"] if job["state"] == "done" else job["done_bytes"]), ""
    elapsed = (job["t1"] or time.time()) - job["t0"]
    speed = done / elapsed if elapsed > 0.5 else 0
    out = {"state": job["state"], "error": job["error"],
           "done": done, "total": job["total"], "fmt_done": _fmt(done), "fmt_total": _fmt(job["total"]),
           "pct": round(100 * done / job["total"], 1) if job["total"] else (100 if job["state"] == "done" else 0),
           "files_done": job["done_files"], "files": job["files"], "current": cur,
           "speed": _fmt(int(speed)) + "/s" if speed else "", "elapsed": int(elapsed)}
    if job["state"] == "done":
        out["result"] = job["result"]
    return out


JSON_ENDPOINTS = {
    "auth": ep_auth, "list": ep_list, "md5": ep_md5, "folder-size": ep_folder_size,
    "rename": ep_rename, "delete": ep_delete, "clean": ep_clean, "preview": ep_preview,
    "save": ep_save, "zip-list": ep_zip_list, "zip-preview": ep_zip_preview,
    "zip-repair": ep_zip_repair, "zip-all": ep_zip_all, "send": ep_send,
    "send-status": ep_send_status,
}


# ── multipart upload (streamed to disk) ───────────────────────────────────────

def parse_multipart(rfile, length: int, boundary: bytes):
    """-> (fields, (filename, local_path) | None). File part is streamed to WORK_DIR."""
    sep = b"\r\n--" + boundary
    buf = b"\r\n"            # lets the first delimiter match `sep` too
    remaining = length
    fields, upload = {}, None

    def fill():
        nonlocal buf, remaining
        if remaining <= 0:
            return False
        chunk = rfile.read(min(CHUNK, remaining))
        if not chunk:
            remaining = 0
            return False
        remaining -= len(chunk)
        buf += chunk
        return True

    while sep not in buf and fill():
        pass
    buf = buf[buf.find(sep) + len(sep):]
    while True:
        while len(buf) < 2 and fill():
            pass
        if buf.startswith(b"--") or not buf:
            break
        while b"\r\n\r\n" not in buf:
            if not fill():
                raise ApiError(400, "Malformed upload")
        head, buf = buf.split(b"\r\n\r\n", 1)
        disp = next((l for l in head.decode("utf-8", "replace").split("\r\n")
                     if l.lower().startswith("content-disposition")), "")
        params = {}
        for part in disp.split(";")[1:]:
            k, _, v = part.strip().partition("=")
            params[k.lower()] = v.strip('"')
        out = None
        if "filename" in params:
            fd, local = tempfile.mkstemp(dir=WORK_DIR)
            out = os.fdopen(fd, "wb")
            upload = (params["filename"], Path(local))
        value = b""
        while True:
            idx = buf.find(sep)
            if idx != -1:
                data, buf = buf[:idx], buf[idx + len(sep):]
            elif len(buf) > len(sep):
                data, buf = buf[:-len(sep)], buf[-len(sep):]
            else:
                data = b""
            if out:
                out.write(data)
            else:
                value += data
            if idx != -1:
                break
            if not fill():
                raise ApiError(400, "Upload truncated")
        if out:
            out.close()
        else:
            fields[params.get("name", "")] = value.decode("utf-8", "replace")
    return fields, upload


def do_upload(be, handler):
    ctype = handler.headers.get("Content-Type", "")
    boundary = next((p.strip()[9:].strip('"') for p in ctype.split(";")
                     if p.strip().startswith("boundary=")), None)
    if not boundary:
        raise ApiError(400, "Expected multipart/form-data")
    fields, upload = parse_multipart(handler.rfile, int(handler.headers.get("Content-Length", 0)),
                                     boundary.encode())
    if not upload:
        raise ApiError(400, "No file")
    fname, local = upload
    try:
        fname = check_name(fname)
        d = norm(fields.get("path"))
        be.need(d, "dir")
        dest = posixpath.join(d, fname)
        if be.exists(dest):
            raise ApiError(400, f'"{fname}" already exists')
        be.put(local, dest)
    finally:
        local.unlink(missing_ok=True)
    return {"ok": True, "name": fname}


# ── HTTP ──────────────────────────────────────────────────────────────────────

UI_TEMPLATE = (HERE / "ui.html").read_text()
SPLIT_PAGE = (HERE / "split.html").read_bytes()


def page_for(be: Backend) -> bytes:
    other = OTHER[be.side]
    return (UI_TEMPLATE
            .replace("__TITLE__", f"{be.label} — Files")
            .replace("__API__", f"/{be.side}/api/")
            .replace("__START__", be.start)
            .replace("__SIDE__", be.side)
            .replace("__OTHER__", other.side)
            .replace("__ROOT_LABEL__", be.label)
            .replace("__OTHER_LABEL__", other.label.split(" ", 1)[1])).encode()


def disposition(kind: str, name: str) -> str:
    ascii_name = name.encode("ascii", "replace").decode().replace('"', "_")
    return f"{kind}; filename=\"{ascii_name}\"; filename*=UTF-8''{urllib.parse.quote(name)}"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.command} {urllib.parse.unquote(self.path)[:160]} "
                         f"{args[1] if len(args) > 1 else ''}\n")

    def send_json(self, obj, status=200, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_bytes(self, body: bytes, ctype: str):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, to: str):
        self.send_response(302)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def route(self):
        """-> (backend, rest-of-path) for /local/... and /adb/..., else (None, path)."""
        path = urllib.parse.urlsplit(self.path).path
        side, _, rest = path.lstrip("/").partition("/")
        return BACKENDS.get(side), rest

    def run(self, fn):
        try:
            fn()
        except ApiError as e:
            self.send_json({"detail": e.detail}, e.status,
                           {"Content-Range": e.detail} if e.status == 416 else None)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except PermissionError:
            self.send_json({"detail": "Permission denied"}, 403)
        except Exception as e:
            self.send_json({"detail": f"{type(e).__name__}: {e}"}, 500)

    # GET ---------------------------------------------------------------------
    def do_GET(self):
        be, rest = self.route()
        qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        if be is None:
            if urllib.parse.urlsplit(self.path).path == "/":
                return self.send_bytes(SPLIT_PAGE, "text/html; charset=utf-8")
            return self.redirect("/")
        if rest == "":
            return self.send_bytes(page_for(be), "text/html; charset=utf-8")
        if rest == "api/dl":
            return self.run(lambda: self.stream(be, norm(qs.get("path"))))
        if rest == "api/raw":
            return self.run(lambda: self.stream(be, norm(qs.get("path")), inline=True))
        if "/" not in rest:
            return self.redirect(f"/{be.side}/")
        self.send_json({"detail": "Not found"}, 404)

    def stream(self, be, p: str, inline=False):
        size = be.need(p, "file")[1]
        name = posixpath.basename(p)
        if inline:
            mt = IMAGE_TYPES.get(posixpath.splitext(name)[1].lower())
            if not mt:
                raise ApiError(400, "Not a viewable image")
            headers = {"Content-Disposition": disposition("inline", name),
                       "X-Content-Type-Options": "nosniff",
                       "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
                       "Cache-Control": "private, max-age=300"}
        else:
            mt = "application/octet-stream"
            headers = {"Content-Disposition": disposition("attachment", name)}
        rng = _parse_range(self.headers.get("Range"), size)
        if rng == "bad":
            raise ApiError(416, f"bytes */{size}")
        start, end = rng if rng else (0, size - 1)
        length = max(0, end - start + 1)
        self.send_response(206 if rng else 200)
        self.send_header("Content-Type", mt)
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        if rng:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        if length:
            for chunk in be.iter_range(p, start, length):
                self.wfile.write(chunk)

    # POST --------------------------------------------------------------------
    def do_POST(self):
        be, rest = self.route()
        if be is None or not rest.startswith("api/"):
            return self.send_json({"detail": "Not found"}, 404)
        self.run(lambda: self.post(be, rest[4:]))

    def post(self, be, ep: str):
        if ep == "upload":
            return self.send_json(do_upload(be, self))
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}") if n else {}
        if ep in JSON_ENDPOINTS:
            return self.send_json(JSON_ENDPOINTS[ep](be, body))
        if ep == "download":
            return self.stream(be, norm(body.get("path")))
        if ep == "download-zip":
            return self.download_zip(be, norm(body.get("path")))
        raise ApiError(501, f"'{ep}' is not available here")

    def download_zip(self, be, p: str):
        be.need(p, "dir")
        tmp = Path(tempfile.mkdtemp(dir=WORK_DIR))
        try:
            name = posixpath.basename(p) or "root"
            src = be.fetch(p, tmp)
            zlocal = tmp / f"{name}.zip"
            with zipfile.ZipFile(zlocal, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, dirs, files in os.walk(src):
                    dirs.sort()
                    for fname in sorted(files):
                        fp = Path(root) / fname
                        try:
                            zf.write(fp, fp.relative_to(src))
                        except OSError:
                            pass
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(zlocal.stat().st_size))
            self.send_header("Content-Disposition", disposition("attachment", f"{name}.zip"))
            self.end_headers()
            with open(zlocal, "rb") as f:
                shutil.copyfileobj(f, self.wfile, CHUNK)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def main():
    if not shutil.which("adb"):
        sys.exit("adb not found on PATH")
    state = subprocess.run(["adb", "get-state"], capture_output=True, text=True)
    if state.returncode:
        print("Device: none — " + (state.stderr.strip() or "adb get-state failed")
              + " (Mac window still works; set ANDROID_SERIAL if several are attached)")
    else:
        model = subprocess.run(["adb", "shell", "getprop ro.product.model"],
                               capture_output=True, text=True).stdout.strip()
        print(f"Device: {model or 'unknown'}")
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    srv.daemon_threads = True
    print(f"Open:    http://localhost:{PORT}/  (Mac | Android)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        shutil.rmtree(WORK_DIR, ignore_errors=True)


if __name__ == "__main__":
    main()
