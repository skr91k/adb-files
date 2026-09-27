# adb-files

A local, two-pane file browser for your **Mac** and an **Android phone over adb**, in one browser window.

- **Left pane:** your Mac's files.
- **Right pane:** the phone's files, via `adb`.
- **Send between them.** Right-click any file or folder and choose **Send to Android** or **Send to Mac**.

It uses only the Python standard library, so there's nothing to `pip install`. It runs on `localhost` only.

## Features

**Browsing, on both panes**
- Browse folders. Sort by name, size or date.
- Preview and edit text, CSV and JSON files.
- View images. Look inside zip files and repair broken ones.
- Upload, download (resumable), rename and delete. Get MD5 checksums and folder sizes. Zip loose files.

**Sending between Mac and Android**
- **Same place on the other side.** An item goes to the same path under the other side's launch folder: `DATA/x/y/file` goes to `DATA/x/y/file`. Missing folders are created.
- **Folders merge** into an existing folder of the same name.
- **Nothing is overwritten silently.** If files already exist, you choose **Overwrite**, **Keep both** (saved as `name (01).ext`), or **Cancel**.
- **Live progress** shows percentage, bytes, files, speed and the current file.
- **Junk is skipped.** `.DS_Store`, `._*`, `Thumbs.db` and similar are left out when sending a folder.
- **Only items inside the launch folders can be sent.**

**Layout**
- The path bar, toolbar and column headers stay fixed while the list scrolls.
- Drag the divider to resize the panes. It remembers your split.

## Requirements

- macOS, with zsh for the `adbb` helper. The server itself is plain Python and should run anywhere.
- Python 3.8 or newer.
- `adb` on your `PATH` (Android platform-tools).
- USB debugging enabled on the phone, and this computer authorized.

## Usage

The quickest way is the `adbb` shell helper. Add it to `~/.zshrc`:

```zsh
source /path/to/adb-files/adbb.zsh
```

Then:

```zsh
adbb           # start the server and open http://localhost:8090/ in Chrome
adbb 2         # several phones attached? pick #2 (or pass a serial)
adbb stop      # stop the server
```

With several devices attached, `adbb` lists them and asks which one to use. Picking a different phone restarts the server on it.

You can also run the server directly:

```sh
python3 adb_files.py
```

Then open:

| URL | Shows |
|---|---|
| `http://localhost:8090/` | both panes, split |
| `http://localhost:8090/local/` | Mac only |
| `http://localhost:8090/adb/` | Android only |

## Configuration

All settings are environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `LOCAL_START` | `~/BhavAppData/DATA` | Mac launch folder, and the root for sending |
| `ADB_START` | `sdcard/Android/data/shakir.bhav.android/files/DATA` | Android launch folder, and the root for sending |
| `PORT` | `8090` | HTTP port |
| `HOST` | `127.0.0.1` | Bind address. Keep it local: there is no password. |
| `ANDROID_SERIAL` | — | Which device to use when several are attached |

For example:

```sh
LOCAL_START=~/Documents ADB_START=sdcard/Download python3 adb_files.py
```

## Files

| File | Purpose |
|---|---|
| `adb_files.py` | HTTP server, with a Mac backend and an adb backend behind the same API |
| `ui.html` | The file browser page, served once per pane |
| `split.html` | The two-pane page with the draggable divider |
| `adbb.zsh` | The `adbb` start/stop/open helper |

## Security

There is **no authentication**. Anyone who can reach the port can read, change and delete files on your Mac and the phone. The server binds to `127.0.0.1` by default. Don't expose it to a network.
