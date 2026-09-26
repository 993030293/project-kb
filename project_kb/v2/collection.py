"""Bounded Windows collection primitives, without database or publication state."""

from __future__ import annotations

import codecs
from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import stat
from typing import BinaryIO, Iterator

from .. import runtime
from ..config import MAX_INDEX_FILE_BYTES, PRIORITY_FILENAMES, SAFE_TEXT_EXTENSIONS
from ..textutil import is_sensitive_path


PARSER_VERSION = "w3-collection-1"
READ_SIZE = 64 * 1024
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
_API_KEY = re.compile(
    r"(?<![A-Za-z0-9])(?:sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,}"
    r"|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"
    r"|AIza[A-Za-z0-9_-]{35}|(?:AKIA|ASIA)[A-Z0-9]{16}"
    r"|xox[baprs]-[A-Za-z0-9-]{20,})(?![A-Za-z0-9])"
)
_SECRET_NAME = r"(?:[a-z][a-z0-9_-]{0,63}[_-])?(?:password|passwd|pwd|token|api[_-]?key|client[_-]?secret)"
_SECRET_FIELD = re.compile(rf"{_SECRET_NAME}\Z", re.IGNORECASE)
_ASSIGNMENT = re.compile(
    rf"(?<![\w])(?:[\"']?{_SECRET_NAME}[\"']?)\s*"
    r"(?::\s*(?:str|String|Optional\[str\]))?\s*[:=]\s*"
    r"(?:\"(?P<double>[^\"\r\n]*)\"|'(?P<single>[^'\r\n]*)'|(?P<bare>[^\s,;}\]#]+))",
    re.IGNORECASE,
)


class CollectionError(ValueError):
    """A classified path-level failure; never attach source content."""

    def __init__(self, code: str, path: Path):
        self.code = code
        self.path = str(path)
        super().__init__(f"{code}: {path}")


def _bound(path: Path, kind: str) -> Path:
    path = Path(path)
    # Win32 alternate streams and trailing-dot aliases are not independent files.
    if any(":" in part or part.rstrip(" .") != part for part in path.parts[1:]):
        raise CollectionError("path_alias", path)
    try:
        checked = runtime.source_path(path) if kind == "source" else runtime.kb_path(path)
    except (ValueError, OSError):
        raise CollectionError("unsafe_path", path) from None
    if kind == "source" and any(is_sensitive_path(part) for part in (checked, *checked.parents)):
        raise CollectionError("sensitive_path", checked)
    return checked


def _identity(info: os.stat_result) -> dict:
    # Keep the stored Windows ctime field's historical creation-time meaning.
    # Python 3.12 fstat and lstat can disagree on ctime while birthtime agrees.
    created = getattr(info, "st_birthtime_ns", info.st_ctime_ns) if os.name == "nt" else info.st_ctime_ns
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": created,
    }


def _fs_path(path: Path) -> Path:
    if os.name != "nt":
        return path
    name = str(path)
    if name.startswith("\\\\?\\"):
        return path
    if name.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + name[2:])
    return Path("\\\\?\\" + name)


def _regular(info: os.stat_result, path: Path) -> None:
    if getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise CollectionError("unsafe_path", path)
    if not stat.S_ISREG(info.st_mode):
        raise CollectionError("not_regular", path)
    if info.st_nlink != 1:
        raise CollectionError("hardlink", path)


@lru_cache(maxsize=1)
def _kernel():
    if os.name != "nt":
        raise CollectionError("platform_unsupported", Path(__file__))
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetFileInformationByHandleEx.argtypes = (
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    )
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    return kernel


def _win_handle(path: Path, *, directory: bool = False, create: bool = False):
    kernel = _kernel()
    access = 0x80 if directory else (0x40000000 if create else 0x80000000)
    # Directory handles permit child writes, but not rename/delete of ancestors.
    share = 0x3 if directory else 0x1
    flags = 0x00200000 | (0x02000000 if directory else 0x08000000)
    handle = kernel.CreateFileW(str(_fs_path(path)), access, share, None, 1 if create else 3, flags, None)
    if handle == ctypes.c_void_p(-1).value:
        error = ctypes.get_last_error()
        code = "destination_exists" if error in (80, 183) else "io_error"
        if error in (32, 33):
            code = "sharing_violation"
        raise CollectionError(code, path)
    try:
        attributes = (wintypes.DWORD * 2)()
        if not kernel.GetFileInformationByHandleEx(handle, 9, attributes, ctypes.sizeof(attributes)):
            raise CollectionError("identity_unavailable", path)
        if attributes[0] & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise CollectionError("unsafe_path", path)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    return handle


@contextmanager
def _parents(path: Path):
    with ExitStack() as stack:
        for parent in reversed(path.parents):
            if parent == Path(parent.anchor):
                continue
            runtime.reject_reparse(parent)
            handle = _win_handle(parent, directory=True)
            stack.callback(_kernel().CloseHandle, handle)
            runtime.reject_reparse(parent)
        yield


def _open_file(path: Path, *, create: bool = False) -> BinaryIO:
    if os.name != "nt":
        raise CollectionError("platform_unsupported", path)
    import msvcrt

    handle = _win_handle(path, create=create)
    try:
        flags = os.O_BINARY | (os.O_WRONLY if create else os.O_RDONLY)
        fd = msvcrt.open_osfhandle(handle, flags)
    except BaseException:
        _kernel().CloseHandle(handle)
        raise
    try:
        return os.fdopen(fd, "wb" if create else "rb")
    except BaseException:
        os.close(fd)
        raise


def _verify(stream: BinaryIO, path: Path, kind: str, identity: dict) -> None:
    checked = _bound(path, kind)
    actual = os.fstat(stream.fileno())
    named = _fs_path(checked).lstat()
    _regular(actual, path)
    _regular(named, path)
    if _identity(actual) != identity or _identity(named) != identity:
        raise CollectionError("source_changed" if kind == "source" else "asset_changed", path)


@contextmanager
def _reader(path: Path, kind: str):
    path = _bound(path, kind)
    try:
        with _parents(path):
            path = _bound(path, kind)
            before = _fs_path(path).lstat()
            _regular(before, path)
            with _open_file(path) as stream:
                identity = _identity(before)
                _verify(stream, path, kind, identity)
                try:
                    yield stream, identity
                finally:
                    _verify(stream, path, kind, identity)
    except CollectionError as exc:
        if exc.code in ("io_error", "sharing_violation", "identity_unavailable"):
            raise CollectionError("source_unavailable" if kind == "source" else "asset_unavailable", path) from None
        raise
    except OSError:
        raise CollectionError("source_unavailable" if kind == "source" else "asset_unavailable", path) from None
    except ValueError:
        raise CollectionError("unsafe_path", path) from None


def _read_bounded(stream: BinaryIO, path: Path, identity: dict) -> bytes:
    if identity["size"] > MAX_INDEX_FILE_BYTES:
        raise CollectionError("too_large", path)
    data = bytearray()
    while True:
        block = stream.read(min(READ_SIZE, MAX_INDEX_FILE_BYTES + 1 - len(data)))
        if not block:
            break
        data.extend(block)
        if len(data) > MAX_INDEX_FILE_BYTES:
            raise CollectionError("too_large", path)
    if len(data) != identity["size"]:
        raise CollectionError("source_changed", path)
    return bytes(data)


def _decode(data: bytes, path: Path) -> tuple[str, str]:
    # Check all bounded bytes, not only the initial sample used by the old reader.
    if any(byte < 32 and byte not in (9, 10, 12, 13) for byte in data) or b"\x7f" in data:
        raise CollectionError("binary_content", path)
    encodings = ("utf-8-sig",) if data.startswith(codecs.BOM_UTF8) else ("utf-8", "gb18030")
    for encoding in encodings:
        try:
            return data.decode(encoding, errors="strict"), encoding
        except UnicodeDecodeError:
            continue
    raise CollectionError("unsupported_encoding", path)


def _literal(value: str) -> bool:
    value = value.strip()
    if not value or value.lower() in ("none", "null"):
        return False
    if value.startswith(("${", "$env:", "os.environ", "os.getenv(", "getenv(", "process.env.")):
        return False
    return True


def _credential_text(text: str) -> bool:
    if _PRIVATE_KEY.search(text) or _API_KEY.search(text):
        return True
    for match in _ASSIGNMENT.finditer(text):
        quoted = match.group("double") if match.group("double") is not None else match.group("single")
        if (quoted is not None and quoted != "") or (quoted is None and _literal(match.group("bare"))):
            return True
    return False


def _credential_tree(value: object) -> bool:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if _credential_text(item):
                return True
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, dict):
            for key, child in item.items():
                if _SECRET_FIELD.fullmatch(key) and child is not None and child != "":
                    return True
                pending.append(child)
    return False


def _scan_credentials(text: str, path: Path, *, source_format: str | None = None) -> None:
    if _credential_text(text):
        raise CollectionError("sensitive_content", path)
    source_format = source_format if source_format is not None else path.suffix.lower()
    if source_format not in (".json", ".jsonl", ".ipynb"):
        return

    def object_values(pairs):
        # Inspect every key before duplicate-key normalization can discard it.
        for key, value in pairs:
            if _SECRET_FIELD.fullmatch(key) and value is not None and value != "":
                raise CollectionError("sensitive_content", path)
        return [value for _, value in pairs]

    documents = text.split("\n") if source_format == ".jsonl" else (text,)
    for document in documents:
        try:
            value = json.loads(document, object_pairs_hook=object_values)
        except CollectionError:
            raise
        except json.JSONDecodeError:
            continue
        except (RecursionError, ValueError):
            raise CollectionError("structured_text_limit", path) from None
        if _credential_tree(value):
            raise CollectionError("sensitive_content", path)


def _extract(text: str, path: Path, *, notebook: bool | None = None) -> tuple[str, list[dict]]:
    notebook_mode = notebook if notebook is not None else path.suffix.lower() == ".ipynb"
    if not notebook_mode:
        return text, [{"field": "decoded_text", "char_start": 0, "char_end": len(text)}]
    try:
        notebook = json.loads(text)
    except (ValueError, RecursionError):
        raise CollectionError("invalid_notebook", path) from None
    if not isinstance(notebook, dict) or not isinstance(notebook.get("cells"), list):
        raise CollectionError("invalid_notebook", path)
    output: list[str] = []
    source_map: list[dict] = []
    offset = 0
    for index, cell in enumerate(notebook["cells"]):
        if not isinstance(cell, dict):
            raise CollectionError("invalid_notebook", path)
        if cell.get("cell_type") not in ("markdown", "code"):
            continue
        source = cell.get("source")
        if not isinstance(source, (str, list)) or (
            isinstance(source, list) and not all(isinstance(part, str) for part in source)
        ):
            raise CollectionError("invalid_notebook", path)
        entry = {"cell_index": index, "cell_type": cell["cell_type"],
                 "field": f"cells[{index}].source", "source_form": "list" if isinstance(source, list) else "string"}
        if source_map:
            output.append("\n\n")
            entry["separator_before"] = {"char_start": offset, "char_end": offset + 2, "generated": True}
            offset += 2
        entry["char_start"] = offset
        parts = source if isinstance(source, list) else [source]
        entry["parts"] = []
        for part_index, part in enumerate(parts):
            entry["parts"].append({
                "field": f"cells[{index}].source[{part_index}]" if isinstance(source, list) else entry["field"],
                "char_start": offset, "char_end": offset + len(part),
            })
            output.append(part)
            offset += len(part)
        entry["char_end"] = offset
        source_map.append(entry)
    return "".join(output), source_map


def _destination(path: Path) -> Path:
    path = _bound(path, "kb")
    staging = _bound(runtime.KB_ROOT / "vault" / "staging", "kb")
    if path == staging or not path.is_relative_to(staging):
        raise CollectionError("outside_staging", path)
    try:
        exists = _fs_path(path).exists()
    except OSError:
        raise CollectionError("asset_unavailable", path) from None
    if exists:
        raise CollectionError("destination_exists", path)
    return path


def _write(stream: BinaryIO, data: bytes, path: Path) -> None:
    for offset in range(0, len(data), READ_SIZE):
        block = data[offset:offset + READ_SIZE]
        if stream.write(block) != len(block):
            raise CollectionError("short_write", path)
    stream.flush()
    os.fsync(stream.fileno())


def collect_file(source: Path, raw_destination: Path, extracted_destination: Path) -> dict:
    """Create private staging files after validation; failures never overwrite assets.

    Characters are Unicode code points. UTF-8 BOM is an encoding marker removed
    only from extraction. I/O failures may leave unreferenced partial staging
    files; reconciliation and final publication belong to the caller.
    """
    source = _bound(source, "source")
    if source.suffix.lower() not in SAFE_TEXT_EXTENSIONS and (
        source.name.lower() not in PRIORITY_FILENAMES and source.stem.lower() not in PRIORITY_FILENAMES
    ):
        raise CollectionError("unsupported_extension", source)
    try:
        runtime.require_sandbox_writes()
    except (PermissionError, ValueError, OSError):
        raise CollectionError("writes_disabled_or_unsafe", source) from None
    raw_destination = _destination(raw_destination)
    extracted_destination = _destination(extracted_destination)
    if raw_destination == extracted_destination:
        raise CollectionError("destinations_same", raw_destination)
    with _reader(source, "source") as (stream, identity):
        raw = _read_bounded(stream, source, identity)
        _verify(stream, source, "source", identity)
        text, encoding = _decode(raw, source)
        _scan_credentials(text, source)
        extracted, source_map = _extract(text, source)
        if _credential_text(extracted):
            raise CollectionError("sensitive_content", source)
        try:
            encoded = extracted.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise CollectionError("invalid_unicode", source) from None
        _verify(stream, source, "source", identity)
        # The caller prepares staging directories; do not create paths on denial.
        try:
            with _parents(raw_destination), _parents(extracted_destination):
                _destination(raw_destination)
                _destination(extracted_destination)
                with _open_file(raw_destination, create=True) as raw_out:
                    with _open_file(extracted_destination, create=True) as text_out:
                        _regular(os.fstat(raw_out.fileno()), raw_destination)
                        _regular(os.fstat(text_out.fileno()), extracted_destination)
                        _write(raw_out, raw, raw_destination)
                        _write(text_out, encoded, extracted_destination)
                        _verify(raw_out, raw_destination, "kb", _identity(os.fstat(raw_out.fileno())))
                        _verify(text_out, extracted_destination, "kb", _identity(os.fstat(text_out.fileno())))
        except CollectionError as exc:
            if exc.code in ("io_error", "sharing_violation", "identity_unavailable"):
                raise CollectionError("asset_write_failed", raw_destination) from None
            raise
        except OSError:
            raise CollectionError("asset_write_failed", raw_destination) from None
        except ValueError:
            raise CollectionError("unsafe_path", raw_destination) from None
    return {
        "status": "collected", "identity": identity, "raw_bytes": len(raw),
        "parser_version": PARSER_VERSION, "encoding": encoding, "extracted_chars": len(extracted),
        "mode": "notebook_cells" if source.suffix.lower() == ".ipynb" else "text",
        "source_format": source.suffix.lower() if source.suffix.lower() in (".json", ".jsonl", ".ipynb") else "text",
        "location_basis": "extracted_text", "char_offsets": "zero_based_half_open_unicode_codepoints",
        "cell_index_basis": "zero_based", "source_map": source_map,
    }


def source_identity(path: Path) -> dict:
    """Return checked filesystem identity without reading source content.

    This is metadata-only observation, not content freshness verification. A
    metadata-fast caller must continue to report not_fully_checked.
    """
    with _reader(path, "source") as (_, identity):
        result = dict(identity)
    return result


def verify_snapshot(raw: Path, extracted: Path, metadata: dict) -> None:
    """Replay current extraction and verify complete private KB assets, read-only.

    This validates raw/extracted consistency and metadata, not cryptographic
    authenticity against coordinated modification of all three inputs.
    """
    raw, extracted = Path(raw), Path(extracted)
    try:
        if not isinstance(metadata, dict) or metadata.get("parser_version") != PARSER_VERSION:
            raise CollectionError("asset_corrupt", raw)
        source_format = metadata.get("source_format")
        if source_format not in ("text", ".json", ".jsonl", ".ipynb"):
            raise CollectionError("asset_corrupt", raw)
        mode = "notebook_cells" if source_format == ".ipynb" else "text"
        if metadata.get("mode") != mode or metadata.get("location_basis") != "extracted_text":
            raise CollectionError("asset_corrupt", raw)
        if metadata.get("char_offsets") != "zero_based_half_open_unicode_codepoints" or (
            metadata.get("cell_index_basis") != "zero_based"
        ):
            raise CollectionError("asset_corrupt", raw)
        source_info = metadata.get("identity")
        identity_keys = {"device", "inode", "size", "mtime_ns", "ctime_ns"}
        if not isinstance(source_info, dict) or set(source_info) != identity_keys or (
            any(type(value) is not int for value in source_info.values())
        ):
            raise CollectionError("asset_corrupt", raw)
        if type(metadata.get("raw_bytes")) is not int or type(metadata.get("extracted_chars")) is not int:
            raise CollectionError("asset_corrupt", raw)
        raw = _bound(raw, "kb")
        extracted = _bound(extracted, "kb")
        if raw == extracted:
            raise CollectionError("asset_corrupt", raw)
        with _reader(raw, "kb") as (raw_stream, raw_identity):
            with _reader(extracted, "kb") as (text_stream, text_identity):
                data = _read_bounded(raw_stream, raw, raw_identity)
                if len(data) != metadata["raw_bytes"] or source_info["size"] != len(data):
                    raise CollectionError("asset_corrupt", raw)
                text, encoding = _decode(data, raw)
                _scan_credentials(text, raw, source_format=source_format)
                expected, source_map = _extract(text, raw, notebook=mode == "notebook_cells")
                if _credential_text(expected):
                    raise CollectionError("asset_corrupt", raw)
                if encoding != metadata.get("encoding") or len(expected) != metadata["extracted_chars"]:
                    raise CollectionError("asset_corrupt", raw)
                expected_map = json.dumps(source_map, ensure_ascii=True, sort_keys=True, allow_nan=False)
                recorded_map = json.dumps(metadata.get("source_map"), ensure_ascii=True, sort_keys=True, allow_nan=False)
                if expected_map != recorded_map:
                    raise CollectionError("asset_corrupt", raw)
                if text_identity["size"] != len(expected.encode("utf-8", errors="strict")):
                    raise CollectionError("asset_corrupt", extracted)
                decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
                offset = 0
                while True:
                    block = text_stream.read(READ_SIZE)
                    actual = decoder.decode(block, final=not block)
                    if actual != expected[offset:offset + len(actual)]:
                        raise CollectionError("asset_corrupt", extracted)
                    offset += len(actual)
                    if not block:
                        break
                if offset != len(expected):
                    raise CollectionError("asset_corrupt", extracted)
    except CollectionError as exc:
        if exc.code in ("asset_unavailable", "asset_corrupt"):
            raise
        raise CollectionError("asset_corrupt", Path(exc.path)) from None
    except OSError:
        raise CollectionError("asset_unavailable", raw) from None
    except (ValueError, TypeError):
        raise CollectionError("asset_corrupt", raw) from None


def files_equal(left: Path, right: Path) -> bool:
    """Compare a source and private KB snapshot completely, with bounded buffers."""
    equal = True
    with _reader(left, "source") as (left_stream, _):
        with _reader(right, "kb") as (right_stream, _):
            while True:
                left_bytes = left_stream.read(READ_SIZE)
                right_bytes = right_stream.read(READ_SIZE)
                if left_bytes != right_bytes:
                    equal = False
                if not left_bytes and not right_bytes:
                    break
    return equal


def iter_chunks(extracted: Path, max_chars: int = 10000, max_lines: int = 180) -> Iterator[dict]:
    """Yield lossless chunks with 1-based inclusive universal-newline line ranges.

    CRLF belongs to one line even when split by the character cap. Character
    offsets are zero-based, half-open Unicode code-point offsets in extraction.
    """
    if type(max_chars) is not int or type(max_lines) is not int or min(max_chars, max_lines) < 1:
        raise CollectionError("invalid_chunk_limits", Path(extracted))
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    buffer: list[str] = []
    ordinal = offset = start = 0
    line = line_start = line_end = 1
    pending_cr = False
    with _reader(extracted, "kb") as (stream, _):
        while True:
            block = stream.read(READ_SIZE)
            try:
                text = decoder.decode(block, final=not block)
            except UnicodeDecodeError:
                raise CollectionError("invalid_extracted_utf8", Path(extracted)) from None
            for char in text:
                if pending_cr and char != "\n":
                    line += 1
                pending_cr = False
                if buffer and (len(buffer) >= max_chars or line - line_start >= max_lines):
                    yield {"ordinal": ordinal, "line_start": line_start, "line_end": line_end,
                           "char_start": start, "char_end": offset, "text": "".join(buffer)}
                    ordinal += 1
                    start = offset
                    buffer = []
                if not buffer:
                    line_start = line
                buffer.append(char)
                line_end = line
                offset += 1
                if char == "\r":
                    pending_cr = True
                elif char == "\n":
                    line += 1
            if not block:
                break
        if buffer:
            yield {"ordinal": ordinal, "line_start": line_start, "line_end": line_end,
                   "char_start": start, "char_end": offset, "text": "".join(buffer)}
