"""Explicit, rebuildable lexical indexes and generation-bound candidate retrieval."""

from contextlib import contextmanager
import json
import re
import sqlite3
import struct
import unicodedata
import zlib

from . import store
from .records import LINEAGE, published_generation, snapshot_availability


REVISION = 'w4-lexical-v2'
TOKEN_VERSION = 'han12-stream-v2-unicode-' + unicodedata.unidata_version
OFFSET_VERSION = 'zlib-u32le-first-span-v1'
CACHE_CHECK_VERSION = 'source-coverage-offset-structure-v1'
SQL_SECONDS = 60.0
MAX_DOCUMENT_CHARS = 1_000_000
MAX_UNIQUE_TOKENS = 100_000
MAX_STREAM_BYTES = 16_000_000
MAX_NORMALIZED_TERM_CHARS = 512
MIN_SORT_KEY = -8_000_000
SNIPPET_CHARS = 256
_SPAN = struct.Struct('<II')
_INDEXES = {
    'body': ('lex_body_fts', 'text_bodies', 'content'),
    'summary': ('lex_summary_fts', 'summaries', 'content'),
    'path': ('lex_path_fts', 'file_memberships', 'rel_path'),
}
_CAMEL = re.compile(r'[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+')
_KEY_FIELDS = {'revision', 'generation_id', 'query', 'project_id', 'include_history', 'last'}


class LexicalError(store.StorageError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


@contextmanager
def _sql_budget(conn):
    with store.query_budget(conn, SQL_SECONDS) as check:
        yield check


def _text(value, name, maximum=240, optional=False):
    if value is None and optional:
        return
    if (type(value) is not str or not value.strip() or len(value) > maximum
            or any(ord(ch) == 0 or 0xD800 <= ord(ch) <= 0xDFFF for ch in value)):
        raise ValueError(f'{name} must be a nonempty string of at most {maximum} characters')


def _batch_size(value):
    if type(value) is not int or not 1 <= value <= 4096:
        raise ValueError('max_documents must be an integer from 1 through 4096')


def _owned(conn):
    if (not getattr(store._ownership, 'held', False)
            or conn not in getattr(store._ownership, 'connections', ()) or not conn.in_transaction):
        raise LexicalError('writer_required', 'Use the active execute_operation connection and transaction')


def _fts_available(conn):
    return any(row[0] == 'fts5' for row in conn.execute('PRAGMA module_list'))


def _objects():
    result = {'lex_documents', 'lex_doc_identity', 'lex_pending', 'lex_aux_fts', 'membership_version',
              'lex_aux_insert', 'lex_aux_delete'}
    for kind, (index, _, _) in _INDEXES.items():
        result.update((index, 'lex_' + kind + '_insert'))
    return result


def _backend(conn):
    if not _fts_available(conn):
        return 'backend_unavailable'
    metadata = dict(conn.execute("SELECT key,value FROM meta WHERE key IN ('lexical_revision','lexical_token_version','lexical_offset_version')"))
    if (metadata.get('lexical_revision') != REVISION or metadata.get('lexical_token_version') != TOKEN_VERSION
            or metadata.get('lexical_offset_version') != OFFSET_VERSION):
        return 'backend_unavailable'
    names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE name GLOB 'lex_*' OR name='membership_version'")}
    if not _objects() <= names:
        return 'backend_unavailable'
    return 'backend_pending' if conn.execute('SELECT 1 FROM lex_pending LIMIT 1').fetchone() else 'ok'


def _han(ch):
    value = ord(ch)
    return (0x3400 <= value <= 0x4DBF or 0x4E00 <= value <= 0x9FFF
            or 0xF900 <= value <= 0xFAFF or 0x20000 <= value <= 0x323AF)


def _normalize(text):
    # Per-code-point normalization keeps every expansion bound to its source span.
    return ''.join(unicodedata.normalize('NFKC', ch).casefold() for ch in text)


def _segments(text):
    start = 0
    while start < len(text):
        ch = text[start]
        if not (_han(ch) or ch.isalnum() or ch == '_'):
            start += 1
            continue
        chinese = _han(ch)
        end = start + 1
        while end < len(text):
            ch = text[end]
            if _han(ch) != chinese or not (ch.isalnum() or ch == '_' or _han(ch)):
                break
            end += 1
        yield chinese, text[start:end], start, end
        start = end


def _word_parts(text, start):
    for match in re.finditer(r'[^_]+', text):
        word = match.group()
        pieces = list(_CAMEL.finditer(word)) if word.isascii() else []
        if pieces and ''.join(piece.group() for piece in pieces) == word:
            for piece in pieces:
                yield 'w:' + _normalize(piece.group()), start + match.start() + piece.start(), start + match.start() + piece.end()
        else:
            yield 'w:' + _normalize(word), start + match.start(), start + match.end()


def token_spans(text):
    """Yield (token, start, end) in original Python code-point offsets."""
    if type(text) is not str:
        raise ValueError('text must be a string')
    for chinese, segment, start, end in _segments(text):
        if chinese:
            for index, ch in enumerate(segment):
                yield 'c:' + _normalize(ch), start + index, start + index + 1
                if index + 1 < len(segment):
                    yield 'b:' + _normalize(segment[index:index + 2]), start + index, start + index + 2
        else:
            yield 'w:' + _normalize(segment), start, end
            yield from _word_parts(segment, start)


def _encoded_token(token):
    # ASCII hex preserves whole normalized tokens without tokenizer punctuation rules.
    return token[0] + token[2:].encode('utf-8').hex()


def _build_cache(text, check):
    first_spans = {}
    stream_bytes = 0
    for ordinal, (token, start, end) in enumerate(token_spans(text)):
        if ordinal % 512 == 0:
            check()
        if len(token) - 2 > MAX_NORMALIZED_TERM_CHARS:
            continue
        encoded = _encoded_token(token)
        if encoded in first_spans:
            continue
        first_spans[encoded] = (start, end)
        stream_bytes += len(encoded) + 1
        if len(first_spans) > MAX_UNIQUE_TOKENS or stream_bytes > MAX_STREAM_BYTES:
            raise LexicalError('document_budget_exceeded', 'Auxiliary document cache exceeds its explicit budget')
    offsets = bytearray(b'LXO2' + struct.pack('<I', len(first_spans)))
    for span in first_spans.values():
        offsets.extend(_SPAN.pack(*span))
    return ' '.join(first_spans), zlib.compress(offsets, 1), len(first_spans)


def _decode_cache(stream, blob, count, original_chars):
    if (type(stream) is not str or not stream.isascii() or len(stream) > MAX_STREAM_BYTES
            or type(blob) is not bytes or len(blob) > 8 + MAX_UNIQUE_TOKENS * 8 + 1024
            or type(count) is not int or not 0 <= count <= MAX_UNIQUE_TOKENS
            or type(original_chars) is not int or not 0 <= original_chars <= MAX_DOCUMENT_CHARS):
        raise LexicalError('index_corrupt', 'Invalid auxiliary document cache bounds')
    expected = 8 + count * _SPAN.size
    try:
        decoder = zlib.decompressobj()
        raw = decoder.decompress(blob, expected + 1)
    except zlib.error as exc:
        raise LexicalError('index_corrupt', 'Invalid compressed source offset map') from exc
    if (len(raw) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
            or raw[:4] != b'LXO2' or struct.unpack_from('<I', raw, 4)[0] != count):
        raise LexicalError('index_corrupt', 'Invalid source offset map structure')
    tokens = stream.split()
    if len(tokens) != count or len(set(tokens)) != count:
        raise LexicalError('index_corrupt', 'Auxiliary stream and offset map disagree')
    result = {}
    for token, (start, end) in zip(tokens, _SPAN.iter_unpack(raw[8:])):
        if not 0 <= start < end <= original_chars:
            raise LexicalError('index_corrupt', 'Auxiliary source span is outside its document')
        result[token] = (start, end)
    return result


def _cached_spans(conn, kind, doc_id):
    row = conn.execute('''SELECT CASE WHEN length(cast(token_stream AS BLOB))<=? THEN token_stream END,
        CASE WHEN length(offset_map)<=? THEN offset_map END,token_count,original_chars
        FROM lex_documents WHERE kind=? AND doc_id=?''',
        (MAX_STREAM_BYTES, 8 + MAX_UNIQUE_TOKENS * 8 + 1024, kind, doc_id)).fetchone()
    if row is None:
        raise LexicalError('index_corrupt', 'Indexed document cache is missing')
    return _decode_cache(*row)


def _pending(conn):
    return bool(conn.execute('SELECT 1 FROM lex_pending LIMIT 1').fetchone())


def _text_window(conn, kind, doc_id, start, length):
    _, table, column = _INDEXES[kind]
    # SQLite TEXT length/substr stop at NUL. Bound the exceptional full read first.
    row = conn.execute(f'''SELECT CASE WHEN instr({column},char(0))>0
        THEN CASE WHEN length(cast({column} AS BLOB))<=? THEN {column} END
        ELSE substr({column},?,?) END,length({column}),instr({column},char(0))>0
        FROM {table} WHERE id=?''', (MAX_DOCUMENT_CHARS * 4, start + 1, length, doc_id)).fetchone()
    if row is None:
        raise LexicalError('index_corrupt', 'An indexed immutable document is missing')
    text, total, has_nul = row
    if text is None:
        raise LexicalError('document_budget_exceeded', 'NUL-containing text exceeds the bounded fallback')
    if has_nul:
        total = len(text)
        text = text[start:start + length]
    return text, total


def _refresh(conn, max_documents, check):
    documents = conn.execute('SELECT kind,doc_id FROM lex_pending ORDER BY kind,doc_id LIMIT ?', (max_documents,)).fetchall()
    processed = 0
    for kind, doc_id in documents:
        check()
        if kind not in _INDEXES:
            raise LexicalError('index_corrupt', 'Unknown queued document kind')
        text, total = _text_window(conn, kind, doc_id, 0, MAX_DOCUMENT_CHARS + 1)
        if total > MAX_DOCUMENT_CHARS:
            raise LexicalError('document_budget_exceeded', 'Explicit lexical document-size extension is required')
        stream, offsets, token_count = _build_cache(text, check)
        conn.execute('DELETE FROM lex_documents WHERE kind=? AND doc_id=?', (kind, doc_id))
        conn.execute('''INSERT INTO lex_documents(kind,doc_id,token_stream,offset_map,token_count,original_chars)
            VALUES(?,?,?,?,?,?)''', (kind, doc_id, stream, offsets, token_count, total))
        conn.execute('DELETE FROM lex_pending WHERE kind=? AND doc_id=?', (kind, doc_id))
        processed += 1
    return {'status': 'pending' if _pending(conn) else 'ready', 'processed_documents': processed,
            'pending': _pending(conn), 'backend_revision': REVISION, 'token_version': TOKEN_VERSION}


def refresh_indexes(conn, *, max_documents=256):
    """Drain auxiliary work inside the caller's controlled write transaction."""
    _batch_size(max_documents)
    _owned(conn)
    with _sql_budget(conn) as check:
        store.check_schema(conn)
        if _backend(conn) == 'backend_unavailable':
            raise LexicalError('backend_unavailable', 'Install the lexical extension explicitly first')
        return _refresh(conn, max_documents, check)


def maintain_indexes(operation_id, *, max_documents=256):
    _text(operation_id, 'operation_id')
    _batch_size(max_documents)
    return store.execute_operation('lexical_maintain', operation_id,
                                   {'revision': REVISION, 'token_version': TOKEN_VERSION, 'max_documents': max_documents},
                                   lambda conn: refresh_indexes(conn, max_documents=max_documents))


def _cache_integrity(conn, check):
    counts = {}
    maps_validated = 0
    kinds = tuple(_INDEXES)
    for table in ('lex_documents', 'lex_pending'):
        invalid = conn.execute(f'''SELECT 1 FROM {table} WHERE kind IS NULL
            OR kind NOT IN (?,?,?) OR typeof(doc_id)!='integer' LIMIT 1''', kinds).fetchone()
        if invalid:
            raise LexicalError('index_corrupt', 'Unknown auxiliary document kind or invalid source ID')
    for kind, (_, table, column) in _INDEXES.items():
        check()
        source, cached, pending, missing = conn.execute(f'''SELECT count(*),
            coalesce(sum(d.id IS NOT NULL),0),coalesce(sum(p.doc_id IS NOT NULL),0),
            coalesce(sum(d.id IS NULL AND p.doc_id IS NULL),0)
            FROM {table} s
            LEFT JOIN lex_documents d ON d.kind=? AND d.doc_id=s.id
            LEFT JOIN lex_pending p ON p.kind=? AND p.doc_id=s.id''', (kind, kind)).fetchone()
        if missing:
            raise LexicalError('index_corrupt', 'An immutable source has neither cache nor queued work: ' + kind)
        orphan = conn.execute(f'''SELECT 1 FROM lex_pending p
            LEFT JOIN {table} s ON s.id=p.doc_id
            WHERE p.kind=? AND s.id IS NULL LIMIT 1''', (kind,)).fetchone()
        if orphan:
            raise LexicalError('index_corrupt', 'Queued work references a missing immutable source: ' + kind)
        counts[kind] = {'source_documents': source, 'cached_documents': cached, 'pending_documents': pending}
        # Stream one joined cache row at a time; only NUL-containing sources need bounded Python length.
        rows = conn.execute(f'''SELECT s.id,
            CASE WHEN length(cast(d.token_stream AS BLOB))<=? THEN d.token_stream END,
            CASE WHEN length(d.offset_map)<=? THEN d.offset_map END,d.token_count,d.original_chars,
            CASE WHEN instr(s.{column},char(0))=0 THEN length(s.{column}) END,
            CASE WHEN instr(s.{column},char(0))>0 AND length(cast(s.{column} AS BLOB))<=?
                THEN s.{column} END
            FROM lex_documents d LEFT JOIN {table} s ON s.id=d.doc_id
            WHERE d.kind=? ORDER BY d.doc_id''',
            (MAX_STREAM_BYTES, 8 + MAX_UNIQUE_TOKENS * 8 + 1024, MAX_DOCUMENT_CHARS * 4, kind))
        seen = 0
        for source_id, stream, blob, count, original_chars, actual_chars, nul_text in rows:
            check()
            if source_id is None:
                raise LexicalError('index_corrupt', 'An auxiliary cache references a missing immutable source: ' + kind)
            if actual_chars is None and type(nul_text) is str:
                actual_chars = len(nul_text)
            if actual_chars is None or original_chars != actual_chars:
                raise LexicalError('index_corrupt', 'Auxiliary original length differs from its immutable source: ' + kind)
            _decode_cache(stream, blob, count, original_chars)
            check()
            seen += 1
        if seen != cached:
            raise LexicalError('index_corrupt', 'Auxiliary source and cache ownership counts disagree: ' + kind)
        maps_validated += seen
    pending = sum(value['pending_documents'] for value in counts.values())
    return {'auxiliary_cache_integrity': 'ok', 'auxiliary_cache_check_version': CACHE_CHECK_VERSION,
            'auxiliary_cache_coverage': 'complete_or_queued' if pending else 'complete',
            'auxiliary_cache_complete': pending == 0, 'auxiliary_kind_counts': counts,
            'auxiliary_source_documents': sum(value['source_documents'] for value in counts.values()),
            'auxiliary_cached_documents': sum(value['cached_documents'] for value in counts.values()),
            'auxiliary_pending_documents': pending, 'auxiliary_offset_maps_validated': maps_validated,
            'semantic_retokenization_performed': False}


def _integrity(conn, check):
    indexes = [item[0] for item in _INDEXES.values()] + ['lex_aux_fts']
    for index in indexes:
        check()
        conn.execute(f"INSERT INTO {index}({index},rank) VALUES('integrity-check',1)")
    return {'external_content_integrity': 'ok', 'rank': 1, 'indexes': indexes,
            **_cache_integrity(conn, check)}


def check_indexes(conn):
    """Check FTS, source coverage and every cached offset map under writer ownership."""
    _owned(conn)
    with _sql_budget(conn) as check:
        store.check_schema(conn)
        if _backend(conn) == 'backend_unavailable':
            raise LexicalError('backend_unavailable', 'The lexical extension is not installed')
        return {**_integrity(conn, check), 'pending': _pending(conn), 'backend_revision': REVISION}


def _rebuild(conn, check):
    conn.execute("INSERT INTO lex_aux_fts(lex_aux_fts) VALUES('rebuild')")
    conn.execute('DELETE FROM lex_documents')
    conn.execute('DELETE FROM lex_pending')
    for kind, (index, table, _) in _INDEXES.items():
        check()
        conn.execute(f"INSERT INTO {index}({index}) VALUES('rebuild')")
        conn.execute(f'INSERT INTO lex_pending SELECT ?,id FROM {table}', (kind,))
    return {**_refresh(conn, 256, check), **_integrity(conn, check)}


def install_indexes(operation_id):
    _text(operation_id, 'operation_id')

    def install(conn):
        with _sql_budget(conn) as check:
            if not _fts_available(conn):
                raise LexicalError('backend_unavailable', 'SQLite FTS5 is not available; no fallback is installed')
            metadata = conn.execute("SELECT value FROM meta WHERE key='lexical_revision'").fetchone()
            if metadata:
                if _backend(conn) == 'backend_unavailable':
                    raise LexicalError('backend_unavailable', 'Incompatible or incomplete lexical extension; preserve it for explicit repair')
                return {'status': 'already_installed', 'backend_revision': REVISION,
                        'token_version': TOKEN_VERSION, 'pending': _pending(conn)}
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name GLOB 'lex_*' LIMIT 1").fetchone():
                raise LexicalError('backend_unavailable', 'Unversioned lexical objects exist; explicit repair is required')
            conn.execute('CREATE INDEX IF NOT EXISTS membership_version ON file_memberships(file_version_id,valid_from)')
            membership_table = conn.execute("SELECT tbl_name FROM sqlite_master WHERE name='membership_version'").fetchone()
            if (membership_table[0] != 'file_memberships'
                    or [row[2] for row in conn.execute("PRAGMA index_info('membership_version')")] != ['file_version_id', 'valid_from']):
                raise LexicalError('backend_unavailable', 'An incompatible membership_version index must be preserved for explicit repair')
            conn.execute('''CREATE TABLE lex_pending(
                kind TEXT NOT NULL CHECK(kind IN ('body','summary','path')), doc_id INTEGER NOT NULL,
                PRIMARY KEY(kind,doc_id)) WITHOUT ROWID''')
            conn.execute('''CREATE TABLE lex_documents(
                id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('body','summary','path')),
                doc_id INTEGER NOT NULL, token_stream TEXT NOT NULL, offset_map BLOB NOT NULL,
                token_count INTEGER NOT NULL, original_chars INTEGER NOT NULL,
                CHECK(token_count>=0 AND original_chars>=0))''')
            conn.execute('CREATE UNIQUE INDEX lex_doc_identity ON lex_documents(kind,doc_id)')
            conn.execute("""CREATE VIRTUAL TABLE lex_aux_fts USING fts5(token_stream,content='lex_documents',
                content_rowid='id',tokenize='ascii',detail='none',columnsize=0)""")
            conn.execute('''CREATE TRIGGER lex_aux_insert AFTER INSERT ON lex_documents BEGIN
                INSERT INTO lex_aux_fts(rowid,token_stream) VALUES(new.id,new.token_stream); END''')
            conn.execute('''CREATE TRIGGER lex_aux_delete AFTER DELETE ON lex_documents BEGIN
                INSERT INTO lex_aux_fts(lex_aux_fts,rowid,token_stream) VALUES('delete',old.id,old.token_stream); END''')
            for kind, (index, table, column) in _INDEXES.items():
                conn.execute(f"CREATE VIRTUAL TABLE {index} USING fts5({column},content='{table}',content_rowid='id',tokenize='unicode61')")
                conn.execute(f'''CREATE TRIGGER lex_{kind}_insert AFTER INSERT ON {table} BEGIN
                    INSERT INTO {index}(rowid,{column}) VALUES(new.id,new.{column});
                    INSERT INTO lex_pending(kind,doc_id) VALUES('{kind}',new.id);
                    END''')
            conn.execute("INSERT INTO meta VALUES('lexical_revision',?)", (REVISION,))
            conn.execute("INSERT INTO meta VALUES('lexical_token_version',?)", (TOKEN_VERSION,))
            conn.execute("INSERT INTO meta VALUES('lexical_offset_version',?)", (OFFSET_VERSION,))
            return _rebuild(conn, check)

    return store.execute_operation('lexical_install', operation_id,
                                   {'revision': REVISION, 'token_version': TOKEN_VERSION}, install)


def rebuild_indexes(operation_id):
    _text(operation_id, 'operation_id')

    def rebuild(conn):
        with _sql_budget(conn) as check:
            if _backend(conn) == 'backend_unavailable':
                raise LexicalError('backend_unavailable', 'Install a compatible lexical extension before rebuilding')
            return _rebuild(conn, check)

    return store.execute_operation('lexical_rebuild', operation_id,
                                   {'revision': REVISION, 'token_version': TOKEN_VERSION}, rebuild)


def _literal_match(query):
    return '"' + query.replace('"', '""') + '"'


def _aux_query(query):
    weights = {}
    segments = 0

    def add(token, weight):
        if len(token) - 2 > MAX_NORMALIZED_TERM_CHARS:
            raise ValueError('normalized query term exceeds the 512-character budget')
        encoded = _encoded_token(token)
        weights[encoded] = max(weight, weights.get(encoded, 0))

    for chinese, segment, _, _ in _segments(query):
        segments += 1
        if chinese:
            tokens = (['c:' + _normalize(segment)] if len(segment) == 1 else
                      ['b:' + _normalize(segment[pos:pos + 2]) for pos in range(len(segment) - 1)])
            for token in tokens:
                add(token, 1 if len(segment) == 1 else 4)
        else:
            whole = 'w:' + _normalize(segment)
            parts = list(dict.fromkeys(token for token, _, _ in _word_parts(segment, 0)))
            add(whole, 12 if parts and parts != [whole] else 4)
            for token in parts:
                add(token, 4)
    if segments > 64 or len(weights) > 256:
        raise ValueError('query exceeds the 64-segment or 256-term budget')
    return sorted(weights.items())


def _validate_after(after, query, project_id, generation_id, include_history):
    if after is None:
        return generation_id, (MIN_SORT_KEY - 1, 0, '', 0, '')
    if type(after) is not dict or set(after) != _KEY_FIELDS:
        raise ValueError('after must be an exact lexical next_key object')
    _text(after['generation_id'], 'after.generation_id')
    if (type(after['revision']) is not str or after['revision'] != REVISION
            or type(after['query']) is not str or after['query'] != query
            or type(after['project_id']) is not type(project_id) or after['project_id'] != project_id
            or type(after['include_history']) is not bool or after['include_history'] != include_history
            or (generation_id is not None and generation_id != after['generation_id'])):
        raise ValueError('after belongs to a different backend, query, generation, or filter')
    last = after['last']
    if (type(last) not in (list, tuple) or len(last) != 5
            or type(last[0]) is not int or not MIN_SORT_KEY <= last[0] <= 3
            or type(last[1]) is not int or last[1] not in (0, 1)
            or type(last[3]) is not int or not 0 <= last[3] <= 2**63 - 1):
        raise ValueError('after.last is not a valid lexical ordering key')
    _text(last[2], 'after.last identity')
    if (type(last[4]) is not str or len(last[4]) > 240
            or any(ord(ch) == 0 or 0xD800 <= ord(ch) <= 0xDFFF for ch in last[4])):
        raise ValueError('after.last provenance must be a bounded string')
    return after['generation_id'], tuple(last)


def _candidate_sql(include_history):
    # Aggregate postings before fetching document metadata. Paths without any
    # evidence occurrence cannot produce a result in either visibility mode.
    current = '' if include_history else 'AND NOT EXISTS(SELECT 1 FROM lineage ended WHERE ended.seq=m.valid_to)'
    summary_current = '' if include_history else '''AND s.record_type!='legacy_unknown'
        AND NOT EXISTS(SELECT 1 FROM summaries newer JOIN lineage nl ON nl.seq=newer.created_generation
                       WHERE newer.supersedes_id=s.id)'''
    return LINEAGE.replace('id=?', 'id=:generation', 1) + ''',
      query_terms(token,weight) AS (
        SELECT json_extract(value,'$[0]'),json_extract(value,'$[1]') FROM json_each(:terms)),
      aux_weights AS (
        SELECT hit.rowid AS cache_id,sum(q.weight) AS covered_weight
        FROM query_terms q JOIN lex_aux_fts(q.token) hit GROUP BY hit.rowid),
      aux_hits AS (
        SELECT d.kind,d.doc_id,w.covered_weight FROM aux_weights w JOIN lex_documents d ON d.id=w.cache_id
        WHERE d.kind!='path' OR EXISTS(SELECT 1 FROM file_memberships pm JOIN evidence_occurrences pe
            ON pe.file_version_id=pm.file_version_id WHERE pm.id=d.doc_id)),
      hits(kind,doc_id,covered_weight,phrase_match) AS (
        SELECT 'body',rowid,0,1 FROM lex_body_fts WHERE lex_body_fts MATCH :match
        UNION ALL SELECT 'summary',rowid,0,1 FROM lex_summary_fts WHERE lex_summary_fts MATCH :match
        UNION ALL SELECT 'path',rowid,0,1 FROM lex_path_fts WHERE lex_path_fts MATCH :match
        UNION ALL SELECT kind,doc_id,covered_weight,0 FROM aux_hits),
      combined AS (
        SELECT kind,doc_id,sum(covered_weight) AS covered_weight,max(phrase_match) AS phrase_match
        FROM hits GROUP BY kind,doc_id),
      document_matches AS (
        SELECT h.kind,h.doc_id,h.covered_weight,d.token_count,
            (h.phrase_match OR instr(coalesce(b.content,s.content,m.rel_path),:query)>0) AS exact_match
        FROM combined h JOIN lex_documents d ON d.kind=h.kind AND d.doc_id=h.doc_id
        LEFT JOIN text_bodies b ON h.kind='body' AND b.id=h.doc_id
        LEFT JOIN summaries s ON h.kind='summary' AND s.id=h.doc_id
        LEFT JOIN file_memberships m ON h.kind='path' AND m.id=h.doc_id
        WHERE h.kind!='path' OR EXISTS(SELECT 1 FROM evidence_occurrences pe WHERE pe.file_version_id=m.file_version_id)),
      doc_hits AS (
        SELECT kind,doc_id,-4*(exact_match*1000000 + covered_weight*100000/:total_weight
            + 1000/(1+token_count)) + CASE WHEN kind='path' THEN 2 ELSE 0 END
            + CASE WHEN exact_match THEN 0 ELSE 1 END AS sort_rank FROM document_matches),
      visible AS (
        SELECT m.* FROM file_memberships m JOIN lineage born ON born.seq=m.valid_from
        JOIN files f ON f.id=m.file_id WHERE m.tombstone=0
        AND (:project IS NULL OR f.project_id=:project) ''' + current + '''),
      occurrence_hits AS (
        SELECT h.sort_rank,0 AS kind,e.id AS entity_key,m.id AS membership_id,'' AS provenance_key
        FROM doc_hits h JOIN evidence_occurrences e ON h.kind='body' AND e.body_id=h.doc_id
        JOIN visible m ON m.file_version_id=e.file_version_id
        UNION ALL
        SELECT h.sort_rank,0,e.id,m.id,'' FROM doc_hits h JOIN visible m ON h.kind='path' AND m.id=h.doc_id
        JOIN evidence_occurrences e ON e.file_version_id=m.file_version_id),
      summary_hits AS (
        SELECT s.id,s.target_type,s.target_id,h.sort_rank FROM doc_hits h JOIN summaries s ON h.kind='summary' AND s.id=h.doc_id
        JOIN lineage born ON born.seq=s.created_generation WHERE 1=1 ''' + summary_current + '''),
      summary_links AS (
        SELECT s.id,s.sort_rank,m.id AS membership_id,e.id AS provenance_key FROM summary_hits s
        JOIN summary_evidence se ON se.summary_id=s.id AND se.status='resolved_snapshot'
        JOIN evidence_occurrences e ON e.id=se.evidence_id
        JOIN visible m ON m.file_version_id=e.file_version_id),
      candidates AS (
        SELECT min(sort_rank) AS sort_rank,kind,entity_key,membership_id,provenance_key
        FROM occurrence_hits GROUP BY kind,entity_key,membership_id,provenance_key
        UNION ALL SELECT DISTINCT sort_rank,1,cast(id AS TEXT),membership_id,provenance_key FROM summary_links
        UNION ALL SELECT sort_rank,1,cast(id AS TEXT),0,'' FROM summary_hits s
        WHERE NOT EXISTS(SELECT 1 FROM summary_links sl WHERE sl.id=s.id)
        AND (:project IS NULL OR (s.target_type='project' AND s.target_id=:project)))
      SELECT sort_rank,kind,entity_key,membership_id,provenance_key FROM candidates
      WHERE (sort_rank,kind,entity_key,membership_id,provenance_key)>(:last0,:last1,:last2,:last3,:last4)
      ORDER BY sort_rank,kind,entity_key,membership_id,provenance_key LIMIT :page_limit'''


def _snippet(conn, kind, doc_id, hints, cache, *, span_loader=None):
    key = (kind, doc_id)
    if key in cache:
        return cache[key]
    spans = (span_loader or _cached_spans)(conn, kind, doc_id)
    first = min(((-hints[token], spans[token][0]) for token in hints if token in spans), default=(0, 0))[1]
    start = max(0, (first or 0) - 48)
    content, total = _text_window(conn, kind, doc_id, start, SNIPPET_CHARS)
    end = start + len(content)
    result = {'snippet': content, 'snippet_start': start, 'snippet_end': end,
              'snippet_total_chars': total, 'snippet_truncated': start > 0 or end < total,
              'snippet_offset_basis': 'stored_text_codepoints'}
    cache[key] = result
    return result


def _result_row(conn, key, generation_id, hints, snippet_cache, *, native_match=None, span_loader=None):
    sort_rank, kind, identity, membership_id, provenance = key
    tier = sort_rank % 4 if native_match is None else None
    row = {'kind': 'evidence' if kind == 0 else 'summary', 'status': 'unconfirmed',
           'content_status': 'unconfirmed', 'evidence_id': identity if kind == 0 else None,
           'summary_id': int(identity) if kind == 1 else None, 'generation_id': generation_id,
           'project_id': None, 'file_id': None, 'file_version_id': None, 'rel_path': None,
           'membership_id': membership_id or None, 'source_state': 'not_checked',
           'match_tier': (('literal_text', 'normalized_text', 'literal_path', 'normalized_path')[tier]
                          if native_match is None else 'native_bm25_' + native_match),
           'relevance_score': (tier - sort_rank) // 4 if native_match is None else -sort_rank,
           'result_key': list(key), 'provenance_evidence_id': provenance or None}
    evidence = identity if kind == 0 else provenance
    if membership_id:
        metadata = conn.execute(LINEAGE + '''SELECT f.project_id,v.file_id,v.id AS file_version_id,v.snapshot_state,
            v.parser_version,m.rel_path,m.valid_from,
            CASE WHEN EXISTS(SELECT 1 FROM lineage ended WHERE ended.seq=m.valid_to) THEN m.valid_to END AS valid_to,
            e.body_id,e.line_start,e.line_end,e.char_start,e.char_end,
            v.asset_path,CASE WHEN json_valid(v.source_identity_json) THEN json_object(
                'raw_bytes',json_extract(v.source_identity_json,'$.raw_bytes'),
                'extracted_asset_path',json_extract(v.source_identity_json,'$.extracted_asset_path'),
                'extracted_bytes',json_extract(v.source_identity_json,'$.extracted_bytes')) END AS source_identity_json,
            EXISTS(SELECT 1 FROM lineage ended WHERE ended.seq=m.valid_to) AS membership_is_history
            FROM file_memberships m JOIN file_versions v ON v.id=m.file_version_id
            JOIN files f ON f.id=v.file_id JOIN evidence_occurrences e ON e.file_version_id=v.id
            WHERE m.id=? AND e.id=?''', (generation_id, membership_id, evidence)).fetchone()
        row['snapshot_availability'] = snapshot_availability(metadata)
        row.update({name: metadata[name] for name in metadata.keys() if name not in {'asset_path', 'source_identity_json'}})
        row['provenance_state'] = 'published_membership'
    else:
        row['provenance_state'] = 'no_visible_resolved_file_reference'
    unavailable = row.get('snapshot_availability') in {'asset_unavailable', 'asset_corrupt'}
    if unavailable:
        row.update({'status': row['snapshot_availability'], 'snippet': None,
                    'snippet_unavailable_reason': 'committed_snapshot_not_available'})
    if kind == 0 and not unavailable:
        row.update(_snippet(conn, 'body', row['body_id'], hints, snippet_cache, span_loader=span_loader))
    if kind == 1:
        summary = conn.execute(LINEAGE + '''SELECT s.target_type,s.target_id,s.record_type,s.summary_type,s.summary_family,
            s.applicability,s.provenance_review,s.content_status AS stored_content_status,s.created_generation,
            EXISTS(SELECT 1 FROM summaries newer JOIN lineage l ON l.seq=newer.created_generation
                   WHERE newer.supersedes_id=s.id) AS summary_is_superseded
            FROM summaries s WHERE s.id=?''', (generation_id, int(identity))).fetchone()
        row.update(dict(summary))
        if not membership_id and row['target_type'] == 'project':
            row['project_id'] = row['target_id']
        if not unavailable:
            row.update(_snippet(conn, 'summary', int(identity), hints, snippet_cache, span_loader=span_loader))
    return row


def _legacy_search_page(conn, query, *, project_id=None, generation_id=None, include_history=False, after=None, limit=10):
    """Return lexical candidates, never generated answers or confirmed source facts."""
    _text(query, 'query', 256)
    _text(project_id, 'project_id', optional=True)
    _text(generation_id, 'generation_id', optional=True)
    if type(include_history) is not bool:
        raise ValueError('include_history must be a boolean')
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('limit must be an integer from 1 through 100')
    generation_id, last = _validate_after(after, query, project_id, generation_id, include_history)
    terms = _aux_query(query)
    hints = dict(terms)
    with _sql_budget(conn):
        if (not conn.in_transaction or conn.row_factory is not sqlite3.Row
                or conn.execute('PRAGMA query_only').fetchone()[0] != 1):
            raise ValueError('search_page requires a short query_only transaction with sqlite3.Row')
        store.check_schema(conn)
        generation = published_generation(conn, generation_id)
        result = {'status': 'ok', 'rows': [], 'next_key': None, 'generation_id': generation['id'],
                  'include_history': include_history, 'backend_revision': REVISION,
                  'token_version': TOKEN_VERSION, 'claim_boundary': 'unconfirmed_lexical_candidates',
                  'truncated': False}
        status = _backend(conn)
        if status != 'ok':
            return {**result, 'status': status, 'reason': 'explicit_index_maintenance_required'}
        if not terms:
            return {**result, 'status': 'no_match', 'reason': 'query_has_no_indexable_terms'}
        sql = _candidate_sql(include_history)
        params = {'generation': generation['id'], 'match': _literal_match(query), 'project': project_id, 'query': query,
                  'terms': json.dumps(terms, separators=(',', ':')), 'total_weight': sum(weight for _, weight in terms),
                  'page_limit': limit + 1, **{'last' + str(i): value for i, value in enumerate(last)},
                  }
        keys = [tuple(row) for row in conn.execute(sql, params).fetchall()]
        snippet_cache = {}
        result['rows'] = [_result_row(conn, key, generation['id'], hints, snippet_cache) for key in keys[:limit]]
        result['unavailable_candidates'] = sum(row['status'] in {'asset_unavailable', 'asset_corrupt'} for row in result['rows'])
        result['status'] = 'ok' if result['rows'] else 'no_match'
        if len(keys) > limit:
            result['truncated'] = True
            result['next_key'] = {'revision': REVISION, 'generation_id': generation['id'], 'query': query,
                                  'project_id': project_id, 'include_history': include_history, 'last': list(keys[limit - 1])}
        return result


def search_page(conn, query, **kwargs):
    """Use only explicitly published native-rank snapshots in this candidate."""
    from . import ranked
    return ranked.search_page(conn, query, **kwargs)


def index_stats(conn):
    """Report index/auxiliary space separately; do not assert exact-body acceptance."""
    with _sql_budget(conn):
        store.check_schema(conn)
        if (conn.execute("SELECT 1 FROM main.meta WHERE key LIKE 'rank_%'").fetchone()
                or conn.execute("SELECT 1 FROM main.sqlite_master WHERE name='rank_domains'").fetchone()):
            from . import ranked
            return ranked.index_stats(conn)
        status = _backend(conn)
        if status == 'backend_unavailable':
            return {'status': status, 'backend_revision': REVISION}
        result = {'status': status, 'backend_revision': REVISION, 'token_version': TOKEN_VERSION,
                  'offset_version': OFFSET_VERSION,
                  'auxiliary_document_rows': conn.execute('SELECT count(*) FROM lex_documents').fetchone()[0],
                  'auxiliary_token_rows': 0,
                  'auxiliary_unique_tokens': conn.execute('SELECT coalesce(sum(token_count),0) FROM lex_documents').fetchone()[0],
                  'auxiliary_token_utf8_bytes': conn.execute('SELECT coalesce(sum(length(cast(token_stream AS BLOB))),0) FROM lex_documents').fetchone()[0],
                  'auxiliary_offset_compressed_bytes': conn.execute('SELECT coalesce(sum(length(offset_map)),0) FROM lex_documents').fetchone()[0],
                  'auxiliary_fts_data_blob_bytes': conn.execute('SELECT coalesce(sum(length(block)),0) FROM lex_aux_fts_data').fetchone()[0],
                  'original_fts_data_blob_bytes': {index: conn.execute(f'SELECT coalesce(sum(length(block)),0) FROM {index}_data').fetchone()[0]
                                                  for index, _, _ in _INDEXES.values()},
                  'pending_documents': conn.execute('SELECT count(*) FROM lex_pending').fetchone()[0],
                  'exact_body_count_acceptance': 'not_performed'}
        if any(row[0] == 'dbstat' for row in conn.execute('PRAGMA module_list')):
            pages = conn.execute("SELECT name,sum(pgsize) FROM dbstat WHERE name GLOB 'lex_*' OR name='membership_version' GROUP BY name").fetchall()
            result['allocated_bytes_by_object'] = dict(pages)
            result['auxiliary_cache_allocated_bytes'] = sum(size for name, size in pages if name in {'lex_documents', 'lex_doc_identity'})
            result['auxiliary_fts_allocated_bytes'] = sum(size for name, size in pages if name.startswith('lex_aux_fts'))
            result['pending_allocated_bytes'] = sum(size for name, size in pages if name == 'lex_pending')
            result['auxiliary_allocated_bytes'] = (result['auxiliary_cache_allocated_bytes'] + result['auxiliary_fts_allocated_bytes']
                                                   + result['pending_allocated_bytes'])
            result['fts_allocated_bytes'] = sum(size for name, size in pages if any(name.startswith(item[0]) for item in _INDEXES.values()))
            result['membership_lookup_allocated_bytes'] = sum(size for name, size in pages if name == 'membership_version')
        else:
            result['allocated_bytes_by_object'] = None
            result['space_measurement_reason'] = 'dbstat_backend_unavailable'
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='rank_snapshots'").fetchone():
            from . import ranked
            generations = [row[0] for row in conn.execute('SELECT generation_id FROM rank_snapshots ORDER BY generation_id')]
            native = {'snapshot_count': len(generations), 'token_stream_bytes': 0, 'offset_map_bytes': 0,
                      'fts_data_blob_bytes': 0, 'document_rows': 0, 'allocated_bytes': None}
            for generation_id in generations:
                prefix = ranked.snapshot(conn, generation_id)['table_prefix']
                row = conn.execute(f'''SELECT count(*),coalesce(sum(length(cast(token_stream AS BLOB))),0),
                    coalesce(sum(length(offset_map)),0) FROM {prefix}_docs''').fetchone()
                native['document_rows'] += row[0]
                native['token_stream_bytes'] += row[1]
                native['offset_map_bytes'] += row[2]
                native['fts_data_blob_bytes'] += conn.execute(
                    f'SELECT coalesce(sum(length(block)),0) FROM {prefix}_fts_data').fetchone()[0]
            if any(row[0] == 'dbstat' for row in conn.execute('PRAGMA module_list')):
                native['allocated_bytes'] = conn.execute(
                    "SELECT coalesce(sum(pgsize),0) FROM dbstat WHERE name GLOB 'rank_*' OR name GLOB 'sqlite_autoindex_rank_*'").fetchone()[0]
            native['byte_sums_are_allocated_size'] = False
            native['acceptance'] = 'not_evaluated'
            result['native_rank_storage'] = native
        return result
