"""Isolated, journaled file refresh with immutable assets and generation publication."""

from contextlib import contextmanager
import json
import msvcrt
import os
from pathlib import Path, PurePosixPath
import shutil
import time

import psutil

from ..config import KB_ROOT, IGNORED_DIR_NAMES, MAX_INDEX_FILE_BYTES
from ..config import PRIORITY_FILENAMES, PROJECT_IGNORED_TOP_LEVEL, SAFE_TEXT_EXTENSIONS
from ..runtime import kb_path, source_path, require_sandbox_writes
from ..textutil import is_sensitive_path
from . import collection
from .records import LINEAGE, published_generation, snapshot_availability
from .store import (OperationConflict, StorageError, WriterBusy, body_id, canonical,
                    execute_operation, new_id, now, read_transaction)


class RefreshError(StorageError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def _checkpoint(phase):
    """Tests replace this hook to terminate a process at a declared boundary."""


def _fs(path):
    text = str(path)
    return Path('\\\\?\\' + text) if os.name == 'nt' and not text.startswith('\\\\?\\') else path


def _key(path):
    return path.replace('\\', '/').casefold()


def _budget(start):
    if (psutil.Process().memory_info().rss > 2 * 1024**3
            or psutil.virtual_memory().available < 8 * 1024**3
            or shutil.disk_usage(KB_ROOT).free < 10 * 1024**3
            or time.monotonic() - start > 1800):
        raise RefreshError('resource_budget_exceeded', 'Refresh reached the frozen sandbox resource envelope')


@contextmanager
def scanner_lock():
    require_sandbox_writes()
    path = kb_path(KB_ROOT / 'scanner.lock')
    with path.open('a+b') as stream:
        if os.fstat(stream.fileno()).st_size == 0:
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise WriterBusy('One refresh is already active') from exc
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def register_root(operation_id, project_id, root, name=None):
    root = source_path(Path(root))
    if not isinstance(project_id, str) or not project_id or (name is not None and not isinstance(name, str)):
        raise ValueError('Project ID and optional name must be strings')
    if root.exists() and not root.is_dir():
        raise ValueError('A project root must be a directory')
    request = {'project_id': project_id, 'root': str(root), 'name': name}

    def write(conn):
        timestamp = now()
        if not conn.execute('SELECT 1 FROM projects WHERE id=?', (project_id,)).fetchone():
            conn.execute('INSERT INTO projects(id,name,legacy_json) VALUES(?,?,?)',
                         (project_id, name or project_id, canonical({'registered_by': 'explicit_v2_request'})))
        row = conn.execute("SELECT id FROM project_roots WHERE project_id=? AND host='local' AND path=?",
                           (project_id, str(root))).fetchone()
        root_id = row[0] if row else new_id()
        if row is None:
            conn.execute('INSERT INTO project_roots VALUES(?,?,?,?,?,?,?)',
                         (root_id, project_id, 'local', str(root), 'available' if root.is_dir() else 'source_unavailable',
                          timestamp, 'explicit_v2_request'))
        parent = conn.execute("SELECT value FROM meta WHERE key='published_generation'").fetchone()
        generation, seq = new_id(), conn.execute('SELECT coalesce(max(seq),0)+1 FROM generations').fetchone()[0]
        conn.execute("INSERT INTO generations VALUES(?,?,?,'published',?,?)",
                     (generation, seq, parent[0] if parent else None, 'register_root:' + operation_id, timestamp))
        conn.execute("INSERT INTO meta VALUES('published_generation',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (generation,))
        return {'status': 'registered', 'project_id': project_id, 'root_id': root_id,
                'root': str(root), 'generation': generation, 'operation_id': operation_id}

    return execute_operation('register_root', operation_id, request, write)


def _current(conn, project_id, generation_id, started=None):
    sql = LINEAGE + '''SELECT m.*,v.asset_path,v.source_identity_json,v.parser_version,v.snapshot_state
       FROM file_memberships m JOIN lineage born ON born.seq=m.valid_from
       JOIN file_versions v ON v.id=m.file_version_id JOIN files f ON f.id=m.file_id
       WHERE f.project_id=? AND NOT EXISTS(SELECT 1 FROM lineage ended WHERE ended.seq=m.valid_to)'''
    result = {}
    for row in conn.execute(sql, (generation_id, project_id)):
        if started is not None and len(result) % 256 == 0:
            _budget(started)
        item = dict(row)
        key = _key(item['rel_path'])
        if key in result:
            raise RefreshError('ambiguous_current_path', 'Multiple current identities occupy the same Windows path')
        result[key] = item
    return result


def _eligible(path):
    return path.suffix.lower() in SAFE_TEXT_EXTENSIONS or path.name.lower() in PRIORITY_FILENAMES


def _paths(root, project_id, allowlist):
    def error(exc):
        raise RefreshError('source_unavailable', f'Directory traversal failed: {exc.filename}') from None

    for directory, dirs, files in os.walk(_fs(root), followlinks=False, onerror=error):
        relative_dir = Path(directory).relative_to(_fs(root))
        base = root / relative_dir
        for name in sorted(list(dirs)):
            child = base / name
            rel = child.relative_to(root).as_posix()
            parts = PurePosixPath(rel).parts
            ignored = (any(part.casefold() in IGNORED_DIR_NAMES for part in parts) or
                       parts[0] in PROJECT_IGNORED_TOP_LEVEL.get(project_id, set()))
            sensitive = is_sensitive_path(child)
            if sensitive or (ignored and not any(item.startswith(_key(rel) + '/') for item in allowlist)):
                dirs.remove(name)
                yield rel, None, 'sensitive_path' if sensitive else 'policy_excluded'
                continue
            source_path(child)
        dirs.sort()
        for name in sorted(files):
            path = base / name
            rel = path.relative_to(root).as_posix()
            parts = PurePosixPath(rel).parts
            ignored = (any(part.casefold() in IGNORED_DIR_NAMES for part in parts[:-1]) or
                       parts[0] in PROJECT_IGNORED_TOP_LEVEL.get(project_id, set()))
            if is_sensitive_path(path):
                yield rel, None, 'sensitive_path'
            elif ignored and _key(rel) not in allowlist:
                yield rel, None, 'policy_excluded'
            elif not _eligible(path):
                yield rel, None, 'unsupported_type'
            else:
                yield rel, source_path(path), None


def _read_manifest(directory):
    with kb_path(directory / 'manifest.json').open(encoding='utf-8') as stream:
        return json.load(stream)


def _entries(directory):
    with kb_path(directory / 'entries.jsonl').open(encoding='utf-8') as stream:
        for line in stream:
            yield json.loads(line)


def _action_table(conn):
    revision = conn.execute("SELECT value FROM meta WHERE key='incremental_revision'").fetchone()
    if revision is not None:
        if revision[0] != 'w3-bound-actions-v1':
            raise RefreshError('incremental_schema_mismatch', 'Incremental action schema differs')
        return
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name='scan_actions'").fetchone():
        raise RefreshError('incremental_schema_mismatch', 'An unversioned action table already exists')
    conn.execute('''CREATE TABLE scan_actions(operation_id TEXT NOT NULL REFERENCES scan_jobs(operation_id),
                    ordinal INTEGER NOT NULL CHECK(ordinal>=0), action_json TEXT NOT NULL,
                    PRIMARY KEY(operation_id,ordinal))''')
    for action in ('UPDATE', 'DELETE'):
        conn.execute(f'''CREATE TRIGGER immutable_scan_actions_{action.lower()} BEFORE {action} ON scan_actions
                         BEGIN SELECT RAISE(ABORT,'immutable scan action'); END''')
    conn.execute('''CREATE TRIGGER scan_actions_discovery_only BEFORE INSERT ON scan_actions
                    WHEN NOT EXISTS(SELECT 1 FROM scan_jobs WHERE operation_id=NEW.operation_id AND state='discovered')
                    BEGIN SELECT RAISE(ABORT,'action plan is sealed'); END''')
    conn.execute("INSERT INTO meta VALUES('incremental_revision','w3-bound-actions-v1')")


def _bound_actions(conn, operation_id):
    revision = conn.execute("SELECT value FROM meta WHERE key='incremental_revision'").fetchone()
    if revision is None or revision[0] != 'w3-bound-actions-v1':
        raise RefreshError('prepared_plan_unavailable', 'This prepared job has no compatible immutable action binding')
    for row in conn.execute('SELECT ordinal,action_json FROM scan_actions WHERE operation_id=? ORDER BY ordinal', (operation_id,)):
        yield row['ordinal'], row['action_json']


def _validate_plan(conn, directory, operation_id, metadata):
    sealed = conn.execute('SELECT request_json FROM write_jobs WHERE operation_id=? AND kind=?',
                          ('scan:' + operation_id + ':extracted', 'scan_state')).fetchone()
    if sealed is None or canonical(json.loads(sealed[0])['metadata']) != canonical(metadata):
        raise RefreshError('prepared_plan_conflict', 'The prepared manifest differs from its immutable journal binding')
    count = 0
    with kb_path(directory / 'entries.jsonl').open(encoding='utf-8') as stream:
        for ordinal, expected in _bound_actions(conn, operation_id):
            line = stream.readline(len(expected) + 2)
            try:
                actual = canonical(json.loads(line))
            except (ValueError, TypeError):
                raise RefreshError('prepared_plan_conflict', 'A prepared action is not the journaled canonical action') from None
            if ordinal != count or not line.endswith('\n') or actual != expected:
                raise RefreshError('prepared_plan_conflict', 'The prepared action plan differs from its immutable binding')
            count += 1
        if stream.read(1) or count != metadata['action_count']:
            raise RefreshError('prepared_plan_conflict', 'The prepared action count differs from its immutable binding')


def _validate_owner(conn, item, project_id, parent_id):
    if item['prior_membership'] is None:
        if item['action'] != 'version' or not item['new_file'] or conn.execute('SELECT 1 FROM files WHERE id=?', (item['file_id'],)).fetchone():
            raise RefreshError('prepared_plan_conflict', 'New-file action ownership differs')
        return
    row = conn.execute(LINEAGE + '''SELECT m.* FROM file_memberships m JOIN lineage born ON born.seq=m.valid_from
                        JOIN files f ON f.id=m.file_id WHERE m.id=? AND m.file_id=? AND f.project_id=?
                        AND NOT EXISTS(SELECT 1 FROM lineage ended WHERE ended.seq=m.valid_to)''',
                       (parent_id, item['prior_membership'], item['file_id'], project_id)).fetchone()
    if row is None or (item['action'] != 'version' and row['file_version_id'] != item['version_id']):
        raise RefreshError('prepared_plan_conflict', 'An action does not belong to the bound project and parent membership')


def _write_json(path, value):
    with kb_path(path).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, separators=(',', ':'))
        stream.flush()
        os.fsync(stream.fileno())


def _state(operation_id, state, metadata, error=None):
    def update(conn):
        conn.execute('UPDATE scan_jobs SET state=?,manifest_json=?,error_json=?,updated_at=? WHERE operation_id=?',
                     (state, canonical(metadata), canonical(error) if error else None, now(), operation_id))
        return {'status': state, 'operation_id': operation_id}
    return execute_operation('scan_state', 'scan:' + operation_id + ':' + state,
                             {'metadata': metadata, 'error': error}, update)


def _discover(operation_id, request, metadata, started):
    root = Path(request['root'])
    if not root.is_dir():
        raise RefreshError('source_unavailable', 'The registered source root is unavailable; no tombstones were published')
    root_before = root.stat()
    with read_transaction() as conn:
        old = _current(conn, request['project_id'], metadata['parent_generation'], started)
    directory = kb_path(Path(metadata['staging']))
    directory.mkdir(parents=True, exist_ok=False)
    seen, exclusions, changed = set(), [], []
    metrics = {'scanned_files': 0, 'extracted_files': 0, 'unchanged_files': 0,
               'not_indexed_files': 0, 'renamed_files': 0, 'deleted_files': 0,
               'policy_hidden_files': 0, 'new_versions': 0, 'io_seconds': 0.0, 'extraction_seconds': 0.0}
    with (directory / 'entries.jsonl').open('x', encoding='utf-8', newline='\n') as stream:
        pending, action_count, batch = [], 0, 0

        def flush_actions():
            nonlocal batch
            if not pending:
                return
            actions = list(pending)
            first = action_count - len(actions)

            def bind(conn):
                conn.executemany('INSERT INTO scan_actions VALUES(?,?,?)',
                                 [(operation_id, first + index, value) for index, value in enumerate(actions)])
                return {'bound_actions': len(actions), 'first_ordinal': first}
            execute_operation('scan_actions', 'scan:' + operation_id + ':actions:' + str(batch),
                              {'operation_id': operation_id, 'parent_generation': metadata['parent_generation'],
                               'request': request, 'first_ordinal': first, 'actions': actions}, bind)
            pending.clear()
            batch += 1

        def emit(value):
            nonlocal action_count
            encoded = canonical(value)
            stream.write(encoded + '\n')
            pending.append(encoded)
            action_count += 1
            if len(pending) == 256:
                flush_actions()

        for rel, source, reason in _paths(root, request['project_id'], set(request['receipt_allowlist'])):
            _budget(started)
            key = _key(rel)
            if reason:
                exclusions.append({'path': rel, 'reason': reason})
                continue
            if key in seen:
                raise RefreshError('ambiguous_source_path', 'Case-insensitive duplicate source paths')
            seen.add(key)
            metrics['scanned_files'] += 1
            previous = old.get(key)
            io_start = time.monotonic()
            identity = collection.source_identity(source)
            prior_metadata = json.loads(previous['source_identity_json']) if previous and previous['source_identity_json'] else {}
            can_compare = bool(previous and previous['snapshot_state'] == 'verified_snapshot'
                               and previous['parser_version'] == collection.PARSER_VERSION)
            same = False
            if can_compare:
                availability = snapshot_availability(previous)
                if availability != 'available':
                    raise RefreshError(availability, 'A committed snapshot is unavailable; refresh cannot claim it unchanged')
                raw = kb_path(Path(previous['asset_path']))
                if not raw.is_file():
                    raise RefreshError('asset_unavailable', 'A committed raw snapshot is missing')
                if request['mode'] == 'metadata-fast':
                    prior = prior_metadata.get('identity', {})
                    same = all(identity.get(field) == prior.get(field) for field in ('size', 'mtime_ns'))
                else:
                    same = collection.files_equal(source, raw)
            if previous and previous['snapshot_state'] == 'not_indexed' and identity == prior_metadata.get('identity'):
                same = True
            metrics['io_seconds'] += time.monotonic() - io_start
            if same:
                metrics['unchanged_files'] += 1
                if previous['tombstone']:
                    emit({'action': 'membership', 'file_id': previous['file_id'], 'version_id': previous['file_version_id'],
                          'prior_membership': previous['id'], 'rel_path': rel, 'reason': 'restored'})
                continue
            item = {'action': 'version', 'rel_path': rel, 'file_id': previous['file_id'] if previous else new_id(),
                    'version_id': new_id(), 'prior_membership': previous['id'] if previous else None,
                    'new_file': previous is None, 'metadata': {'identity': identity}, 'snapshot_state': 'not_indexed'}
            if identity['size'] > MAX_INDEX_FILE_BYTES:
                item['reason'] = 'file_too_large'
                metrics['not_indexed_files'] += 1
            else:
                raw, extracted = directory / (item['version_id'] + '.raw'), directory / (item['version_id'] + '.txt')
                extract_start = time.monotonic()
                item['metadata'] = collection.collect_file(source, raw, extracted)
                item['snapshot_state'] = 'verified_snapshot'
                metrics['extraction_seconds'] += time.monotonic() - extract_start
                metrics['extracted_files'] += 1
            changed.append(item)

        protected = {key for key in old if any(key == _key(event['path']) or key.startswith(_key(event['path']) + '/') for event in exclusions)}
        missing = {key: value for key, value in old.items() if key not in seen and key not in protected and not value['tombstone']}
        claimed = set()
        for item in changed:
            candidates, same_identity = [], []
            if item['new_file'] and item['snapshot_state'] == 'verified_snapshot':
                for key, candidate in missing.items():
                    if key in claimed or candidate['snapshot_state'] != 'verified_snapshot' or candidate['parser_version'] != collection.PARSER_VERSION:
                        continue
                    previous_meta = json.loads(candidate['source_identity_json'])
                    prior, current = previous_meta.get('identity', {}), item['metadata']['identity']
                    if prior.get('size') != current['size']:
                        continue
                    _budget(started)
                    if collection.files_equal(root / item['rel_path'], kb_path(Path(candidate['asset_path']))):
                        candidates.append((key, candidate))
                        if all(prior.get(field) == current[field] for field in ('device', 'inode')):
                            same_identity.append((key, candidate))
                if len(same_identity) == 1:
                    key, candidate = same_identity[0]
                    claimed.add(key)
                    metrics['renamed_files'] += 1
                    prior_metadata = json.loads(candidate['source_identity_json'])
                    if all(prior_metadata.get(field) == item['metadata'].get(field) for field in ('parser_version', 'mode', 'source_format')):
                        emit({'action': 'membership', 'file_id': candidate['file_id'], 'version_id': candidate['file_version_id'],
                              'prior_membership': candidate['id'], 'rel_path': item['rel_path'], 'reason': 'verified_rename'})
                        continue
                    item.update(file_id=candidate['file_id'], new_file=False, prior_membership=candidate['id'])
                    candidates = []
                item['candidate_files'] = [candidate['file_id'] for _, candidate in candidates]
            emit(item)
            metrics['new_versions'] += 1
        for key, previous in old.items():
            if previous['tombstone'] or key in claimed or key in seen:
                continue
            reason = 'policy_excluded' if key in protected else 'deleted'
            emit({'action': 'tombstone', 'file_id': previous['file_id'], 'version_id': previous['file_version_id'],
                  'prior_membership': previous['id'], 'rel_path': previous['rel_path'], 'reason': reason})
            metrics['policy_hidden_files' if key in protected else 'deleted_files'] += 1
        flush_actions()
        stream.flush()
        os.fsync(stream.fileno())
    root_after = root.stat()
    if (root_before.st_dev, root_before.st_ino) != (root_after.st_dev, root_after.st_ino):
        raise RefreshError('source_changed', 'The source root identity changed during traversal')
    result = {**metadata, 'metrics': metrics, 'exclusions': exclusions, 'action_count': action_count,
              'content_freshness': 'not_fully_checked' if request['mode'] == 'metadata-fast' else 'fully_checked_eligible',
              'traversal_complete': True, 'observation_model': 'per_file_locked_reads_not_atomic_filesystem_snapshot'}
    _write_json(directory / 'manifest.json', result)
    _checkpoint('after_extraction_files')
    _state(operation_id, 'extracted', result)
    return result


def _publish(operation_id, request, metadata, started):
    staging, assets = Path(metadata['staging']), kb_path(Path(metadata['assets']))
    if staging.exists():
        if assets.exists():
            raise RefreshError('asset_collision', 'Both staging and published asset directories exist')
        assets.parent.mkdir(parents=True, exist_ok=True)
        _checkpoint('before_asset_publication')
        os.rename(staging, assets)
        _checkpoint('after_asset_publication')
    if not assets.is_dir():
        raise RefreshError('asset_unavailable', 'Prepared assets are unavailable')
    if _read_manifest(assets) != metadata:
        raise RefreshError('manifest_conflict', 'The retained manifest differs from the job record')
    with read_transaction() as conn:
        _validate_plan(conn, assets, operation_id, metadata)
        for _, encoded in _bound_actions(conn, operation_id):
            item = json.loads(encoded)
            _budget(started)
            if item['action'] == 'version' and item['snapshot_state'] == 'verified_snapshot':
                collection.verify_snapshot(assets / (item['version_id'] + '.raw'), assets / (item['version_id'] + '.txt'), item['metadata'])
    _state(operation_id, 'assets_published', metadata)
    _checkpoint('before_database_commit')

    def commit(conn):
        database_started = time.monotonic()
        parent = published_generation(conn)
        if parent['id'] != metadata['parent_generation']:
            raise RefreshError('generation_conflict', 'Published generation advanced; preserve this job and use a new operation ID')
        generation, seq, timestamp = new_id(), conn.execute('SELECT max(seq)+1 FROM generations').fetchone()[0], now()
        conn.execute("INSERT INTO generations VALUES(?,?,?,'building',?,?)", (generation, seq, parent['id'], 'refresh:' + operation_id, timestamp))
        occurrences = 0
        _validate_plan(conn, assets, operation_id, metadata)
        for _, encoded in _bound_actions(conn, operation_id):
            item = json.loads(encoded)
            _budget(started)
            _validate_owner(conn, item, request['project_id'], parent['id'])
            if item['prior_membership'] is not None:
                closed = conn.execute('UPDATE file_memberships SET valid_to=? WHERE id=? AND valid_to IS NULL', (seq, item['prior_membership'])).rowcount
                if closed != 1:
                    raise RefreshError('generation_conflict', 'The expected current membership cannot be closed')
            if item['action'] == 'version':
                if item['new_file']:
                    conn.execute('INSERT INTO files(id,project_id) VALUES(?,?)', (item['file_id'], request['project_id']))
                raw = assets / (item['version_id'] + '.raw') if item['snapshot_state'] == 'verified_snapshot' else None
                snapshot_metadata = {**item['metadata'], 'not_indexed_reason': item.get('reason'),
                                     'extracted_asset_path': str(assets / (item['version_id'] + '.txt')) if raw else None,
                                     'extracted_bytes': (assets / (item['version_id'] + '.txt')).stat().st_size if raw else None}
                conn.execute('INSERT INTO file_versions VALUES(?,?,?,?,?,?,?,?)',
                             (item['version_id'], item['file_id'], canonical({'rel_path': item['rel_path']}),
                              collection.PARSER_VERSION, item['snapshot_state'], str(raw) if raw else None,
                              canonical(snapshot_metadata), timestamp))
                if raw:
                    collection.verify_snapshot(raw, Path(snapshot_metadata['extracted_asset_path']), item['metadata'])
                    for chunk in collection.iter_chunks(Path(snapshot_metadata['extracted_asset_path'])):
                        conn.execute('INSERT INTO evidence_occurrences VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                                     (new_id(), item['version_id'], body_id(conn, chunk['text'], collection.PARSER_VERSION),
                                      'extracted_text', chunk['line_start'], chunk['line_end'], chunk['char_start'], chunk['char_end'],
                                      chunk['ordinal'], None, canonical({'location_basis': 'extracted_text'})))
                        occurrences += 1
                for candidate in item.get('candidate_files', []):
                    relation_id = conn.execute('SELECT coalesce(max(id),0)+1 FROM relations').fetchone()[0]
                    conn.execute('INSERT INTO relations VALUES(?,?,?,?,?,?,?,?)',
                                 (relation_id, 'file', item['file_id'], 'file', candidate, 'possible_move',
                                  canonical({'status': 'candidate', 'reason': 'equal_bytes_without_unique_filesystem_identity',
                                             '_kb_v2_created_generation': seq}), 'unreviewed'))
            conn.execute('INSERT INTO file_memberships(file_id,file_version_id,rel_path,valid_from,tombstone) VALUES(?,?,?,?,?)',
                         (item['file_id'], item['version_id'], item['rel_path'], seq, int(item['action'] == 'tombstone')))
        _checkpoint('during_database_commit')
        conn.execute("UPDATE generations SET state='published' WHERE id=?", (generation,))
        conn.execute("UPDATE meta SET value=? WHERE key='published_generation'", (generation,))
        conn.execute("UPDATE scan_jobs SET state='committed',updated_at=? WHERE operation_id=?", (now(), operation_id))
        return {'status': 'refreshed', 'api_version': 2, 'generation': generation, 'operation_id': operation_id,
                'project_id': request['project_id'], 'new_occurrences': occurrences,
                'metrics': metadata['metrics'], 'content_freshness': metadata['content_freshness'],
                'exclusion_count': len(metadata['exclusions']), 'manifest_path': str(assets / 'manifest.json'),
                'database_prepare_seconds': time.monotonic() - database_started,
                'elapsed_before_commit_seconds': time.monotonic() - started,
                'observation_model': metadata['observation_model']}

    result = execute_operation('refresh', operation_id, request, commit)
    _checkpoint('after_database_commit')
    return result


def refresh(operation_id, project_id, root, mode='full', receipt_allowlist=None):
    if not isinstance(operation_id, str) or not operation_id or len(operation_id) > 180:
        raise ValueError('Refresh operation IDs require 1 through 180 characters')
    if mode not in {'full', 'metadata-fast'} or not isinstance(project_id, str) or not project_id:
        raise ValueError('Use a project ID and full or metadata-fast mode')
    allowlist = []
    for item in receipt_allowlist or []:
        if not isinstance(item, str) or not item or '\\' in item or ':' in item:
            raise ValueError('Receipt allowlist entries must be exact relative POSIX paths')
        path = PurePosixPath(item)
        if path.is_absolute() or '..' in path.parts or '*' in item or '?' in item:
            raise ValueError('Receipt allowlist entries must not contain traversal or wildcard syntax')
        allowlist.append(_key(item))
    root = source_path(Path(root))
    request = {'project_id': project_id, 'root': str(root), 'mode': mode, 'receipt_allowlist': sorted(set(allowlist))}
    started = time.monotonic()
    with scanner_lock():
        with read_transaction() as conn:
            old = conn.execute('SELECT kind,request_json,result_json FROM write_jobs WHERE operation_id=?', (operation_id,)).fetchone()
            if old:
                if old['kind'] != 'refresh' or old['request_json'] != canonical(request):
                    raise OperationConflict('Refresh operation ID was already used for a different request')
                return json.loads(old['result_json'])
            job = conn.execute('SELECT * FROM scan_jobs WHERE operation_id=?', (operation_id,)).fetchone()
            job = dict(job) if job else None
        if job:
            metadata = json.loads(job['manifest_json'])
            if metadata['request'] != request:
                raise OperationConflict('Refresh operation ID was already used for a different request')
            if job['state'] not in {'extracted', 'assets_published'}:
                if job['state'] == 'discovered':
                    _state(operation_id, 'failed', metadata, {'code': 'incomplete_discovery', 'message': 'Prior process ended before the traversal was durably sealed'})
                raise RefreshError('incomplete_discovery' if job['state'] == 'discovered' else 'failed_job',
                                   'This retained job cannot resume discovery; use a new operation ID')
        else:
            def begin(conn):
                _action_table(conn)
                if not conn.execute("SELECT 1 FROM project_roots WHERE project_id=? AND host='local' AND path=?", (project_id, str(root))).fetchone():
                    raise ValueError('Register this project root explicitly before refreshing it')
                parent = published_generation(conn)
                identity = new_id()
                metadata = {'request': request, 'parent_generation': parent['id'], 'job_id': identity,
                            'staging': str(kb_path(KB_ROOT / 'vault' / 'staging' / identity)),
                            'assets': str(kb_path(KB_ROOT / 'vault' / 'assets' / identity))}
                timestamp = now()
                conn.execute("INSERT INTO scan_jobs VALUES(?,?,'discovered',?,NULL,?,?)",
                             (operation_id, project_id, canonical(metadata), timestamp, timestamp))
                return metadata
            metadata = execute_operation('scan_begin', 'scan:' + operation_id + ':begin', request, begin)
            _checkpoint('after_discovery')
            try:
                metadata = _discover(operation_id, request, metadata, started)
            except Exception as exc:
                _state(operation_id, 'failed', metadata, {'code': getattr(exc, 'code', 'source_unavailable'), 'message': str(exc)[:512]})
                raise
        try:
            return _publish(operation_id, request, metadata, started)
        except Exception as exc:
            _state(operation_id, 'failed', metadata, {'code': getattr(exc, 'code', 'publication_failed'), 'message': str(exc)[:512]})
            raise
