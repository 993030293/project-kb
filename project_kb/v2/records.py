from __future__ import annotations

import json
from pathlib import Path
import stat

from ..runtime import kb_path

from .store import canonical, execute_operation, new_id, now, NotPublished, read_transaction


LINEAGE = """WITH RECURSIVE lineage(id,seq,parent_id) AS (
 SELECT id,seq,parent_id FROM generations WHERE id=? AND state='published'
 UNION SELECT g.id,g.seq,g.parent_id FROM generations g JOIN lineage l ON g.id=l.parent_id
 WHERE g.state='published') """


def published_generation(conn, generation_id=None):
    if generation_id is None:
        row = conn.execute("SELECT value FROM meta WHERE key='published_generation'").fetchone()
        generation_id = row[0] if row else None
    row = conn.execute("SELECT * FROM generations WHERE id=?", (generation_id,)).fetchone()
    if row is None or row["state"] != "published":
        raise NotPublished("The requested generation is not published or has been retired")
    return dict(row)


def storage_stats():
    with read_transaction() as conn:
        generation = published_generation(conn)
        return {"status": "ok", "api_version": 2, "generation": generation["id"],
                'count_scope': 'storage_all_including_unpublished_and_history',
                **{table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                   for table in ("projects", "files", "file_versions", "evidence_occurrences", "text_bodies", "summaries", "relations", "concepts")}}


def evidence_membership(conn, evidence_id, generation, include_history=True):
    sql = LINEAGE + """SELECT m.* FROM evidence_occurrences e
      JOIN file_memberships m ON m.file_version_id=e.file_version_id
      JOIN lineage born ON born.seq=m.valid_from
      WHERE e.id=? AND m.tombstone=0"""
    params = [generation['id'], evidence_id]
    if not include_history:
        sql += ' AND NOT EXISTS(SELECT 1 FROM lineage ended WHERE ended.seq=m.valid_to)'
    return conn.execute(sql + ' ORDER BY m.valid_from DESC LIMIT 1', params).fetchone()


def snapshot_availability(row):
    if row['snapshot_state'] != 'verified_snapshot':
        return 'legacy_extracted_only' if row['snapshot_state'] == 'legacy_extracted_only' else 'not_required'
    try:
        metadata = json.loads(row['source_identity_json'])
        assets = ((row['asset_path'], metadata['raw_bytes']),
                  (metadata['extracted_asset_path'], metadata['extracted_bytes']))
        for path, expected_size in assets:
            info = kb_path(Path(path)).stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != expected_size:
                return 'asset_corrupt'
        return 'available'
    except OSError:
        return 'asset_unavailable'
    except (ValueError, TypeError, KeyError):
        return 'asset_corrupt'


def source_availability(conn, project_id):
    observation = conn.execute('''SELECT state,error_json,updated_at FROM scan_jobs
                                  WHERE project_id=? ORDER BY updated_at DESC,operation_id DESC LIMIT 1''', (project_id,)).fetchone()
    if observation:
        error = json.loads(observation['error_json']) if observation['error_json'] else {}
        if error.get('code') == 'source_unavailable':
            return {'state': 'source_unavailable', 'observed_at': observation['updated_at'], 'basis': 'refresh_observation'}
        if observation['state'] == 'committed':
            return {'state': 'available_at_collection', 'observed_at': observation['updated_at'], 'basis': 'completed_per_file_collection'}
    root = conn.execute('''SELECT state,observed_at FROM project_roots WHERE project_id=?
                           ORDER BY observed_at DESC,id DESC LIMIT 1''', (project_id,)).fetchone()
    state = 'source_unavailable' if root and ('unavailable' in root['state'] or root['state'] == 'user_confirmed_removed') else 'unknown'
    return {'state': state, 'observed_at': root['observed_at'] if root else None, 'basis': 'root_registration_not_live_source_check'}


def evidence_record(evidence_id: str, offset: int = 0, length: int = 4096,
                    generation_id: str | None = None, include_history: bool = True):
    if type(offset) is not int or type(length) is not int or offset < 0 or length < 1 or length > 8192:
        raise ValueError("Use a nonnegative offset and a length from 1 through 8192 characters")
    if type(include_history) is not bool:
        raise ValueError('include_history must be a boolean')
    with read_transaction() as conn:
        generation = published_generation(conn, generation_id)
        membership = evidence_membership(conn, evidence_id, generation, include_history)
        if membership is None:
            return {'status': 'not_found', 'api_version': 2, 'evidence_id': evidence_id,
                    'generation': generation['id'], 'reason': 'not_visible_in_published_scope'}
        row = conn.execute("""SELECT e.file_version_id,e.line_start,e.line_end,e.char_start,e.char_end,
          CASE WHEN instr(b.content,char(0))>0 THEN b.content
          ELSE substr(b.content,?,?) END AS content,instr(b.content,char(0))>0 AS has_nul,
          b.char_length,v.file_id,v.snapshot_state,v.parser_version,v.asset_path,
          json_object('raw_bytes',json_extract(v.source_identity_json,'$.raw_bytes'),
          'extracted_asset_path',json_extract(v.source_identity_json,'$.extracted_asset_path'),
          'extracted_bytes',json_extract(v.source_identity_json,'$.extracted_bytes')) AS source_identity_json,
          json_extract(v.legacy_json,'$.rel_path') AS captured_rel_path,f.project_id
          FROM evidence_occurrences e JOIN text_bodies b ON b.id=e.body_id
          JOIN file_versions v ON v.id=e.file_version_id JOIN files f ON f.id=v.file_id WHERE e.id=?""", (offset + 1, length, evidence_id)).fetchone()
        if row is None:
            return {"status": "not_found", "api_version": 2, "evidence_id": evidence_id}
        availability = snapshot_availability(row)
        if availability in {'asset_unavailable', 'asset_corrupt'}:
            return {'status': availability, 'api_version': 2, 'evidence_id': evidence_id,
                    'generation': generation['id'], 'file_version_id': row['file_version_id'],
                    'reason': 'committed_snapshot_not_available'}
        total = row['char_length']
        if offset > total:
            raise ValueError("Offset exceeds the evidence text length")
        end = min(offset + length, total)
        # SQLite text substring stops at NUL; preserve unusual legacy text exactly.
        content = row['content'][offset:end] if row['has_nul'] else row['content']
        return {"status": "ok", "api_version": 2, "evidence_id": evidence_id,
                "generation": generation['id'], "include_history": include_history,
                "project_id": row["project_id"], "file_id": row["file_id"], "file_version_id": row["file_version_id"],
                "rel_path": membership['rel_path'], "captured_rel_path": row['captured_rel_path'], "parser_version": row["parser_version"],
                "snapshot_state": row["snapshot_state"], 'snapshot_availability': availability,
                "line_start": row["line_start"], "line_end": row["line_end"],
                'char_start': row['char_start'], 'char_end': row['char_end'],
                'location_basis': 'extracted_text' if row['char_start'] is not None else 'legacy_extracted_line_numbers',
                'source_availability': source_availability(conn, row['project_id']),
                "offset": offset, "next_offset": end if end < total else None, "total_chars": total,
                "text": content, "truncated": end < total, "content_status": "unconfirmed"}


def resolve_legacy(snapshot_id: str, reference: str):
    with read_transaction() as conn:
        generation = published_generation(conn)
        row = conn.execute("SELECT evidence_id,status FROM legacy_refs WHERE snapshot_id=? AND reference=?", (snapshot_id, reference)).fetchone()
        if row is None:
            return {"status": "unresolved_reference", "snapshot_id": snapshot_id, "reference": reference}
        if row['evidence_id'] and evidence_membership(conn, row['evidence_id'], generation) is None:
            return {'status': 'unresolved_reference', 'snapshot_id': snapshot_id,
                    'reference': reference, 'resolution_state': 'not_published'}
        return {"status": "ok" if row["evidence_id"] else "unresolved_reference", "snapshot_id": snapshot_id,
                "reference": reference, "evidence_id": row["evidence_id"], "resolution_state": row["status"]}


def append_summary(operation_id: str, target_type: str, target_id: str, summary_type: str, content: str,
                   evidence_ids: list[str] | None = None, record_type: str = "note",
                   summary_family: str | None = None, supersedes_id: int | None = None):
    if record_type not in {"plan", "result", "note"}:
        raise ValueError("Unsupported summary record type")
    if not all(isinstance(value, str) and value for value in (target_type, target_id, summary_type, content)):
        raise ValueError("Summary identity and content fields must be nonempty strings")
    if evidence_ids is not None and not isinstance(evidence_ids, list):
        raise ValueError("Evidence IDs must be a list of nonempty stable-ID strings")
    evidence_ids = tuple(evidence_ids) if evidence_ids is not None else ()
    if not all(isinstance(item, str) and item for item in evidence_ids):
        raise ValueError("Evidence IDs must be a list of nonempty stable-ID strings")
    if summary_family is not None and (type(summary_family) is not str or not summary_family.strip()):
        raise ValueError('summary_family must be None or a nonempty string')
    if supersedes_id is not None and (type(supersedes_id) is not int or not 0 < supersedes_id <= 2**63-1):
        raise ValueError('supersedes_id must be None or a positive integer')
    request = {"target_type": target_type, "target_id": target_id, "summary_type": summary_type,
               "content": content, "evidence_ids": evidence_ids, "record_type": record_type,
               "summary_family": summary_family, "supersedes_id": supersedes_id}

    def write(conn):
        parent = published_generation(conn)
        target_resolution = 'logical_namespace'
        if target_type in {'project', 'concept'}:
            table = 'projects' if target_type == 'project' else 'concepts'
            if conn.execute(f'SELECT 1 FROM {table} WHERE id=?', (target_id,)).fetchone() is None:
                raise ValueError('Typed project/concept targets must be registered; use an explicit workflow namespace for detached notes')
            target_resolution = 'registered'
        if supersedes_id is not None:
            old = conn.execute(LINEAGE + "SELECT s.target_type,s.target_id,s.summary_family FROM summaries s JOIN lineage l ON l.seq=s.created_generation WHERE s.id=?",
                               (parent['id'], supersedes_id)).fetchone()
            if old is None or not summary_family or tuple(old) != (target_type, target_id, summary_family):
                raise ValueError("Supersession requires an explicit matching summary family and target")
        for evidence in evidence_ids:
            if evidence_membership(conn, evidence, parent) is None:
                raise ValueError("Unknown or unpublished evidence ID; resolve published legacy aliases explicitly first")
            version = conn.execute('''SELECT v.* FROM file_versions v JOIN evidence_occurrences e
                                  ON e.file_version_id=v.id WHERE e.id=?''', (evidence,)).fetchone()
            if snapshot_availability(version) in {'asset_unavailable', 'asset_corrupt'}:
                raise ValueError('A cited snapshot is unavailable or corrupt')
        generation, timestamp = new_id(), now()
        seq = conn.execute("SELECT coalesce(max(seq),0)+1 FROM generations").fetchone()[0]
        conn.execute("INSERT INTO generations VALUES(?,?,?,'published',?,?)", (generation, seq, parent["id"], "summary:" + operation_id, timestamp))
        cursor = conn.execute("""INSERT INTO summaries(target_type,target_id,summary_type,content,evidence_ids,created_at,updated_at,
          summary_family,supersedes_id,record_type,applicability,created_generation) VALUES(?,?,?,?,?,?,?,?,?,?,'unclassified',?)""",
                              (target_type, target_id, summary_type, content, canonical(evidence_ids), timestamp, timestamp,
                               summary_family, supersedes_id, record_type, seq))
        summary_id = cursor.lastrowid
        for ordinal, evidence in enumerate(evidence_ids):
            conn.execute("INSERT INTO summary_evidence VALUES(?,?,?,?,?,'resolved_snapshot')", (summary_id, ordinal, canonical(evidence), "stable_evidence_id", evidence))
        conn.execute("UPDATE meta SET value=? WHERE key='published_generation'", (generation,))
        return {"status": "saved", "api_version": 2, "summary_id": summary_id, "generation": generation,
                "operation_id": operation_id, "content_status": "unconfirmed", 'target_resolution': target_resolution}

    return execute_operation("save_summary", operation_id, request, write)
