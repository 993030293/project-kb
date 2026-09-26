"""Install the existing rank backend using a single maintenance deadline."""
import json
import math
import os
from pathlib import Path
import sqlite3
import time

from ..runtime import kb_path, reject_reparse
from ..config import DB_PATH
from . import ranked, store

ATTEMPT = Path(__file__).resolve().parents[3]


class MaintenanceDeadline(TimeoutError):
    def __init__(self, phase):
        super().__init__('Maintenance deadline exceeded: '+phase)
        self.phase = phase


def check_deadline(deadline, phase='during_operation'):
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError('Invalid maintenance deadline')
    if time.monotonic() >= deadline:
        raise MaintenanceDeadline(phase)


def validate_scope(scope):
    if (scope.get('revision') != 'p03b-scope-r1' or scope.get('attempt') != str(ATTEMPT)
            or scope.get('code_root') != str(ATTEMPT / 'code')
            or type(scope.get('plan_summary_id')) is not int or scope['plan_summary_id'] != 238
            or scope.get('real_queries_released') is not False):
        raise PermissionError('Maintenance scope identity differs')
    root = Path(scope['write_root'])
    reject_reparse(root)
    target = kb_path(DB_PATH)
    if (not root.is_absolute() or not root.resolve().is_relative_to(ATTEMPT)
            or not target.is_relative_to(root.resolve()) or target.name != 'kb.sqlite'):
        raise PermissionError('Maintenance target outside admitted scope')
    if scope.get('mode') == 'synthetic_maintenance':
        if scope.get('real_source') is not None or not root.is_relative_to(ATTEMPT / 'tiny'):
            raise PermissionError('Invalid synthetic maintenance scope')
    elif scope.get('mode') == 'source_only_build':
        if scope.get('build_admitted') is not True or target != Path(scope['target_database']):
            raise PermissionError('Unreleased source build target')
    else:
        raise PermissionError('Unsupported maintenance scope')
    return target


def install(operation_id, generation_id, *, deadline):
    check_deadline(deadline, 'before_operation')
    if deadline-time.monotonic() > 900:
        raise ValueError('Maintenance deadline exceeds 900 seconds')
    temp = Path(os.environ['TEMP']).resolve()
    if not temp.is_relative_to(ATTEMPT) or temp.name != 'temp':
        raise PermissionError('Maintenance temporary root differs')
    scope_path = temp.parent / 'scope.json'
    reject_reparse(scope_path)
    if scope_path.stat().st_size > 65536:
        raise ValueError('Oversized maintenance scope')
    scope = json.loads(scope_path.read_text(encoding='utf-8'))
    validate_scope(scope)
    request = {'revision': ranked.REVISION, 'generation_id': generation_id,
               'maintenance_revision': 'p03b-maintenance-r1'}

    def handler(conn):
        # Keep this callback until execute_operation closes the connection after commit.
        conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        check_deadline(deadline)
        result = ranked.install_snapshot(conn, generation_id, lambda: check_deadline(deadline))
        check_deadline(deadline)
        return result

    try:
        result = store.execute_operation('rank_install', operation_id, request, handler,
                                         timeout=min(5.0, max(0.001, deadline-time.monotonic())))
    except sqlite3.OperationalError as exc:
        if time.monotonic() >= deadline and 'interrupted' in str(exc):
            raise MaintenanceDeadline('during_operation_commit_state_requires_readback') from exc
        raise
    check_deadline(deadline, 'after_operation_may_be_committed')
    return result
