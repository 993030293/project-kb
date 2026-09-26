"""Check compact response contracts without modifying the production store."""

import copy
import inspect
import json

import pytest

from project_kb import retrieval as rt


def row(identity=1, kind="summary"):
    return {"kind": kind, "summary_id": identity if kind == "summary" else None,
            "evidence_id": None if kind == "summary" else str(identity), "membership_id": identity,
            "result_type": "summary" if kind == "summary" else "evidence_chunk",
            "file_version_id": "version", "project_id": "first", "rel_path": "source.md",
            "content_status": "unconfirmed", "provenance_review": "unreviewed",
            "evidence_ids": ["evidence-1"], "snippet": "stored source text", "snippet_start": 12,
            "snippet_end": 30, "line_start": 1, "line_end": 3,
            "result_key": ["internal-rank-metadata"], "summary": "duplicate text"}


def page(rows, generation="generation-1", **kwargs):
    return {"status": "ok", "results": rows, "summary_results": rows, "generation": generation,
            "backend_revision": "native", "truncated": False, "visibility_scope": "current", **kwargs}


def test_compact_preserves_evidence_and_order_without_mutation(monkeypatch):
    value = page([row(2), row(1)])
    before = copy.deepcopy(value)
    calls = []
    monkeypatch.setattr(rt, "search", lambda q, **kw: calls.append(kw) or value)
    result = rt.retrieve("source", "first", 2)
    assert [r["summary_id"] for r in result["results"]] == [2, 1]
    assert result["results"][0]["evidence_ids"] == ["evidence-1"]
    assert result["results"][0]["content_status"] == "unconfirmed"
    assert result["results"][0]["snippet_start"] == 12
    assert "result_key" not in result["results"][0] and "summary_results" not in result
    assert value == before and calls == [{"mode": "fts", "filters": {"project_id": "first"}, "top_k": 2}]


def test_no_hits_stay_local(monkeypatch):
    monkeypatch.setattr(rt, "search", lambda *a, **kw: page([]))
    result = rt.retrieve("source")
    assert result["status"] == "no_match" and result["results"] == []
    assert "expansion" not in result and "queries_used" not in result


def test_backend_error_propagates_unchanged(monkeypatch):
    error = {"status": "error", "errorcode": "backend_unavailable", "results": []}
    monkeypatch.setattr(rt, "search", lambda *a, **kw: error)
    assert rt.retrieve("source") == error


@pytest.mark.parametrize("kwargs", [dict(query=""), dict(query="a" * 257), dict(query="a", top_k=True),
    dict(query="a", top_k=21), dict(query="a", project_id="")])
def test_invalid_arguments(kwargs):
    with pytest.raises(ValueError):
        rt.retrieve(**kwargs)


def test_retrieval_accepts_only_local_search_inputs():
    assert tuple(inspect.signature(rt.retrieve).parameters) == ("query", "project_id", "top_k")


def test_output_budget_keeps_records_whole(monkeypatch):
    rows = [dict(row(i), snippet="x" * 3000) for i in range(20)]
    monkeypatch.setattr(rt, "search", lambda *a, **kw: page(rows))
    value = rt.retrieve("source", top_k=20)
    assert 0 < len(value["results"]) < 20 and value["payload_truncated"]
    assert len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()) <= rt.WIRE_LIMIT
    assert all(r["snippet"] == "x" * 3000 for r in value["results"])
