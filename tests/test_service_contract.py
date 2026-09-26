"""Public compatibility calls must not hide errors or duplicate graph output."""

from contextlib import contextmanager

from project_kb import service


def test_graph_search_returns_one_relations_collection(monkeypatch):
    monkeypatch.setattr(service, "related", lambda query, depth: {
        "status": "ok", "item_id": query, "relations": [{"target_id": "second"}],
    })
    result = service.search("first", mode="graph")
    assert result["results"] == [{"target_id": "second"}]
    assert "relations" not in result


def test_save_summary_does_not_report_failed_write_as_ok(monkeypatch):
    class Connection:
        def execute(self, query):
            return self

        def fetchone(self):
            return None

    @contextmanager
    def reading():
        yield Connection(), {"id": "sample"}

    monkeypatch.setattr(service, "reading", reading)
    monkeypatch.setattr(service.api, "save_summary", lambda *args, **kwargs: {
        "status": "error", "errorcode": "storage_error",
    })
    result = service.save_summary("workflow", "sample", "note", "content")
    assert result == {"status": "error", "errorcode": "storage_error"}
