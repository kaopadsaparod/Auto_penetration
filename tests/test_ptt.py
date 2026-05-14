"""
Tests for PTT schema and SQLite persistence.
"""
import json
import os
import sys
import tempfile
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.ptt import PentestNode, PTTStore


@pytest.fixture
def ptt():
    """Create a temporary PTTStore for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_ptt.db")
        store = PTTStore(db_path=db_path)
        yield store
        store.close()


class TestPentestNode:
    def test_create_default(self):
        node = PentestNode()
        assert len(node.id) == 12
        assert node.phase == "recon"
        assert node.status == "pending"
        assert node.findings == []
        assert node.tokens_used == 0

    def test_to_dict_serializes_lists(self):
        node = PentestNode(findings=[{"port": 80}])
        d = node.to_dict()
        assert isinstance(d["findings"], str)
        assert json.loads(d["findings"]) == [{"port": 80}]

    def test_from_row_deserializes(self):
        node = PentestNode(findings=[{"port": 80}])
        d = node.to_dict()
        restored = PentestNode.from_row(d)
        assert restored.findings == [{"port": 80}]
        assert restored.id == node.id

    def test_unique_ids(self):
        ids = {PentestNode().id for _ in range(100)}
        assert len(ids) == 100  # All unique


class TestPTTStore:
    def test_save_and_get(self, ptt):
        node = PentestNode(phase="enum", tool_used="nmap")
        ptt.save(node)
        retrieved = ptt.get(node.id)
        assert retrieved is not None
        assert retrieved.phase == "enum"
        assert retrieved.tool_used == "nmap"

    def test_upsert(self, ptt):
        node = PentestNode(status="pending")
        ptt.save(node)
        node.status = "success"
        ptt.save(node)
        retrieved = ptt.get(node.id)
        assert retrieved.status == "success"

    def test_get_nonexistent(self, ptt):
        assert ptt.get("nonexistent") is None

    def test_delete(self, ptt):
        node = PentestNode()
        ptt.save(node)
        assert ptt.delete(node.id) is True
        assert ptt.get(node.id) is None

    def test_get_next_pending_priority(self, ptt):
        # Enum node created first
        enum_node = PentestNode(phase="enum")
        ptt.save(enum_node)
        # Recon node created second but should be returned first
        recon_node = PentestNode(phase="recon")
        ptt.save(recon_node)

        next_node = ptt.get_next_pending()
        assert next_node.phase == "recon"  # Earlier phase wins

    def test_get_next_pending_none_when_empty(self, ptt):
        assert ptt.get_next_pending() is None

    def test_get_next_pending_skips_non_pending(self, ptt):
        node = PentestNode(status="success")
        ptt.save(node)
        assert ptt.get_next_pending() is None

    def test_get_all_by_status(self, ptt):
        ptt.save(PentestNode(status="success"))
        ptt.save(PentestNode(status="success"))
        ptt.save(PentestNode(status="failed"))
        assert len(ptt.get_all_by_status("success")) == 2
        assert len(ptt.get_all_by_status("failed")) == 1

    def test_get_children(self, ptt):
        parent = PentestNode()
        ptt.save(parent)
        child1 = PentestNode(parent_id=parent.id)
        child2 = PentestNode(parent_id=parent.id)
        ptt.save(child1)
        ptt.save(child2)
        children = ptt.get_children(parent.id)
        assert len(children) == 2

    def test_get_total_tokens(self, ptt):
        ptt.save(PentestNode(tokens_used=100))
        ptt.save(PentestNode(tokens_used=200))
        assert ptt.get_total_tokens() == 300

    def test_get_stats(self, ptt):
        ptt.save(PentestNode(status="success", phase="recon"))
        ptt.save(PentestNode(status="pending", phase="enum"))
        stats = ptt.get_stats()
        assert stats["total_nodes"] == 2
        assert stats["success"] == 1
        assert stats["pending"] == 1

    def test_reset(self, ptt):
        ptt.save(PentestNode())
        ptt.save(PentestNode())
        ptt.reset()
        assert ptt.get_stats()["total_nodes"] == 0

    def test_findings_roundtrip(self, ptt):
        """Verify JSON list fields survive save/load."""
        findings = [{"port": 80, "service": "http"}, {"port": 22, "service": "ssh"}]
        node = PentestNode(findings=findings)
        ptt.save(node)
        loaded = ptt.get(node.id)
        assert loaded.findings == findings
