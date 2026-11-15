import sys
import types

from rag.mitre_store import TechniqueIndex


class FakeCollection:
    def __init__(self):
        self.records = {}
        self.upsert_calls = []
        self.deleted = []

    def get(self, include=None):
        return {
            "ids": list(self.records),
            "metadatas": [v["metadata"] for v in self.records.values()],
        }

    def upsert(self, ids, documents, metadatas):
        self.upsert_calls.append(list(ids))
        for tid, doc, meta in zip(ids, documents, metadatas):
            self.records[tid] = {"document": doc, "metadata": meta}

    def delete(self, ids):
        self.deleted.extend(ids)
        for tid in ids:
            self.records.pop(tid, None)

    def count(self):
        return len(self.records)


class FakeClient:
    def __init__(self, collection):
        self.collection = collection

    def get_or_create_collection(self, *args, **kwargs):
        return self.collection


def setup_chroma(monkeypatch, collection):
    chromadb = types.ModuleType("chromadb")
    chromadb.PersistentClient = lambda path: FakeClient(collection)

    utils = types.ModuleType("chromadb.utils")
    utils.__path__ = []

    embedding_functions = types.ModuleType(
        "chromadb.utils.embedding_functions"
    )
    embedding_functions.SentenceTransformerEmbeddingFunction = (
        lambda **kwargs: object()
    )

    monkeypatch.setitem(sys.modules, "chromadb", chromadb)
    monkeypatch.setitem(sys.modules, "chromadb.utils", utils)
    monkeypatch.setitem(
        sys.modules, "chromadb.utils.embedding_functions",
        embedding_functions,
    )


def technique(text="Original description"):
    return {
        "id": "T1110",
        "name": "Brute Force",
        "tactics": "credential-access",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "action": "Review authentication logs",
        "text": text,
    }


def test_changed_content_is_reindexed(monkeypatch, tmp_path):
    collection = FakeCollection()
    setup_chroma(monkeypatch, collection)

    TechniqueIndex(str(tmp_path), [technique()])
    assert collection.records["T1110"]["document"] == "Original description"
    assert len(collection.upsert_calls) == 1

    TechniqueIndex(str(tmp_path), [technique("Updated description")])
    assert collection.records["T1110"]["document"] == "Updated description"
    assert len(collection.upsert_calls) == 2


def test_unchanged_content_is_not_reindexed(monkeypatch, tmp_path):
    collection = FakeCollection()
    setup_chroma(monkeypatch, collection)

    data = [technique()]
    TechniqueIndex(str(tmp_path), data)
    TechniqueIndex(str(tmp_path), data)

    assert len(collection.upsert_calls) == 1


def test_removed_techniques_are_deleted(monkeypatch, tmp_path):
    collection = FakeCollection()
    collection.records["T9999"] = {
        "document": "Obsolete",
        "metadata": {"name": "Obsolete"},
    }
    setup_chroma(monkeypatch, collection)

    TechniqueIndex(str(tmp_path), [technique()])

    assert "T9999" in collection.deleted
    assert "T9999" not in collection.records


def test_empty_technique_list_is_respected(monkeypatch, tmp_path):
    collection = FakeCollection()
    setup_chroma(monkeypatch, collection)

    TechniqueIndex(str(tmp_path), [])

    assert collection.upsert_calls == []
    assert collection.count() == 0
