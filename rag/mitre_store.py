"""Layer 3a: VectorRAG over MITRE ATT&CK techniques (ChromaDB, cosine, MiniLM).

If you already have a loader built on mitreattack-python, pass its output as
`techniques` (same dict keys). The seed list below is the fallback.
"""

TECHNIQUES = [
    {"id": "T1110", "name": "Brute Force", "tactics": "credential-access",
     "url": "https://attack.mitre.org/techniques/T1110/",
     "action": "Block the source, enforce account lockout, review authentication logs",
     "text": "Adversary makes many repeated login attempts against a remote service such as "
             "SSH, RDP or SMB to guess credentials. Many short connections from one source "
             "to one authentication port."},
    {"id": "T1046", "name": "Network Service Discovery", "tactics": "discovery",
     "url": "https://attack.mitre.org/techniques/T1046/",
     "action": "Rate limit or block the scanning source, check which services responded",
     "text": "Adversary scans hosts and ports to find running services. One source contacts "
             "many destination ports or hosts with tiny flows of one to three packets."},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactics": "exfiltration",
     "url": "https://attack.mitre.org/techniques/T1041/",
     "action": "Isolate the internal host, block the external address, preserve flow records",
     "text": "Stolen data is sent out over the same channel used for command and control. "
             "Repeated low volume encrypted flows from an internal host to one external "
             "address with steady outbound bytes."},
    {"id": "T1071", "name": "Application Layer Protocol", "tactics": "command-and-control",
     "url": "https://attack.mitre.org/techniques/T1071/",
     "action": "Inspect destination reputation, look for periodic beaconing intervals",
     "text": "Command and control traffic hides inside common protocols such as HTTP, HTTPS "
             "or DNS. Periodic beacon like connections from an internal host to an external "
             "server."},
    # T1059 (command interpreter) and T1003 (credential dumping) are host level
    # behaviours; a flow detector will rarely retrieve them. Add them back only if
    # the agent layer expects them.
]


class TechniqueIndex:
    def __init__(self, path="chroma_db", techniques=None):
        import hashlib
        import chromadb
        from chromadb.utils import embedding_functions
        techniques = techniques or TECHNIQUES
        # one collection per technique set, so switching between the small seed list and the
        # full matrix never mixes old and new documents
        key = hashlib.sha1(",".join(sorted(t["id"] for t in techniques)).encode()).hexdigest()[:8]
        self.client = chromadb.PersistentClient(path=path)
        ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        self.col = self.client.get_or_create_collection(
            f"mitre_{key}", embedding_function=ef, metadata={"hnsw:space": "cosine"})
        if self.col.count() != len(techniques):
            for i in range(0, len(techniques), 100):
                batch = techniques[i:i + 100]
                self.col.upsert(
                    ids=[t["id"] for t in batch],
                    documents=[t["text"] for t in batch],
                    metadatas=[{k: t[k] for k in ("name", "tactics", "url", "action")} for t in batch])

    def query(self, text, k=3):
        r = self.col.query(query_texts=[text], n_results=min(k, self.col.count()))
        out = []
        for tid, dist, meta in zip(r["ids"][0], r["distances"][0], r["metadatas"][0]):
            out.append({"technique_id": tid, **meta,
                        "confidence": round(max(0.0, min(1.0, 1.0 - dist)), 3)})
        return out


def make_index(mode="full", path="chroma_db", scope="network"):
    """mode "full" (default): the official ATT&CK Enterprise matrix, filtered by scope (see mitre_loader).
    mode "seed": the 4 hand written techniques, an offline fallback."""
    if mode == "full":
        from .mitre_loader import load_attack_techniques
        return TechniqueIndex(path, load_attack_techniques(scope=scope))
    return TechniqueIndex(path)
