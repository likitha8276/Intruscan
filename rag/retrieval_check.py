"""Check the MITRE lookup.

  python -m rag.retrieval_check [--mitre full] [--bench]

Default: top matches for each behaviour phrase the bridge uses.
--bench: 14 hand written flow-visible attack behaviours, scored top-1 / top-3 against expected
technique ids (prefix match, so T1110 also accepts T1110.001). Small and hand written: a sanity
benchmark for tuning, not a published accuracy figure.
"""
import argparse
from . import bridge as B
from .bridge import select_hits, NO_LOOKUP
from .event_builder import REL_PHRASE
from .mitre_store import make_index

ALT = {
    "PORT_SCAN": "one source contacting many destination ports or hosts with tiny flows",
    "BRUTE_FORCE_SUSPECTED": "many repeated short connections from one source to a remote login service",
    "EXFIL_SUSPECTED": "internal host sending data out to an external server again and again",
    "DOS_FLOOD_SUSPECTED": "huge volume of packets sent at one web server in milliseconds",
    "ANOMALOUS_FLOW": "nightly backup transferring a large volume between two internal servers",
}
EXPECTED = {"PORT_SCAN": ("T1046", "T1595"), "BRUTE_FORCE_SUSPECTED": ("T1110",),
            "EXFIL_SUSPECTED": ("T1041", "T1048", "T1567", "T1030"),
            "DOS_FLOOD_SUSPECTED": ("T1498", "T1499"), "ANOMALOUS_FLOW": None}

BENCH = [
    ("one host probing many ports on several servers with tiny connections", ("T1046", "T1595")),
    ("repeated failed login attempts against ssh from a single source", ("T1110",)),
    ("internal host sending data out to an external server again and again", ("T1041", "T1048", "T1567", "T1030")),
    ("very large burst of packets flooding a single server to exhaust it", ("T1498", "T1499")),
    ("regular periodic connections from an internal host to an external server like a beacon", ("T1071", "T1573", "T1095", "T1571")),
    ("dns requests with unusually long encoded names sent to one resolver", ("T1071", "T1048", "T1568", "T1572")),
    ("internal host connecting to many other internal hosts over smb file sharing", ("T1021", "T1570", "T1135")),
    ("remote desktop connections from one internal host to many internal hosts", ("T1021",)),
    ("communication with an external address over an uncommon port", ("T1571", "T1095")),
    ("large amount of data sent out in small chunks to stay under alert limits", ("T1030",)),
    ("traffic relayed through a proxy or tunnel to hide the real destination", ("T1090", "T1572")),
    ("many connections from an external address scanning our public services", ("T1595", "T1046")),
    ("exploit attempts sent to a public facing web server", ("T1190",)),
    ("internal host discovering other hosts and shares on the local network", ("T1018", "T1135", "T1046")),
]


def run_bench(index):
    present_ids = set(index.col.get()["ids"])
    t1 = t3 = counted = 0
    for text, exp in BENCH:
        hits = index.query(text, k=3)
        ids = [h["technique_id"] for h in hits]
        in_index = any(i.startswith(exp) for i in present_ids)
        ok1, ok3 = ids[0].startswith(exp), any(i.startswith(exp) for i in ids)
        if in_index:
            counted += 1
            t1 += ok1
            t3 += ok3
        mark = "TOP1" if ok1 else ("TOP3" if ok3 else ("miss" if in_index else "expected id not in this index"))
        print(f"\n[{mark}] {text}\n  expected {'/'.join(exp)}")
        for h in hits:
            print(f"    {h['technique_id']:10s} {h['confidence']:.3f}  {h['name']}")
    print(f"\nbenchmark (only cases whose expected technique is in the index): "
          f"top-1 {t1}/{counted}, top-3 {t3}/{counted}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mitre", choices=["seed", "full"], default="full")
    ap.add_argument("--mitre-scope", choices=["network", "flow", "all"], default="network")
    ap.add_argument("--bench", action="store_true")
    ap.add_argument("--min-conf", type=float, default=B.MIN_CONF)
    ap.add_argument("--gap", type=float, default=B.GAP)
    ap.add_argument("--max-hits", type=int, default=B.MAX_HITS)
    a = ap.parse_args()
    B.MIN_CONF, B.GAP, B.MAX_HITS = a.min_conf, a.gap, a.max_hits
    index = make_index(a.mitre, "chroma_db", a.mitre_scope)
    print(f"index: {a.mitre} ({a.mitre_scope}), {index.col.count()} techniques")
    if a.bench:
        run_bench(index)
        return
    for behavior, phrase in REL_PHRASE.items():
        if behavior in NO_LOOKUP:
            print(f"\n{behavior}: not queried (no concrete behaviour)")
            continue
        for label, text in (("bridge wording", phrase), ("alternative", ALT[behavior])):
            hits = index.query(text, k=8)
            want = EXPECTED[behavior]
            verdict = "  OK" if hits[0]["technique_id"].startswith(want) else f"  WRONG (expected {'/'.join(want)})"
            print(f"\n{behavior} / {label}{verdict}\n  query: {text}")
            for h in hits[:5]:
                print(f"    {h['technique_id']:10s} {h['confidence']:.3f}  {h['name']}")
            shown = [h["technique_id"] + (f" (variant {h['variant'].split()[0]})" if h.get("variant") else "")
                     for h in select_hits(hits)]
            print(f"  bridge would show (min {B.MIN_CONF}, gap {B.GAP}, max {B.MAX_HITS}): {shown or 'nothing'}")


if __name__ == "__main__":
    main()
