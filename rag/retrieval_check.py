
"""Check the MITRE lookup.

Usage:
    python -m rag.retrieval_check
    python -m rag.retrieval_check --mitre full --bench
    python -m rag.retrieval_check --mitre full --mitre-scope network --bench

Default:
    Shows top matches for each behavior phrase used by the bridge.

--bench:
    Compares 14 original handwritten behavior queries against
    14 improved retrieval queries.

Metrics:
    Top-1: expected technique appears first.
    Top-3: expected technique appears within the first three.
    Bridge selection: expected technique survives select_hits().

This is a small, handwritten sanity benchmark, not a published
accuracy measurement or production detection metric.
"""

import argparse

from . import bridge as B
from .bridge import select_hits, NO_LOOKUP
from .event_builder import REL_PHRASE
from .mitre_store import make_index


# ---------------------------------------------------------------------
# Original alternative queries used by the bridge diagnostic
# ---------------------------------------------------------------------

ALT = {
    "PORT_SCAN": (
        "one source contacting many destination ports or hosts "
        "with tiny flows"
    ),
    "BRUTE_FORCE_SUSPECTED": (
        "many repeated short connections from one source "
        "to a remote login service"
    ),
    "EXFIL_SUSPECTED": (
        "internal host sending data out to an external server "
        "again and again"
    ),
    "DOS_FLOOD_SUSPECTED": (
        "huge volume of packets sent at one web server in milliseconds"
    ),
    "ANOMALOUS_FLOW": (
        "nightly backup transferring a large volume "
        "between two internal servers"
    ),
}


EXPECTED = {
    "PORT_SCAN": ("T1046", "T1595"),
    "BRUTE_FORCE_SUSPECTED": ("T1110",),
    "EXFIL_SUSPECTED": ("T1041", "T1048", "T1567", "T1030"),
    "DOS_FLOOD_SUSPECTED": ("T1498", "T1499"),
    "ANOMALOUS_FLOW": None,
}


# ---------------------------------------------------------------------
# Original 14-query benchmark
# DO NOT modify these when comparing retrieval improvements.
# ---------------------------------------------------------------------

BENCH = [
    (
        "one host probing many ports on several servers with tiny connections",
        ("T1046", "T1595"),
    ),
    (
        "repeated failed login attempts against ssh from a single source",
        ("T1110",),
    ),
    (
        "internal host sending data out to an external server again and again",
        ("T1041", "T1048", "T1567", "T1030"),
    ),
    (
        "very large burst of packets flooding a single server to exhaust it",
        ("T1498", "T1499"),
    ),
    (
        "regular periodic connections from an internal host to an external server like a beacon",
        ("T1071", "T1573", "T1095", "T1571"),
    ),
    (
        "dns requests with unusually long encoded names sent to one resolver",
        ("T1071", "T1048", "T1568", "T1572"),
    ),
    (
        "internal host connecting to many other internal hosts over smb file sharing",
        ("T1021", "T1570", "T1135"),
    ),
    (
        "remote desktop connections from one internal host to many internal hosts",
        ("T1021",),
    ),
    (
        "communication with an external address over an uncommon port",
        ("T1571", "T1095"),
    ),
    (
        "large amount of data sent out in small chunks to stay under alert limits",
        ("T1030",),
    ),
    (
        "traffic relayed through a proxy or tunnel to hide the real destination",
        ("T1090", "T1572"),
    ),
    (
        "many connections from an external address scanning our public services",
        ("T1595", "T1046"),
    ),
    (
        "exploit attempts sent to a public facing web server",
        ("T1190",),
    ),
    (
        "internal host discovering other hosts and shares on the local network",
        ("T1018", "T1135", "T1046"),
    ),
]


# ---------------------------------------------------------------------
# Improved retrieval queries
# These are experimental. They do not replace the original baseline.
# ---------------------------------------------------------------------

IMPROVED_BENCH = [
    (
        "network service discovery scanning multiple destination ports across multiple hosts",
        ("T1046", "T1595"),
    ),
    (
        "repeated authentication attempts against SSH remote login services to guess passwords",
        ("T1110",),
    ),
    (
        "exfiltration of data from an internal host to an external server over a command and control channel or alternative protocol",
        ("T1041", "T1048", "T1567", "T1030"),
    ),
    (
        "denial of service network flood overwhelming a server with a high volume of packets",
        ("T1498", "T1499"),
    ),
    (
        "command and control beaconing through periodic outbound HTTP HTTPS or DNS connections to a remote server",
        ("T1071", "T1573", "T1095", "T1571"),
    ),
    (
        "DNS tunneling using long encoded DNS query names to communicate with command and control infrastructure or exfiltrate data",
        ("T1071", "T1048", "T1568", "T1572"),
    ),
    (
        "SMB remote services and Windows administrative shares used for lateral movement between internal hosts",
        ("T1021", "T1570", "T1135"),
    ),
    (
        "Remote Desktop Protocol RDP connections used to access other internal systems through remote services",
        ("T1021",),
    ),
    (
        "network communication using a non-standard uncommon destination port instead of the standard application protocol port",
        ("T1571", "T1095"),
    ),
    (
        "data exfiltration by splitting large transfers into smaller chunks to evade transfer size limits",
        ("T1030",),
    ),
    (
        "adversary relaying network traffic through a multi-hop proxy or tunnel to hide the original destination",
        ("T1090", "T1572"),
    ),
    (
        "external adversary actively scanning public IP address blocks and exposed network services",
        ("T1595", "T1046"),
    ),
    (
        "exploiting a vulnerability in an internet-facing public-facing web application or server to gain initial access",
        ("T1190",),
    ),
    (
        "remote system discovery and network share discovery by enumerating internal hosts and SMB shares",
        ("T1018", "T1135", "T1046"),
    ),
]


# ---------------------------------------------------------------------
# Technique ID matching
# Exact parent match or exact sub-technique prefix.
# Example: T1110 accepts T1110.001 but not T11100.
# ---------------------------------------------------------------------

def matches_expected(actual, expected):
    return any(
        actual == technique
        or actual.startswith(technique + ".")
        for technique in expected
    )


# ---------------------------------------------------------------------
# Benchmark evaluation
# ---------------------------------------------------------------------

def evaluate_set(index, cases, label):
    present_ids = set(index.col.get()["ids"])

    top1 = 0
    top3 = 0
    bridge_hits = 0
    counted = 0

    print("\n" + "=" * 75)
    print(label)
    print("=" * 75)

    for text, expected in cases:

        # Check whether at least one expected technique is available.
        available = any(
            matches_expected(tid, expected)
            for tid in present_ids
        )

        # Raw vector retrieval: top 3.
        hits = index.query(text, k=3)
        ids = [hit["technique_id"] for hit in hits]

        ok1 = bool(ids) and matches_expected(ids[0], expected)

        ok3 = any(
            matches_expected(tid, expected)
            for tid in ids
        )

        # Actual bridge candidate selection: top 8 followed by filtering.
        full_hits = index.query(text, k=8)
        selected = select_hits(full_hits)

        selected_ids = [
            hit["technique_id"]
            for hit in selected
        ]

        bridge_ok = any(
            matches_expected(tid, expected)
            for tid in selected_ids
        )

        # Count only cases whose expected technique exists in the index.
        if available:
            counted += 1
            top1 += int(ok1)
            top3 += int(ok3)
            bridge_hits += int(bridge_ok)

        if not available:
            mark = "NOT IN INDEX"
        elif ok1:
            mark = "TOP1"
        elif ok3:
            mark = "TOP3"
        else:
            mark = "MISS"

        print(f"\n[{mark}] {text}")
        print("  Expected:", "/".join(expected))

        print("  Retrieved top 3:")
        for hit in hits:
            print(
                f"    {hit['technique_id']:10s} "
                f"{hit['confidence']:.3f}  "
                f"{hit['name']}"
            )

        print("  Bridge candidates:", selected_ids or "nothing")

    print("\n" + "-" * 75)
    print(label + " RESULTS")
    print("-" * 75)

    print(f"Eligible cases:      {counted}")
    print(f"Top-1:               {top1}/{counted}")
    print(f"Top-3:               {top3}/{counted}")
    print(f"Bridge selection:    {bridge_hits}/{counted}")

    if counted:
        print(f"Top-1 percentage:    {top1 / counted * 100:.1f}%")
        print(f"Top-3 percentage:    {top3 / counted * 100:.1f}%")
        print(f"Bridge percentage:   {bridge_hits / counted * 100:.1f}%")


def run_bench(index):
    evaluate_set(index, BENCH, "ORIGINAL QUERIES")
    evaluate_set(index, IMPROVED_BENCH, "IMPROVED QUERIES")


# ---------------------------------------------------------------------
# Default bridge wording diagnostic
# ---------------------------------------------------------------------

def run_behavior_check():
    for behavior, phrase in REL_PHRASE.items():

        if behavior in NO_LOOKUP:
            print(
                f"\n{behavior}: not queried "
                "(no concrete behaviour)"
            )
            continue

        alternatives = (
            ("bridge wording", phrase),
            ("alternative", ALT[behavior]),
        )

        expected = EXPECTED[behavior]

        for label, text in alternatives:

            hits = index.query(text, k=8)

            if not hits:
                print(f"\n{behavior} / {label}: no results")
                continue

            if expected and matches_expected(
                hits[0]["technique_id"], expected
            ):
                verdict = "OK"
            elif expected:
                verdict = (
                    "WRONG (expected "
                    + "/".join(expected)
                    + ")"
                )
            else:
                verdict = "NO EXPECTED TECHNIQUE"

            print(
                f"\n{behavior} / {label} [{verdict}]"
                f"\n  query: {text}"
            )

            for hit in hits[:5]:
                print(
                    f"    {hit['technique_id']:10s} "
                    f"{hit['confidence']:.3f}  "
                    f"{hit['name']}"
                )

            shown = [
                hit["technique_id"]
                + (
                    f" (variant {hit['variant'].split()[0]})"
                    if hit.get("variant")
                    else ""
                )
                for hit in select_hits(hits)
            ]

            print(
                f"  bridge would show "
                f"(min {B.MIN_CONF}, gap {B.GAP}, "
                f"max {B.MAX_HITS}): "
                f"{shown or 'nothing'}"
            )


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    global index

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--mitre",
        choices=["seed", "full"],
        default="full",
    )

    parser.add_argument(
        "--mitre-scope",
        choices=["network", "flow", "all"],
        default="network",
    )

    parser.add_argument(
        "--bench",
        action="store_true",
    )

    parser.add_argument(
        "--min-conf",
        type=float,
        default=B.MIN_CONF,
    )

    parser.add_argument(
        "--gap",
        type=float,
        default=B.GAP,
    )

    parser.add_argument(
        "--max-hits",
        type=int,
        default=B.MAX_HITS,
    )

    args = parser.parse_args()

    # Apply selection settings for bridge evaluation.
    B.MIN_CONF = args.min_conf
    B.GAP = args.gap
    B.MAX_HITS = args.max_hits

    # Create or load the selected MITRE index.
    index = make_index(
        args.mitre,
        "chroma_db",
        args.mitre_scope,
    )

    print(
        f"index: {args.mitre} ({args.mitre_scope}), "
        f"{index.col.count()} techniques"
    )

    if args.bench:
        run_bench(index)
        return

    run_behavior_check()


if __name__ == "__main__":
    main()
