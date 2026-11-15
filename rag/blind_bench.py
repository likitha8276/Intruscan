
"""
Independent blind benchmark for MITRE ATT&CK retrieval.

These are SOC-style descriptions, deliberately written without
copying MITRE technique names or descriptions.
"""

BLIND_BENCH = [
    {
        "name": "external_port_scanning",
        "query": (
            "One external machine tried connecting to many internal "
            "machines across several different ports."
        ),
        "expected": ("T1046", "T1595"),
    },
    {
        "name": "ssh_login_failures",
        "query": (
            "One source address generated hundreds of unsuccessful "
            "remote login attempts against an SSH server."
        ),
        "expected": ("T1110",),
    },
    {
        "name": "periodic_external_connections",
        "query": (
            "A workstation repeatedly contacted an unfamiliar "
            "external server at regular intervals."
        ),
        "expected": ("T1071", "T1573"),
    },
    {
        "name": "unusual_dns_requests",
        "query": (
            "DNS requests contained unusually long strings of "
            "encoded-looking characters in their domain names."
        ),
        "expected": ("T1071.004",),
    },
    {
        "name": "internal_share_access",
        "query": (
            "One internal computer accessed shared folders on "
            "several other computers."
        ),
        "expected": ("T1135",),
    },
    {
        "name": "remote_desktop_activity",
        "query": (
            "One workstation initiated remote desktop sessions "
            "with several other internal machines."
        ),
        "expected": ("T1021.001",),
    },
    {
        "name": "unusual_destination_port",
        "query": (
            "A computer communicated with an external server "
            "using an unusual destination port."
        ),
        "expected": ("T1571",),
    },
    {
        "name": "outbound_data_transfer",
        "query": (
            "An internal machine transferred unusually large "
            "amounts of data to an external destination."
        ),
        "expected": ("T1041", "T1048"),
    },
    {
        "name": "high_volume_network_traffic",
        "query": (
            "A server received an unusually high volume of "
            "network traffic from multiple external sources."
        ),
        "expected": ("T1498", "T1499"),
    },
    {
        "name": "web_application_exploit",
        "query": (
            "An external request attempted to exploit a weakness "
            "in an internet-facing application."
        ),
        "expected": ("T1190",),
    },
]

from rag.mitre_store import make_index
from rag.bridge import select_hits

def matches_expected(actual_id, expected_ids):
    """Match an exact technique or one of its sub-techniques."""
    return any(
        actual_id == expected
        or actual_id.startswith(expected + ".")
        for expected in expected_ids
    )

def run_benchmark(index):
    top1_correct = 0
    top3_correct = 0
    bridge_correct = 0

    print("\n" + "=" * 75)
    print("INDEPENDENT BLIND SOC RETRIEVAL BENCHMARK")
    print("=" * 75)

    for case in BLIND_BENCH:
        query = case["query"]
        expected = case["expected"]

        results = index.query(query, k=8)
        top3 = results[:3]

        top1_ok = bool(top3) and matches_expected(
            top3[0]["technique_id"], expected
        )

        top3_ok = any(
            matches_expected(hit["technique_id"], expected)
            for hit in top3
        )

        bridge_hits = select_hits(results)
        bridge_ok = any(
            matches_expected(hit["technique_id"], expected)
            for hit in bridge_hits
        )

        top1_correct += int(top1_ok)
        top3_correct += int(top3_ok)
        bridge_correct += int(bridge_ok)

        print(f"\n[{case['name']}]")
        print(f"Query: {query}")
        print(f"Expected: {', '.join(expected)}")

        print("Top 3 retrieved:")
        for hit in top3:
            print(
                f"  {hit['technique_id']:<12} "
                f"{hit['confidence']:.3f}  "
                f"{hit['name']}"
            )

        print(
            "Bridge candidates:",
            [hit["technique_id"] for hit in bridge_hits]
        )

        print(
            f"Results: Top-1={'PASS' if top1_ok else 'MISS'}, "
            f"Top-3={'PASS' if top3_ok else 'MISS'}, "
            f"Bridge={'PASS' if bridge_ok else 'MISS'}"
        )

    total = len(BLIND_BENCH)

    print("\n" + "-" * 75)
    print("FINAL RESULTS")
    print("-" * 75)
    print(f"Top-1:            {top1_correct}/{total}")
    print(f"Top-3:            {top3_correct}/{total}")
    print(f"Bridge selection: {bridge_correct}/{total}")
    print(f"Top-1 rate:       {top1_correct / total * 100:.1f}%")
    print(f"Top-3 rate:       {top3_correct / total * 100:.1f}%")
    print(f"Bridge rate:      {bridge_correct / total * 100:.1f}%")

def main():
    index = make_index("full")
    run_benchmark(index)

if __name__ == "__main__":
    main()