from mitre_loader import load_attack_techniques

techniques = load_attack_techniques(scope="network")

for tid in ("T1071", "T1190"):
    print("\n" + "=" * 70)
    matches = [t for t in techniques if t["id"].startswith(tid)]
    if not matches:
        print(tid, "NOT FOUND IN INDEX")
    for t in matches:
        print("ID:", t["id"])
        print("NAME:", t["name"])
        print("TACTIC:", t["tactics"])
        print("DOCUMENT:", t["text"])