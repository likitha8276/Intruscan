"""Load the official MITRE ATT&CK Enterprise matrix (STIX JSON) as retrieval documents.

No extra package needed. The first run downloads the public STIX bundle (about 55 MB) from
the mitre-attack/attack-stix-data GitHub repo into ./mitre_cache/ and reuses it afterwards.

Scopes (which techniques go into the vector store):
  all      every active technique and sub-technique
  network  techniques whose official detection strategies use Network Traffic Flow,
           Network Traffic Content or Network Connection Creation data   (default)
  flow     only techniques detectable from Network Traffic Flow data (NetFlow style)

Why filter: most ATT&CK techniques are host level (process, registry, file) and can never be
inferred from flow records, so a flow detector should not retrieve them.
"""
import json
import os
import re
import urllib.request
from collections import defaultdict

URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
       "enterprise-attack/enterprise-attack.json")
SCOPES = {
    "flow": {"Network Traffic Flow"},
    "network": {"Network Traffic Flow", "Network Traffic Content", "Network Connection Creation"},
}
# Brute force is detected from logon logs in MITRE's own mapping, but over the network it shows
# up as many repeated connections to a login port, which is what our heuristic looks for.
ALWAYS_INCLUDE_PREFIXES = ("T1110",)

_CITE = re.compile(r"\(Citation:[^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_TAG = re.compile(r"<[^>]+>")


def _clean(text, limit=700):
    text = _CITE.sub("", text or "")
    text = _LINK.sub(r"\1", text)
    text = _TAG.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _fetch(cache_dir, refresh):
    path = os.path.join(cache_dir, "enterprise-attack.json")
    if refresh or not os.path.exists(path):
        os.makedirs(cache_dir, exist_ok=True)
        print("downloading MITRE ATT&CK enterprise data (about 55 MB, one time)...")
        urllib.request.urlretrieve(URL, path)
    return path


def _attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"], ref.get("url", "")
    return None, ""


def load_attack_techniques(scope="network", cache_dir="mitre_cache", refresh=False, path=None):
    if scope not in ("all", "network", "flow"):
        raise ValueError("scope must be all, network or flow")
    path = path or _fetch(cache_dir, refresh)
    with open(path, encoding="utf-8") as fh:
        objs = json.load(fh)["objects"]
    by_id = {o["id"]: o for o in objs}
    active = {o["id"]: o for o in objs if o["type"] == "attack-pattern"
              and not o.get("revoked") and not o.get("x_mitre_deprecated")}

    allowed = None
    if scope != "all":
        wanted = {o["id"] for o in objs if o["type"] == "x-mitre-data-component"
                  and o["name"] in SCOPES[scope]}
        has_net = {}
        for s in objs:
            if s["type"] != "x-mitre-detection-strategy":
                continue
            has_net[s["id"]] = any(
                ref.get("x_mitre_data_component_ref") in wanted
                for a in s.get("x_mitre_analytic_refs", [])
                for ref in (by_id.get(a, {}).get("x_mitre_log_source_references") or []))
        allowed = {r["target_ref"] for r in objs if r["type"] == "relationship"
                   and r["relationship_type"] == "detects" and has_net.get(r["source_ref"])}
        if not allowed:
            raise ValueError("this ATT&CK file has no detection strategy mapping; use scope='all'")

    parent_of = {r["source_ref"]: r["target_ref"] for r in objs
                 if r["type"] == "relationship" and r["relationship_type"] == "subtechnique-of"}
    mitigations = defaultdict(set)
    for r in objs:
        if r["type"] == "relationship" and r["relationship_type"] == "mitigates":
            src = by_id.get(r["source_ref"], {})
            if src.get("type") == "course-of-action" and not src.get("revoked") \
                    and not src.get("x_mitre_deprecated"):
                mitigations[r["target_ref"]].add(src["name"])

    out = []
    for sid, o in active.items():
        tid, url = _attack_id(o)
        if not tid:
            continue
        if allowed is not None and sid not in allowed and not tid.startswith(ALWAYS_INCLUDE_PREFIXES):
            continue
        parent = parent_of.get(sid)
        name = o["name"]
        if parent in active:
            name = f"{active[parent]['name']}: {name}"
        tactics = ", ".join(p["phase_name"] for p in o.get("kill_chain_phases", [])
                            if p.get("kill_chain_name") == "mitre-attack")
        mit = sorted(mitigations.get(sid) or mitigations.get(parent) or [])[:3]
        out.append({"id": tid, "name": name, "tactics": tactics, "url": url,
                    "action": "MITRE mitigations: " + (", ".join(mit) if mit else "none listed"),
                    "text": f"{name}. Tactic: {tactics}. {_clean(o.get('description'))}"})
    out.sort(key=lambda t: t["id"])
    return out
