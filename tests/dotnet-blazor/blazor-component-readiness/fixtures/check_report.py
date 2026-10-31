"""Outcome checks for report drafts; no sibling implementation or model is required."""
import hashlib
import json
from pathlib import Path
import sys


def require(condition):
    if not condition:
        raise ValueError("Incomplete, unbound or incorrect assessment draft")


def check(path, kind, manifest="confirmed.json"):
    value = json.loads(Path(path).read_bytes())
    inputs = Path(manifest).read_bytes()
    confirmed = json.loads(inputs)
    count, ids_digest = {
        "package": (60, "1c1d876513c9c16734a94b197f7cc506cfd82c1894f89a93b104dd7ab6a82ec3"),
        "component": (52, "f132fd52e7532ba7b967607619df46c907025062a331a735877701c7509c6a4d"),
    }[kind]
    ids = value["selected_ids"]
    require(len(ids) == count and len(set(ids)) == count and
            hashlib.sha256(json.dumps(ids, separators=(",", ":")).encode()).hexdigest() == ids_digest)
    require(value["schema_version"] == 2 and value["assessment_kind"] == kind and
            value["completion_state"] == "incomplete" and value["overlays"] == [] and
            value["package_reference"] is None)
    require(confirmed["state"] == "confirmed" and confirmed["source"]["availability"] == "unresolved")
    digest = lambda content: {"algorithm": "sha256", "value": hashlib.sha256(content).hexdigest()}
    require(value["identity"]["input_manifest_sha256"] == digest(inputs) and
            value["identity"]["package"]["nupkg_sha256"] == digest(Path("sample.nupkg").read_bytes()))
    require(value["identity"]["component_id"] == ("date-field" if kind == "component" else None))
    require(value["rubric_sha256"]["value"] ==
            "0153ba6982fd1102df9193d3bc2b1957bac1e3478bd0d6cef5a78b0e6daa31cd")
    require(len(value["rows"]) == count and [row["id"] for row in value["rows"]] == ids)
    require(all(row["status"] in (None, "not tested") and row["evidence_ids"] == []
                for row in value["rows"]))


if __name__ == "__main__":
    check(sys.argv[1], sys.argv[2])
