"""Reviewed, fail-closed report mapping for the eleven offline package resolvers."""
import hashlib
import json
import re
import unicodedata

VERSION = "eleven-row-handoff/2.0.0"
ROWS = tuple(f"LP-{number:02}" for number in range(1, 11)) + ("PI-01",)
RESOLVERS = dict(zip(ROWS, (
    "lp01-license-policy", "lp02-public-source", "lp03-dependency-licenses",
    "lp04-notice-coverage", "lp05-license-expression", "lp06-repository-url",
    "lp07-repository-commit", "lp08-authors", "lp09-project-url",
    "lp10-binary-attribution", "pi01-strong-name",
)))
STATUSES = {"V": "verified", "G": "gap", "N": "not tested",
            "O": "owner evidence required", "A": "not applicable"}
RESOLVER_VERSIONS = {row: "2.0.0" if row == "LP-04" else "1.2.0" if row == "LP-03" else
                     "1.1.0" if row in ("LP-01", "LP-02", "PI-01") else "1.0.0" for row in ROWS}

# Each entry is (explicit branches, status, smallest next action). Unknown keys are errors.
GROUPS = {
    "LP-01": (
        ("owner-evidence-accepted", "V", ""),
        ("approved-non-copyleft", "V", ""),
        ("copyleft weak-copyleft non-osi", "G", "Correct the authoritative offered license or grant."),
        ("file-declared file-unverified missing-license", "O",
         "Supply the owner-authorized complete repository and release-scoped license grant."),
        ("owner-acceptance-missing", "O", "Supply explicit acceptance of owner-authority prevalidation."),
        ("owner-record-conflict grant-contradiction conflicting-declarations", "O",
         "Supply authoritative owner reconciliation of the conflicting license or identity claims."),
        ("mixed-alternatives", "O", "Supply a binding owner license choice and applicable grant."),
        ("owner-record-invalid owner-binding-conflict grant-binding-conflict", "N",
         "Re-admit the actual record and grant with supported schemas and exact checked bindings."),
        ("grant-missing grant-incomplete", "N",
         "Obtain complete grant bytes and the required applicability and prevalidation record."),
        ("grant-limit", "N", "Obtain supported bounded complete-grant evidence without truncation."),
        ("unclassified-osi custom-license exception-unreviewed", "N",
         "Obtain supported reviewed license or exception classification under the frozen policy."),
        ("unknown-license deprecated-license invalid-expression expression-limit unsafe-metadata", "N",
         "Obtain an unambiguous supported license declaration, classification and applicable grant."),
        ("unsafe-package missing-package", "N", "Obtain exact safely inspectable package bytes."),
        ("missing-policy missing-corpus invalid-policy", "N", "Restore the exact bundled frozen policy and catalog."),
    ),
    "LP-02": (
        ("public-source-observed", "V", ""),
        ("missing-package package-unreadable", "N", "Obtain safely inspectable exact package bytes."),
        ("source-declaration-missing public-retrieval-unresolved", "N",
         "Obtain a supported exact repository and revision declaration and admitted anonymous retrieval."),
        ("observation-missing observation-invalid observation-binding-conflict", "N",
         "Obtain an admitted anonymous capture bound to the exact package, revision and retained archive."),
        ("source-relevance-unestablished", "N", "Repair the missing selected supplemental source-file binding."),
    ),
    "LP-03": (
        ("dependencies-policy-satisfied", "V", ""),
        ("incompatible-dependency-license", "G", "Correct the incompatible exact dependency declaration or version."),
        ("missing-package scope-missing", "N", "Obtain the exact root and supported release-wide SBOM assessment binding."),
        ("input-invalid binding-conflict", "N", "Repair admission and identity bindings using actual retained evidence."),
        ("policy-unavailable", "N", "Restore the exact frozen policy and catalog."),
        ("evidence-missing closure-unresolved", "N",
         "Obtain a supported raw release SBOM with a bound caller authoritative release-wide designation."),
        ("dependency-bytes-missing", "N", "Obtain the exact inventoried dependency package."),
        ("license-evidence-unresolved", "N", "Obtain unambiguous supported exact-package license declaration evidence."),
    ),
    "LP-04": (
        ("missing-package", "N", "Obtain the exact assessed package bytes for a bounded web-asset scan."),
        ("input-invalid", "N", "Obtain a complete safely inspectable package within the supported bounds."),
        ("legacy-protocol", "N", "Remove retired v1 packet roles and rerun the package-only inventory."),
        ("surface-unsupported", "N", "Assess the listed unsupported representations separately to establish their origin and notice obligations."),
        ("no-supported-layout-assets", "N", "Establish whether the requirement applies by assessing other representations or obtaining explicit applicability evidence."),
        ("origin-review-missing", "N", "Review the retained assets to establish origin and any resulting notice obligations."),
    ),
    "LP-05": (
        ("expression", "V", ""),
        ("missing-expression file", "G", "Populate PackageLicenseExpression in the exact package."),
        ("foreign-license ambiguous malformed unsupported-version", "N", "Obtain unambiguous supported NuGet license metadata."),
    ),
    "LP-06": (
        ("populated", "V", ""),
        ("missing-repository missing-url blank-url", "G", "Populate RepositoryUrl in the exact package."),
        ("foreign-repository ambiguous unsupported-attribute", "N", "Obtain unambiguous supported NuGet repository metadata."),
    ),
    "LP-07": (
        ("full-sha1 full-sha256", "V", ""),
        ("missing-repository missing-commit blank-commit invalid-characters null-oid abbreviated-commit invalid-length",
         "G", "Declare the full nonzero commit SHA in RepositoryCommit."),
        ("foreign-repository ambiguous unsupported-attribute", "N", "Obtain unambiguous supported NuGet commit metadata."),
    ),
    "LP-08": (
        ("populated", "V", ""),
        ("missing-authors blank-authors delimiter-only", "G", "Populate Authors with an actual author entry."),
        ("foreign-authors ambiguous malformed-authors", "N", "Obtain unambiguous supported NuGet authors metadata."),
    ),
    "LP-09": (
        ("populated", "V", ""),
        ("missing-project-url blank-project-url", "G", "Populate ProjectUrl in the exact package."),
        ("case-variant-project-url foreign-project-url ambiguous malformed-project-url", "N",
         "Obtain exact-case unambiguous supported NuGet projectUrl metadata."),
    ),
    "LP-10": (
        ("no-code-payload", "V", ""),
        ("missing-package unreadable-package unsafe-archive ambiguous-nuspec missing-nuspec missing-root-nuspec "
         "unsafe-nuspec invalid-xml foreign-root invalid-metadata ambiguous-metadata incomplete-inventory", "N",
         "Obtain a complete safely inspectable exact package inventory."),
        ("unsupported-executable-content", "N", "Obtain supported safe classification and per-entry attribution."),
        ("compiled-attribution-unverified", "N",
         "Obtain per-entry ownership and public release-commit build or referenced-upstream byte mappings."),
        ("text-code-attribution-unverified", "N",
         "Obtain per-entry ownership and exact public-commit blob, verified transform or upstream byte mappings."),
        ("mixed-code-attribution-unverified", "N", "Obtain both compiled-build and executable-text per-entry attribution maps."),
    ),
    "PI-01": (
        ("verified-signed no-assemblies", "V", ""),
        ("unsigned-assembly delay-signed public-signed invalid-signature", "G",
         "Correct strong-name signing of the identified shipped assembly and repeat cryptographic verification."),
        ("missing-package unsafe-package unsafe-assembly opaque-container", "N",
         "Obtain complete safely inspectable package, PE and nested-container evidence."),
        ("signature-unverified", "N", "Obtain supported algorithm and key evidence or independent cryptographic verification."),
    ),
}
COMMON_METADATA = (
    "missing-package ambiguous-nuspec missing-nuspec missing-root-nuspec unsafe-nuspec "
    "ambiguous-metadata invalid-xml foreign-root unreadable-package"
)


def mapping():
    result = {}
    for row, groups in GROUPS.items():
        if row in ROWS[4:9]:
            groups += ((COMMON_METADATA, "N", "Obtain safely inspectable exact package bytes with unique recognized metadata."),)
        for branches, status, action in groups:
            for branch in branches.split():
                key = (row, branch)
                if key in result:
                    raise ValueError(f"Duplicate mapping: {key}")
                result[key] = (status, action)
    if len(result) != 171:
        raise ValueError("The reviewed mapping must contain exactly 171 row/branch pairs.")
    return result


MAPPING = mapping()
FIELDS = {"row_id", "resolver_id", "resolver_version", "branch_id", "decision", "applicability",
          "inputs", "evidence_references", "evidence_contract", "finding", "missing_fact",
          "required_input", "next_category"}


def checked_result(value, pins):
    if not isinstance(value, dict) or set(value) not in (FIELDS, FIELDS | {"bundled_web_assets"}):
        raise ValueError("Unexpected resolver result fields.")
    row, branch = value["row_id"], value["branch_id"]
    if ((row, branch) not in MAPPING or value["resolver_id"] != RESOLVERS[row] or
            value["resolver_version"] != RESOLVER_VERSIONS[row] or value["inputs"] != pins):
        raise ValueError("Unknown resolver branch, version or input binding.")
    code = MAPPING[row, branch][0]
    decision = "deterministic" if code in "VGA" else "escalated"
    if value["decision"] != decision or value["applicability"] not in ("applicable", "unknown", "not-applicable"):
        raise ValueError("Resolver decision contradicts the reviewed branch mapping.")
    if ((code == "A") != (value["applicability"] == "not-applicable") or
            decision == "deterministic" and value["applicability"] == "unknown"):
        raise ValueError("Resolver applicability contradicts the reviewed branch mapping.")
    text = value["finding"] if decision == "deterministic" else value["missing_fact"]
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Resolver omitted the deciding finding or missing fact.")
    if decision == "deterministic":
        if any(value[key] is not None for key in ("missing_fact", "required_input", "next_category")):
            raise ValueError("A deterministic finding has unresolved fields.")
    elif (value["finding"] is not None or not value["required_input"] or not value["next_category"]):
        raise ValueError("An escalation lacks its exact input and routing boundary.")
    references = value["evidence_references"]
    if (not isinstance(references, list) or not all(isinstance(item, str) and item for item in references) or
            len(set(references)) != len(references) or
            decision == "deterministic" and not references and not value["evidence_contract"]):
        raise ValueError("Resolver evidence contract is missing or malformed.")
    surface_branch = row == "LP-04" and branch in (
        "surface-unsupported", "no-supported-layout-assets", "origin-review-missing")
    if ("bundled_web_assets" in value) != surface_branch:
        raise ValueError("Unexpected or missing LP-04 bounded inventory.")
    if surface_branch:
        checked_web_assets(value["bundled_web_assets"], branch)
    return value


def checked_web_assets(inventory, branch):
    if (not isinstance(inventory, dict) or set(inventory) != {
            "profile", "assets", "unsupported_candidates", "inventory_sha256"} or
            inventory["profile"] != "bundled-web-assets/1"):
        raise ValueError("Unsupported LP-04 inventory profile.")
    assets, unsupported = inventory["assets"], inventory["unsupported_candidates"]
    if not isinstance(assets, list) or len(assets) > 512 or not isinstance(unsupported, list) or len(unsupported) > 4096:
        raise ValueError("LP-04 inventory exceeds its bounded profile.")
    paths, canonical, total = [], "bundled-web-assets/1\n", 0
    for asset in assets:
        if (not isinstance(asset, dict) or set(asset) != {"path", "length", "sha256"} or
                not isinstance(asset["path"], str) or not asset["path"] or
                any(ord(ch) < 32 or ord(ch) == 127 for ch in asset["path"]) or
                type(asset["length"]) is not int or not 0 <= asset["length"] <= 64 * 1024 * 1024 or
                not isinstance(asset["sha256"], str) or not re.fullmatch("[a-f0-9]{64}", asset["sha256"])):
            raise ValueError("Malformed LP-04 asset evidence.")
        paths.append(asset["path"])
        total += asset["length"]
        canonical += f"{asset['path']}\t{asset['length']}\t{asset['sha256']}\n"
    # Match .NET StringComparer.Ordinal, including supplementary Unicode characters.
    ordinal = lambda path: path.encode("utf-16-be")
    if (paths != sorted(set(paths), key=ordinal) or total > 64 * 1024 * 1024 or
            not all(isinstance(path, str) and path and not any(ord(ch) < 32 for ch in path) for path in unsupported) or
            unsupported != sorted(set(unsupported), key=ordinal) or
            hashlib.sha256(canonical.encode("utf-8")).hexdigest() != inventory["inventory_sha256"] or
            (branch == "surface-unsupported") != bool(unsupported) or
            branch == "origin-review-missing" and not assets or
            branch == "no-supported-layout-assets" and assets):
        raise ValueError("LP-04 inventory digest, ordering or branch is inconsistent.")


def literal(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def excerpt(value, pointer, maximum=1800):
    text = literal(value)
    if len(text.encode("utf-8")) <= maximum:
        return text
    return f"{len(value)} items retained at {pointer}; complete values exceed the row display budget"


def partial_facts(row, facts, acquisition, branch=None):
    if row == "LP-04":
        return ""
    root = facts["package"]
    source = facts["source"]
    if row == "LP-01":
        candidates = [{key: value for key, value in item.items() if key != "utf8_text"}
                      for item in root["license_or_notice_candidates"]]
        for item, original in zip(candidates, root["license_or_notice_candidates"]):
            if original.get("utf8_text"):
                item["literal_heading"] = original["utf8_text"].splitlines()[0]
        license_matches = [item["package_entry"] for item in facts["exact_source_matches"]
                           if item["package_entry"] in {c["path"] for c in candidates}]
        limitation = (" Declarations and named files do not establish owner authority or a release-scoped grant."
                      if MAPPING.get((row, branch), ("O", ""))[0] != "V" else "")
        return (f"Observed package license declarations {literal(root['license_declarations'])}; "
                f"named text candidates {excerpt(candidates, 'observations#/package/license_or_notice_candidates', 1000)}; "
                f"license/notice entries with exact source-byte matches {excerpt(license_matches, 'observations#/exact_source_matches', 400)}."
                + limitation)
    if row == "LP-02":
        if source is None:
            return "No admitted retained source archive; actual acquisition and eligibility limits are retained in acquisition.json."
        projects = [{"path": p["path"], "sdk": p["sdk_declaration"], "package_ids": p["package_id_declarations"],
                     "inherited_build_files": [b["path"] for b in p["ancestor_build_files"]]}
                    for p in source["projects"]]
        # Library-like projects first; the complete packet retains samples and other projects too.
        projects.sort(key=lambda p: (not bool(p["package_ids"]), p["path"]))
        return (f"Package repository declarations {excerpt(root['repository_declarations'], 'observations#/package/repository_declarations', 600)}. "
                f"Retained source SHA-256 {source['sha256']}, {source['file_count']} files, "
                f"declared-root match {literal(source['declared_root_matches'])}; "
                f"{len(projects)} unevaluated projects; first project {excerpt(projects[:1], 'observations#/source/projects', 1200)}. "
                "Project inventory is supplemental and unevaluated. Public availability requires a bound anonymous "
                "acquisition observation; source relevance and binary-build correspondence are not independently established.")
    if row == "LP-03":
        licenses = [{"id": p["id"], "version": p["version"], "license": p["license_declarations"]}
                    for p in facts["supplied_dependencies"]]
        grouped = {}
        for package in facts["supplied_dependencies"]:
            key = literal(package["license_declarations"])
            grouped.setdefault(key, []).append(package["id"] + "/" + package["version"])
        groups = [{"license_declarations": json.loads(key), "count": len(versions),
                   "versions": excerpt(versions, "observations#/supplied_dependencies", 1450)}
                  for key, versions in sorted(grouped.items())]
        admitted = acquisition.get("sbom_admission")
        inventory = admitted["admission"]["inventory"] if admitted else None
        summary = "No helper-admitted caller-designated inventory in acquisition; declaration samples alone do not establish completeness."
        if inventory is not None:
            retained = {p["id"].lower() + "/" + p["version"] for p in facts["supplied_dependencies"]}
            keys = {p["key"] for p in inventory["dependencies"]}
            summary = (f"Caller-designated authoritative release-wide SBOM SHA-256 {inventory['sbom_sha256']}; "
                       f"{len(keys)} inventoried exact NuGet versions, {len(keys & retained)} retained matches; "
                       f"missing {excerpt(sorted(keys - retained), 'acquisition#/sbom_admission', 650)}; "
                       f"extra samples {excerpt(sorted(retained - keys), 'observations#/supplied_dependencies', 250)}. "
                       "Structure does not independently prove completeness or publication. "
                       f"SBOM file-checksum diagnostics (separate from PI-10): "
                       f"{excerpt(inventory['diagnostics'], 'acquisition#/sbom_admission/admission/inventory/diagnostics', 400)}.")
        return (f"{len(licenses)} supplied exact dependency versions; license declarations by group "
                f"{excerpt(groups, 'observations#/supplied_dependencies', 2100)}. "
                f"Root grouped ranges {excerpt(root['declared_dependencies'], 'observations#/package/declared_dependencies', 650)}. "
                + summary)
    if row == "LP-10":
        matches = [item["package_entry"] for item in facts["exact_source_matches"]]
        common = (f"{len(facts['package_entries'])} package files; {len(matches)} exact packaged/source match sets "
                  f"{excerpt(matches, 'observations#/exact_source_matches', 1400)}. ")
        assemblies = [{key: item[key] for key in ("path", "name", "version", "informational_versions", "repository_metadata")}
                      for item in facts["assembly_candidates"]]
        return (common + f"{len(assemblies)} PE/CLI candidates with declared assembly metadata "
                f"{excerpt(assemblies, 'observations#/assembly_candidates', 1700)}. "
                "Exact text matches and declared assembly attributes do not establish ownership, referenced-upstream identity or compiled-build correspondence.")
    if row == "PI-01":
        assemblies = [{key: item[key] for key in ("path", "state", "public_key_length",
                      "strong_name_signed_flag", "strong_name_signature_size")}
                      for item in facts["assembly_candidates"]]
        return (f"{len(assemblies)} PE/CLI candidates with inspected signing fields "
                f"{excerpt(assemblies, 'observations#/assembly_candidates', 2800)}. "
                "Outer NuGet package signing does not sign the contained DLLs; the deciding resolver separately checks complete inventory and cryptographic validity.")
    return ""


def decisions(results, facts, acquisition, ids):
    rows = []
    for row in ROWS:
        value = results[row]
        code, action = MAPPING[row, value["branch_id"]]
        fact = value["finding"] if code in "VGA" else value["missing_fact"]
        observation = f"{row} [{value['branch_id']}]: {fact}"
        partial = partial_facts(row, facts, acquisition, value["branch_id"])
        if partial:
            observation += " " + partial
        if facts["diagnostics"] and row in ("LP-01", "LP-02", "LP-03", "LP-04", "LP-10"):
            observation += " Inspection diagnostics: " + excerpt(facts["diagnostics"], "observations#/diagnostics", 250) + "."
        # Unsafe display text is an admission error, never silently normalized or clipped.
        if (len(observation.encode("utf-8")) > 4096 or unicodedata.normalize("NFC", observation) != observation or
                any(unicodedata.category(c) in ("Cc", "Cf") and c not in "\u200c\u200d" for c in observation)):
            raise ValueError(f"{row} observation exceeds the supported text profile; complete packets are retained.")
        follow = None
        owner = None
        if code == "N":
            follow = f"{action} Blocker: {value['missing_fact']}"
        elif code == "O":
            owner = action + " Missing fact: " + value["missing_fact"]
            follow = "Re-run this handoff after the named owner evidence is admitted."
        elif code == "G":
            follow = action
        rows.append({"id": row, "status": STATUSES[code], "observation": observation, "evidence_ids": ids[row],
                     "owner_action": owner, "assessment_follow_up": follow,
                     "not_applicable_rationale": value["finding"] if code == "A" else None})
    return {"schema_version": 1, "rows": rows, "findings": [], "summary_groups": [], "completion_state": "incomplete"}
