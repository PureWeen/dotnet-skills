"""Reviewed, fail-closed report mapping for the eleven offline package resolvers."""
import json
import re
import unicodedata

VERSION = "eleven-row-handoff/1.0.1"
ROWS = tuple(f"LP-{number:02}" for number in range(1, 11)) + ("PI-01",)
RESOLVERS = dict(zip(ROWS, (
    "lp01-license-policy", "lp02-public-source", "lp03-dependency-licenses",
    "lp04-notice-coverage", "lp05-license-expression", "lp06-repository-url",
    "lp07-repository-commit", "lp08-authors", "lp09-project-url",
    "lp10-binary-attribution", "pi01-strong-name",
)))
STATUSES = {"V": "verified", "G": "gap", "N": "not tested",
            "O": "owner evidence required", "A": "not applicable"}

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
        ("source-relevance-unestablished", "N", "Obtain an admitted project and implementation relevance mapping."),
    ),
    "LP-03": (
        ("dependencies-policy-satisfied", "V", ""),
        ("incompatible-dependency-license", "G", "Correct the reviewed incompatible applicable dependency grant or version."),
        ("owner-evidence-required", "O", "Supply the unpublished owner-issued grant identified by the applicability review."),
        ("missing-package scope-missing", "N", "Obtain the exact root and explicit supported target-framework scope."),
        ("input-invalid binding-conflict", "N", "Repair admission and identity bindings using actual retained evidence."),
        ("policy-unavailable", "N", "Restore the exact frozen policy and catalog."),
        ("evidence-missing closure-unresolved", "N",
         "Obtain an admitted resolved graph and acquisition capture covering the requested target union."),
        ("dependency-bytes-missing", "N", "Obtain the exact inventoried dependency package."),
        ("license-evidence-unresolved", "N", "Obtain complete applicable grants and supported whole-version reviews."),
    ),
    "LP-04": (
        ("notice-coverage-satisfied", "V", ""),
        ("required-representation-missing", "G", "Restore the identified required representation and recheck exhaustive mapping."),
        ("no-applicable-surface", "A", ""),
        ("owner-evidence-required", "O", "Supply the genuinely private fact named by the admitted obligation review."),
        ("missing-package scope-missing", "N", "Obtain the exact root and explicit target-framework and all-entry scope."),
        ("input-invalid binding-conflict", "N", "Repair admission and exact root, inventory, review and entry bindings."),
        ("evidence-missing inventories-unresolved", "N", "Obtain admitted complete dependency and all-root-entry inventories."),
        ("subject-bytes-missing", "N", "Obtain the exact inventoried dependency or asset bytes."),
        ("reviews-unresolved", "N", "Obtain a supported retained whole-subject obligation review."),
        ("mapping-unresolved", "N", "Obtain exhaustive reviewed mapping and supported exact representations."),
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
    if len(result) != 179:
        raise ValueError("The reviewed mapping must contain exactly 179 row/branch pairs.")
    return result


MAPPING = mapping()
FIELDS = {"row_id", "resolver_id", "resolver_version", "branch_id", "decision", "applicability",
          "inputs", "evidence_references", "evidence_contract", "finding", "missing_fact",
          "required_input", "next_category"}


def checked_result(value, pins):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError("Unexpected resolver result fields.")
    row, branch = value["row_id"], value["branch_id"]
    if ((row, branch) not in MAPPING or value["resolver_id"] != RESOLVERS[row] or
            value["resolver_version"] != "1.0.0" or value["inputs"] != pins):
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
    return value


def literal(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def excerpt(value, pointer, maximum=1800):
    text = literal(value)
    if len(text.encode("utf-8")) <= maximum:
        return text
    return f"{len(value)} items retained at {pointer}; complete values exceed the row display budget"


def partial_facts(row, facts, acquisition, branch=None):
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
                "Local source and project facts do not establish anonymous acquisition, library relevance or binary-build correspondence.")
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
        return (f"{len(licenses)} supplied exact dependency versions; license declarations by group "
                f"{excerpt(groups, 'observations#/supplied_dependencies', 2100)}. "
                f"Root grouped ranges {excerpt(root['declared_dependencies'], 'observations#/package/declared_dependencies', 650)}. "
                "These are declaration samples, not resolved closure, complete applicable grants or whole-version reviews.")
    if row in ("LP-04", "LP-10"):
        matches = [item["package_entry"] for item in facts["exact_source_matches"]]
        common = (f"{len(facts['package_entries'])} package files; {len(matches)} exact packaged/source match sets "
                  f"{excerpt(matches, 'observations#/exact_source_matches', 1400)}. ")
        if row == "LP-04":
            dependencies = facts["supplied_dependencies"]
            notice_packages = sum(bool(p["license_or_notice_candidates"]) for p in dependencies)
            notice_files = sum(len(p["license_or_notice_candidates"]) for p in dependencies)
            scripts = [item["path"] for item in facts["package_entries"]
                       if item["path"].lower().endswith((".js", ".mjs", ".cjs"))]
            correspondence = (f"{sum(path in matches for path in scripts)} of {len(scripts)} shipped scripts have exact source-byte matches; "
                              f"stylesheet entries without exact source-byte matches "
                              f"{excerpt([item['path'] for item in facts['package_entries'] if item['path'].lower().endswith('.css') and item['path'] not in matches], 'observations#/package_entries', 650)}. "
                              if source is not None else "Source-byte correspondence was not inspected. ")
            return (common + f"Named license/notice candidates: {len(root['license_or_notice_candidates'])} root files "
                    "(observations#/package/license_or_notice_candidates); "
                    f"{notice_files} files across {notice_packages} of {len(dependencies)} supplied dependency versions "
                    "(observations#/supplied_dependencies); "
                    + (f"{len(source['license_or_notice_candidates'])} source files "
                       "(observations#/source/license_or_notice_candidates). " if source is not None else "source unavailable. ")
                    + correspondence + "Named notice candidates are not obligation reviews or exhaustive notice mappings.")
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
