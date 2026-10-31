import hashlib
import io
import json
from pathlib import Path
import re
import sys
import zipfile


if len(sys.argv) > 1:
    def require(condition):
        if not condition:
            raise ValueError("Incomplete, unbound or incorrect package-result contract")

    result = json.loads(Path(sys.argv[1]).read_text())
    require(set(result) == {"schema_version", "cases"} and result["schema_version"] == 1)
    cases = result["cases"]
    require(isinstance(cases, list) and bool(cases))
    rows = ["LP-%02d" % i for i in range(1, 11)] + ["PI-01"]
    if len(sys.argv) > 2 and sys.argv[2] == "all":
        require([item["result"]["row_id"] for item in cases] == rows)
        require([item["case_id"] for item in cases] == ["package-" + row.lower() for row in rows])
    else:
        require(len(cases) == 1 and cases[0]["case_id"] == "notice" and
                cases[0]["result"]["row_id"] == "LP-04")
    digest = hashlib.sha256(Path("sample.nupkg").read_bytes()).hexdigest()
    for item in cases:
        require(set(item) == {"case_id", "result"})
        row = item["result"]
        require(set(row) == {"row_id", "resolver_id", "resolver_version", "branch_id", "decision",
                             "applicability", "finding", "missing_fact", "required_input",
                             "next_category", "evidence_contract", "evidence_references", "inputs"})
        require(row["row_id"] in rows and row["resolver_version"] == "1.0.0")
        require(re.fullmatch(r"[a-z][a-z0-9-]*", row["resolver_id"]) is not None and
                re.fullmatch(r"[a-z][a-z0-9-]*", row["branch_id"]) is not None)
        require(row["inputs"] == [{"role": "package", "path": "sample.nupkg", "sha256": digest}])
        require(isinstance(row["evidence_references"], list) and
                all(isinstance(value, str) and value for value in row["evidence_references"]))
        require(row["applicability"] in ("applicable", "not-applicable", "unknown"))
        if row["decision"] == "escalated":
            require(row["finding"] is None and row["applicability"] != "not-applicable" and
                    all(isinstance(row[key], str) and row[key]
                        for key in ("missing_fact", "required_input", "next_category")))
        else:
            require(row["decision"] == "deterministic" and row["applicability"] != "unknown" and
                    isinstance(row["finding"], str) and bool(row["finding"]) and
                    bool(row["evidence_references"] or row["evidence_contract"]) and
                    all(row[key] is None for key in ("missing_fact", "required_input", "next_category")))
        if row["row_id"] == "LP-04":
            require(row["branch_id"] == "scope-missing" and row["decision"] == "escalated")
    sys.exit(0)

buffer = io.BytesIO()
with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
    for name, content in (
        ("Sample.nuspec", b"<package><metadata><id>Example.Controls</id><version>1.0.0</version>"
         b'<license type="expression">MIT</license><authors>Example Maintainers</authors>'
         b'<repository type="git" url="https://github.com/example/controls" '
         b'commit="1234567890123456789012345678901234567890"/>'
         b"<projectUrl>https://example.test/controls</projectUrl></metadata></package>"),
        ("build/assessment.targets", b'<Project><Target Name="NeverRun" BeforeTargets="Build">'
         b'<Error Text="Assessed package code was executed."/></Target></Project>'),
    ):
        entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
        entry.create_system = 3
        entry.external_attr = 0o100644 << 16
        archive.writestr(entry, content)
Path("sample.nupkg").write_bytes(buffer.getvalue())
request = {"schema_version": 1, "cases": [{"case_id": "notice", "row_id": "LP-04", "inputs": [
    {"role": "package", "path": "sample.nupkg",
     "sha256": hashlib.sha256(buffer.getvalue()).hexdigest()}]}]}
Path("request.json").write_text(json.dumps(request))
request["cases"][0]["inputs"][0]["sha256"] = "0" * 64
Path("changed.json").write_text(json.dumps(request))
Path("malformed.json").write_text('{"schema_version":1,"schema_version":1,"cases":[]}')
Path("Directory.Build.targets").write_text(
    '<Project><Target Name="NeverImportAssessment" BeforeTargets="PrepareForBuild">'
    '<Error Text="Assessed build customizations must not be imported."/></Target></Project>')
