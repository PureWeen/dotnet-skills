"""Offline tests for the shipped eleven-row collector and fail-closed report mapping."""
from collections import Counter
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import unicodedata
import zipfile
import zlib

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SCRIPTS = REPO / "plugins/dotnet-blazor/skills/blazor-package-readiness-resolver/scripts"
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("autofill", SCRIPTS / "autofill-eleven.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
import eleven_rows as rows


def archive(entries):
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", compression=zipfile.ZIP_STORED) as zipped:
        for name, value in entries.items():
            if isinstance(name, str):
                entry = zipfile.ZipInfo()
                entry.filename = name
                name = entry
            zipped.writestr(name, value)
    return memory.getvalue()


def package(package_id="Example.Controls", version="1.0.0", dependencies=""):
    return archive({
        "Example.nuspec": (
            f'<package><metadata><id>{package_id}</id><version>{version}</version><authors>Example</authors>'
            '<license type="expression">MIT</license><projectUrl>https://example.test/controls</projectUrl>'
            '<repository type="git" url="https://github.com/example/controls" '
            f'commit="{"1" * 40}"/>{dependencies}</metadata></package>').encode(),
        "[Content_Types].xml": b"<Types/>",
    })


def frozen_results():
    store = json.loads((HERE / "corpus/expectations.json").read_bytes())
    built = []
    for kind, value in store["nodes"]:
        built.append(store["strings"][value] if kind == "s" else
                     {store["strings"][key]: built[item] for key, item in value} if kind == "o" else
                     [built[item] for item in value] if kind == "a" else value)
    from oracles.lp03_sbom_expectations import mapping_results
    from oracles.lp04_dlite_expectations import mapping_results as lp04_results
    from oracles.lp10_expectations import mapping_results as lp10_results
    return ([case["expected"] for kind, index in store["files"].values() if kind in ("j", "u")
             for case in built[index].get("cases", []) if "expected" in case and
             not (case["expected"]["row_id"] == "LP-04" and
                  case["expected"]["resolver_version"] == "1.0.0")] +
            mapping_results() + lp04_results() + lp10_results())


def empty_observations():
    return {"package": {"license_declarations": [], "repository_declarations": [],
                        "license_or_notice_candidates": [], "declared_dependencies": []},
            "source": None, "supplied_dependencies": [], "package_entries": [],
            "exact_source_matches": [], "assembly_candidates": [], "diagnostics": []}


class SbomCollectionTests(unittest.TestCase):
    def test_release_sbom_zip_extracts_only_bounded_manifest_and_optional_checksum(self):
        raw = b'{"spdxVersion":"SPDX-2.2"}'
        for checksum in (False, True):
            entries = {"manifest.spdx.json": raw}
            if checksum:
                entries["manifest.spdx.json.sha256"] = tool.sha(raw).encode("ascii")
            with self.subTest(checksum=checksum):
                self.assertEqual(tool.release_sbom_from_zip(archive(entries)), raw)
        invalid = [
            {"other.json": raw},
            {"nested/manifest.spdx.json": raw},
            {"../manifest.spdx.json": raw},
            {"manifest.spdx.json": raw, "extra.json": raw},
            {"manifest.spdx.json": raw, "MANIFEST.SPDX.JSON": raw},
            {"manifest.spdx.json": raw, "manifest.spdx.json.sha256": b"0" * 64},
            {"manifest.spdx.json": b"x" * (tool.SBOM_LIMIT + 1)},
        ]
        for entries in invalid:
            with self.subTest(names=list(entries)), self.assertRaises((ValueError, zipfile.BadZipFile)):
                tool.release_sbom_from_zip(archive(entries))
        with self.assertRaises(ValueError):
            tool.release_sbom_from_zip(archive({"manifest.spdx.json": raw}) + b"trailing")
        linked = zipfile.ZipInfo("manifest.spdx.json")
        linked.external_attr = (0o120777 << 16)
        with self.assertRaises(ValueError):
            tool.release_sbom_from_zip(archive({linked: raw}))
        encrypted = bytearray(archive({"manifest.spdx.json": raw}))
        encrypted[6] |= 1
        central = encrypted.index(b"PK\x01\x02")
        encrypted[central + 8] |= 1
        with self.assertRaises(ValueError):
            tool.release_sbom_from_zip(bytes(encrypted))
        maximum = b"x" * tool.SBOM_LIMIT
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            entry = zipfile.ZipInfo("manifest.spdx.json")
            entry.compress_type = compression
            self.assertEqual(tool.release_sbom_from_zip(archive({entry: maximum})), maximum)
        with self.assertRaises(ValueError):
            tool.release_sbom_from_zip(b"x" * (tool.SBOM_ZIP_LIMIT + 1))
        duplicate = io.BytesIO()
        with zipfile.ZipFile(duplicate, "w") as zipped:
            zipped.writestr("manifest.spdx.json", raw)
            with self.assertWarns(UserWarning):
                zipped.writestr("manifest.spdx.json", raw)
        with self.assertRaises(ValueError):
            tool.release_sbom_from_zip(duplicate.getvalue())
        corrupt = bytearray(archive({"manifest.spdx.json": raw}))
        corrupt[corrupt.index(raw)] ^= 1
        with self.assertRaises(zipfile.BadZipFile):
            tool.release_sbom_from_zip(bytes(corrupt))

    def test_release_sbom_zip_rejects_surplus_deflate_with_matching_prefix_crc(self):
        prefix = b"{}"
        entry = zipfile.ZipInfo("manifest.spdx.json")
        entry.compress_type = zipfile.ZIP_DEFLATED
        forged = bytearray(archive({entry: prefix + b" " * (2 * tool.MIB - len(prefix))}))
        central = forged.index(b"PK\x01\x02")
        for offset in (14, central + 16):
            forged[offset:offset + 4] = zlib.crc32(prefix).to_bytes(4, "little")
        for offset in (22, central + 24):
            forged[offset:offset + 4] = len(prefix).to_bytes(4, "little")
        for reader in (tool.archive_inventory, tool.release_sbom_from_zip):
            with self.subTest(reader=reader.__name__), self.assertRaises((ValueError, zipfile.BadZipFile)):
                reader(bytes(forged))

    def test_release_sbom_zip_retains_wrapper_and_designates_extracted_bytes(self):
        raw = b'{"spdxVersion":"SPDX-3.0"}'
        with tempfile.TemporaryDirectory(prefix="sbom-zip-") as directory:
            root = Path(directory).resolve()
            capture = root / "capture"
            capture.mkdir()
            main, wrapped = capture / "package.nupkg", root / "release.zip"
            main.write_bytes(package())
            wrapped.write_bytes(archive({"manifest.spdx.json": raw}))
            def admit(request, output):
                pins = tool.load(request)["inputs"]
                sbom_pin = next(pin for pin in pins if pin["role"] == "sbom")
                self.assertEqual(sbom_pin["sha256"], tool.sha(raw))
                self.assertEqual(tool.load(capture / "lp-03-scope.json")["sbom_sha256"], tool.sha(raw))
                tool.dump(output, {"schema_version": 2, "producer": "sbom-inventory/2.0.0",
                    "inputs": pins, "admission": {"disposition": "unsupported",
                        "detail": "Unsupported SPDX version.", "inventory": None}})
            transport = mock.Mock(side_effect=AssertionError("Unsupported SBOM must not fetch."))
            collector = tool.Collector(root, capture, 64, True, transport, admit=admit)
            collector.collect(main, tool.package_metadata(main.read_bytes()), None, [],
                              source_allowed=False, release_sbom=wrapped)
            transport.assert_not_called()
            self.assertEqual(collector.sbom.read_bytes(), raw)
            record = collector.records[0]
            self.assertEqual(record["sha256"], tool.sha(wrapped.read_bytes()))
            self.assertEqual((root / record["retained_path"]).read_bytes(), wrapped.read_bytes())
            self.assertEqual(collector.total, sum(p.stat().st_size for p in capture.iterdir()))

    def test_package_metadata_supports_all_nuspec_namespaces(self):
        namespaces = ("", *(f"http://schemas.microsoft.com/packaging/{version}/nuspec.xsd"
                            for version in ("2010/07", "2011/08", "2011/10", "2012/06", "2013/01", "2013/05")))
        for namespace in (*namespaces, "http://example.com/nuspec.xsd"):
            def control(metadata_namespace=None, id_namespace=None):
                return archive({"Example.nuspec": (
                    f'<package xmlns="{namespace}"><metadata' +
                    (f' xmlns="{metadata_namespace}"' if metadata_namespace is not None else "") +
                    '><id' + (f' xmlns="{id_namespace}"' if id_namespace is not None else "") +
                    '>Example.Controls</id><version>1.0.0</version></metadata></package>').encode()})
            with self.subTest(namespace=namespace):
                if namespace not in namespaces:
                    with self.assertRaisesRegex(ValueError, "namespace"):
                        tool.package_metadata(control())
                    continue
                self.assertEqual(tool.package_metadata(control())["id"], "example.controls")
                other = namespaces[-1] if not namespace else ""
                with self.assertRaisesRegex(ValueError, "metadata"):
                    tool.package_metadata(control(metadata_namespace=other))
                with self.assertRaisesRegex(ValueError, "id"):
                    tool.package_metadata(control(id_namespace=other))

    def test_exact_native_inventory_roles_holes_and_no_minimum_sampling(self):
        from oracles.lp03_sbom_expectations import sbom, encoded
        with tempfile.TemporaryDirectory(prefix="sbom-helper-") as directory:
            root = Path(directory).resolve()
            capture = root / "capture"
            capture.mkdir()
            main = capture / "package.nupkg"
            main.write_bytes(package(dependencies='<dependencies><dependency id="Example.Dependency" version="0.5.0"/></dependencies>'))
            raw = root / "release.spdx.json"
            raw.write_bytes(encoded(sbom(("example.dependency", "z.dependency"))))
            supplied = root / "supplied.nupkg"
            supplied.write_bytes(package("z.dependency"))
            components = [{"id": name, "version": "1.0.0", "key": name + "/1.0.0", "ecosystem": "nuget"}
                          for name in ("example.dependency", "z.dependency")]
            def admit(request, output):
                pins = tool.load(request)["inputs"]
                self.assertEqual({p["role"] for p in pins}, {"package", "assessment", "sbom"})
                assessment = tool.load(capture / "lp-03-scope.json")
                self.assertEqual(assessment["designation"]["sbom_sha256"], tool.sha(raw.read_bytes()))
                self.assertEqual(assessment["designation"]["basis"], "caller-authoritative-release-inventory/1")
                tool.dump(output, {"schema_version": 2, "producer": "sbom-inventory/2.0.0", "inputs": pins,
                                  "admission": {"disposition": "admitted", "structural_admission": "admitted",
                                    "designation_admission": "designated", "inventory": {
                                        "profile": "spdx22-release-nuget-npm-union/1.0.0", "dependencies": components}}})
            collector = tool.Collector(root, capture, 64, False, admit=admit)
            collector.collect(main, tool.package_metadata(main.read_bytes()), None, [supplied], release_sbom=raw)
            _, request = tool.requests(root, capture, main, tool.package_metadata(main.read_bytes()), collector, None)
            lp03 = next(c for c in request["cases"] if c["row_id"] == "LP-03")
            lp04 = next(c for c in request["cases"] if c["row_id"] == "LP-04")
            self.assertEqual([p["role"] for p in lp04["inputs"]], ["package"])
            self.assertFalse((capture / "lp-04-scope.json").exists())
            self.assertEqual([p["role"] for p in lp03["inputs"] if p["role"].startswith("dependency-")], ["dependency-001"])
            self.assertEqual([r["subject"] for r in collector.records], ["package", "documentation"])
            self.assertTrue(all(not r["request_sent"] and r["method"] == "local-file" for r in collector.records))
            self.assertEqual(collector.edges, [])

    def test_sbom_import_and_exact_download_share_retrieval_and_byte_budgets(self):
        from oracles.lp03_sbom_expectations import encoded, sbom
        for budget, feed, expected in ((1, "nuget.org", 0), (2, "nuget.org", 1), (64, "dotnet-public", 2)):
            with self.subTest(budget=budget, feed=feed), tempfile.TemporaryDirectory(prefix="sbom-budget-") as directory:
                root = Path(directory).resolve()
                capture = root / "capture"
                capture.mkdir()
                main = capture / "package.nupkg"
                main.write_bytes(package())
                raw = root / "sbom.json"
                raw.write_bytes(encoded(sbom(("microsoft.sourcelink.github", "z.tool"))))
                calls = []
                def admit(request, output):
                    tool.dump(output, {"schema_version": 2, "producer": "sbom-inventory/2.0.0",
                        "inputs": tool.load(request)["inputs"], "admission": {
                            "disposition": "admitted", "structural_admission": "admitted", "designation_admission": "designated",
                            "inventory": {"profile": "spdx22-release-nuget-npm-union/1.0.0",
                              "dependencies": [{"id": name, "version": "1.0.0", "ecosystem": "nuget"} for name in ("microsoft.sourcelink.github", "z.tool")]}}})
                def transport(url, destination, maximum, seconds):
                    calls.append(url)
                    destination.write_bytes(b"partial")
                    return {"result": "unavailable", "detail_code": "http-status", "http_status": 404}
                collector = tool.Collector(root, capture, budget, True, transport, nuget_feed=feed, admit=admit)
                collector.collect(main, tool.package_metadata(main.read_bytes()), None, [], source_allowed=False, release_sbom=raw)
                self.assertEqual(len(calls), expected)
                self.assertEqual(len(collector.records), expected + 1)
                self.assertEqual(collector.total, sum(p.stat().st_size for p in capture.iterdir() if p.is_file()))
                self.assertEqual(collector.dependencies, {})
                if calls:
                    self.assertIn("/microsoft.sourcelink.github/1.0.0/", calls[0])
                    self.assertTrue(all(url.startswith(tool.NUGET_FEEDS[feed]) for url in calls))
                    if feed == "dotnet-public":
                        self.assertTrue(all("api.nuget.org" not in url for url in calls))

    def test_unsupported_inventory_never_triggers_transport(self):
        with tempfile.TemporaryDirectory(prefix="sbom-unsupported-") as directory:
            root = Path(directory).resolve()
            capture = root / "capture"
            capture.mkdir()
            main, raw = capture / "package.nupkg", root / "unsupported.json"
            main.write_bytes(package())
            raw.write_bytes(b'{"spdxVersion":"SPDX-2.3"}')
            def admit(request, output):
                tool.dump(output, {"schema_version": 2, "producer": "sbom-inventory/2.0.0",
                    "inputs": tool.load(request)["inputs"], "admission": {
                        "disposition": "unsupported", "detail": "Unsupported format.", "inventory": None}})
            transport = mock.Mock(side_effect=AssertionError("Unsupported SBOM must not fetch."))
            collector = tool.Collector(root, capture, 64, True, transport, admit=admit)
            collector.collect(main, tool.package_metadata(main.read_bytes()), None, [], source_allowed=False, release_sbom=raw)
            transport.assert_not_called()
            self.assertEqual(collector.records[0]["method"], "local-file")
            self.assertFalse(collector.records[0]["request_sent"])

    def test_source_only_dollar_members_preserve_path_guards(self):
        names = ["repo/src/Comparer$1.ts", "repo/src/Event Args$2.ts"]
        data = archive({name: b"retained source bytes, never executed" for name in names})
        self.assertEqual(tool.archive_inventory(data, source=True), names)
        with self.assertRaises(ValueError):
            tool.archive_inventory(data)
        for path in ("repo/$/../../escape", "repo/CONIN$.txt", "repo/a$.", "repo//",
                     "C:/repo/a$.ts", "//host/a$.ts", "repo/a$:stream"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                tool.archive_inventory(archive({path: b""}), source=True)
        for pair in (("repo/a$.ts", "repo/A$.ts"), ("repo/a$/", "repo/a$")):
            with self.subTest(pair=pair), self.assertRaises(ValueError):
                tool.archive_inventory(archive(dict.fromkeys(pair, b"")), source=True)

    def test_npm_imports_bind_local_bytes_without_retrieval_claims(self):
        for mode in ("retained", "hash-conflict", "missing", "oversized"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix="npm-intake-") as directory:
                root = Path(directory).resolve()
                capture = root / "capture"
                capture.mkdir()
                supplied = root / "supplied"
                supplied.mkdir()
                content = b"exact caller-designated archive bytes"
                if mode != "missing":
                    (supplied / "npm.tgz").write_bytes(content if mode != "oversized" else b"x" * (tool.PACKAGE_LIMIT + 1))
                packet = {"schema_version": 1, "basis": "caller-designated-exact-npm-archives/1",
                    "root_sha256": "a" * 64, "sbom_sha256": "b" * 64, "archives": [{
                        "purl": "pkg:npm/%40scope/foo@1.0.0", "path": "npm.tgz",
                        "sha256": "0" * 64 if mode == "hash-conflict" else tool.sha(content)}]}
                manifest = supplied / "npm-archives.json"
                tool.dump(manifest, packet)
                inventory = {"root_sha256": "a" * 64, "sbom_sha256": "b" * 64,
                    "dependencies": [{"ecosystem": "npm", "id": "@scope/foo", "version": "1.0.0"}]}
                collector = tool.Collector(root, capture, 0, False)
                collector.import_npm_packet(manifest, inventory)
                self.assertEqual(collector.records, [])
                self.assertEqual((capture / "npm-archives.json").read_bytes(), manifest.read_bytes())
                result = collector.npm_imports[0]
                self.assertFalse(result["request_sent"])
                self.assertEqual(result["result"], mode if mode in ("retained", "hash-conflict") else "missing-or-unsupported")
                self.assertEqual(bool(collector.npm_dependencies), mode in ("retained", "hash-conflict"))


    def test_provenance_inputs_require_all_three_artifacts_and_source_archive(self):
        with tempfile.TemporaryDirectory(prefix="provenance-helper-") as directory:
            root = Path(directory).resolve()
            capture = root / "capture"
            capture.mkdir()
            main = capture / "package.nupkg"
            main.write_bytes(package())
            metadata = tool.package_metadata(main.read_bytes())
            package_pin = tool.pin(capture, main, "package")
            source = root / "source.zip"
            source.write_bytes(archive({"controls-" + "1" * 40 + "/Controls.csproj": b"<Project/>"}))
            release = root / "release.nupkg"
            release.write_bytes(main.read_bytes())
            bundle = root / "provenance.sigstore.json"
            bundle.write_bytes(b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}')
            collector = tool.Collector(root, capture, 10, False)
            collector.collect(main, metadata, source, [])
            with self.assertRaisesRegex(ValueError, "Both --release-nupkg and --provenance-bundle are required"):
                tool.provenance_inputs(capture, package_pin, metadata, collector,
                                       unittest.mock.Mock(release_nupkg=release, provenance_bundle=None))
            mock_completed = unittest.mock.Mock(
                returncode=0, stdout='[{"verificationResult":{}}]', stderr="")
            with unittest.mock.patch.object(tool.subprocess, "run", return_value=mock_completed) as mocked_run:
                provenance = tool.provenance_inputs(
                    capture, package_pin, metadata, collector,
                    unittest.mock.Mock(release_nupkg=release, provenance_bundle=bundle), b"k" * 32)
                mocked_run.assert_called_once()
                self.assertTrue(Path(mocked_run.call_args.args[0][0]).is_absolute())
                self.assertEqual(mocked_run.call_args.kwargs["encoding"], "utf-8")
                self.assertEqual(mocked_run.call_args.kwargs["errors"], "replace")
            cwd_before = os.getcwd()
            try:
                os.chdir(root)
                for fake_name in ("gh", "gh.exe", "gh.cmd", "gh.bat"):
                    fake_bin = root / fake_name
                    fake_bin.write_text("#!/bin/sh\necho '[]'\n", encoding="utf-8")
                    os.chmod(fake_bin, 0o755)
                self.assertIsNone(tool.resolve_executable("gh", ["", ".", str(root / "nonexistent")]))
            finally:
                os.chdir(cwd_before)
            receipt = json.loads(tool.base64.b64decode(tool.load(capture / "provenance-attestation.json")["payload"]))
            self.assertIsNone(receipt["source_acquisition"], "B1 local imports must never invent trusted source acquisition")
            def clear_admission():
                for name in ("release-package.nupkg", "provenance-bundle.json", "provenance-attestation.json"):
                    (capture / name).unlink(missing_ok=True)
            saved_receipt = (capture / "provenance-attestation.json").read_bytes()
            valid_payload = tool.base64.b64encode(
                b'{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1"}'
            ).decode("ascii")
            valid_bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                            "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": valid_payload}}
            for raw_bad in (
                b"null",
                b"[]",
                b"123",
                b'"str"',
                b'{"predicateType":"https://cyclonedx.org/bom","predicateType":"https://slsa.dev/provenance/v1"}',
                b'{"predicateType":"https://slsa.dev/provenance/v1","nested":{"k":1,"k":2}}',
                b'{"predicateType":"https://slsa.dev/provenance/v1","nan":NaN}',
            ):
                bad_payload = tool.base64.b64encode(raw_bad).decode("ascii")
                bad_bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                              "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": bad_payload}}
                multi = root / "attestations.json"
                multi.unlink(missing_ok=True)
                tool.dump(multi, {"attestations": [{"bundle": bad_bundle}, {"bundle": valid_bundle}]})
                clear_admission()
                with mock.patch.object(tool.subprocess, "run", return_value=mock_completed):
                    tool.provenance_inputs(capture, package_pin, metadata, collector,
                                           mock.Mock(release_nupkg=release, provenance_bundle=multi), b"k" * 32)
                self.assertEqual(tool.load(capture / "provenance-bundle.json"), valid_bundle)
                only_bad = root / "only-bad-attestations.json"
                only_bad.unlink(missing_ok=True)
                tool.dump(only_bad, {"attestations": [{"bundle": bad_bundle}]})
                clear_admission()
                with self.assertRaisesRegex(ValueError, "No SLSA v1 provenance bundle found"):
                    tool.provenance_inputs(capture, package_pin, metadata, collector,
                                           mock.Mock(release_nupkg=release, provenance_bundle=only_bad), b"k" * 32)
            for bad_stdout in (
                '[{"verificationResult":{}, "verificationResult":{}}]',
                '[{"verificationResult":{"k":1,"k":2}}]',
                '[{"verificationResult":{"n":NaN}}]',
                '[{"verificationResult":{"n":Infinity}}]',
                '[{"verificationResult":{"n":-Infinity}}]',
            ):
                clear_admission()
                with mock.patch.object(tool.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=bad_stdout, stderr="")):
                    tool.provenance_inputs(capture, package_pin, metadata, collector,
                                           mock.Mock(release_nupkg=release, provenance_bundle=bundle), b"k" * 32)
                rejected = json.loads(tool.base64.b64decode(tool.load(capture / "provenance-attestation.json")["payload"]))
                self.assertEqual(rejected["verification"], [])
                self.assertEqual(rejected["verification_status"], "unverified")
            clear_admission()
            with mock.patch.object(tool.subprocess, "run", return_value=mock.Mock(returncode=1, stderr="no", stdout="")):
                tool.provenance_inputs(capture, package_pin, metadata, collector,
                                       mock.Mock(release_nupkg=release, provenance_bundle=bundle), b"k" * 32)
            failed = json.loads(tool.base64.b64decode(tool.load(capture / "provenance-attestation.json")["payload"]))
            self.assertEqual(failed["verification"], [])
            self.assertEqual(failed["verification_status"], "unverified")
            clear_admission()
            with mock.patch.object(tool.subprocess, "run", side_effect=subprocess.TimeoutExpired("gh", 60)):
                with self.assertRaisesRegex(tool.ToolFailure, "60-second timeout"):
                    tool.provenance_inputs(capture, package_pin, metadata, collector,
                                           mock.Mock(release_nupkg=release, provenance_bundle=bundle), b"k" * 32)
            (capture / "provenance-attestation.json").write_bytes(saved_receipt)
            _, request = tool.requests(root, capture, main, metadata, collector, None, provenance)
            lp10 = next(c for c in request["cases"] if c["row_id"] == "LP-10")
            self.assertEqual([p["role"] for p in lp10["inputs"]],
                             ["package", "release-package", "provenance-bundle",
                              "provenance-attestation", "source-archive"])
            capture2 = root / "capture2"
            capture2.mkdir()
            main2 = capture2 / "package.nupkg"
            main2.write_bytes(main.read_bytes())
            row_packets = root / "row-packets.json"
            row_packets.write_text(json.dumps({"schema_version": 1, "cases": [
                {"case_id": "eleven-lp-10", "row_id": "LP-10", "inputs": [
                    {"role": "package", "path": "package.nupkg", "sha256": package_pin["sha256"]},
                    {"role": "release-package", "path": "../release.nupkg", "sha256": package_pin["sha256"]},
                ]}
            ]}), encoding="utf-8")
            collector2 = tool.Collector(root, capture2, 10, False)
            collector2.collect(main2, metadata, source, [])
            with self.assertRaisesRegex(ValueError, "LP-10 provenance packets must be admitted via --release-nupkg and --provenance-bundle"):
                tool.requests(root, capture2, main2, metadata, collector2, row_packets, [])
            for row in ("LP-04", "LP-10"):
                row_packets.write_text(json.dumps({"schema_version": 1, "cases": [
                    {"case_id": "override", "row_id": row, "inputs": [package_pin]}]}), encoding="utf-8")
                for name in ("inspection-request.json", "policy.json", "corpus.json", "resolve-request.json"):
                    (capture / name).unlink(missing_ok=True)
                with self.assertRaisesRegex(ValueError, "overrides are forbidden"):
                    tool.requests(root, capture, main, metadata, collector, row_packets, provenance)


class MappingTests(unittest.TestCase):
    def test_all_171_branches_and_frozen_decision_boundaries(self):
        results = frozen_results()
        observed = {(r["row_id"], r["branch_id"]) for r in results}
        self.assertEqual(set(rows.MAPPING), observed)
        self.assertEqual(len(observed), 175)
        self.assertGreaterEqual(len(results), 870)
        def display_safe(text):
            return (len(text.encode("utf-8")) <= 4096 and unicodedata.normalize("NFC", text) == text and
                    not any(unicodedata.category(c) in ("Cc", "Cf") and c not in "\u200c\u200d" for c in text))

        defaults = {row: next(value for value in results if value["row_id"] == row and
                              display_safe(value["finding"] or value["missing_fact"])) for row in rows.ROWS}
        facts = empty_observations()
        for value in results:
            rows.checked_result(value, value["inputs"])
            status = rows.MAPPING[value["row_id"], value["branch_id"]][0]
            self.assertEqual(value["decision"] == "deterministic", status in "VGA")
            self.assertEqual(value["applicability"] == "not-applicable", status == "A")
            selected = {**defaults, value["row_id"]: value}
            text = value["finding"] if value["decision"] == "deterministic" else value["missing_fact"]
            observation = f"{value['row_id']} [{value['branch_id']}]: {text}"
            partial = rows.partial_facts(value["row_id"], facts, {}, value["branch_id"])
            if partial:
                observation += " " + partial
            if not display_safe(observation):
                with self.assertRaisesRegex(ValueError, "supported text profile"):
                    rows.decisions(selected, facts, {}, {row: [] for row in rows.ROWS})
                continue
            output = rows.decisions(selected, facts, {}, {row: [] for row in rows.ROWS})
            row = next(item for item in output["rows"] if item["id"] == value["row_id"])
            self.assertEqual(row["status"], rows.STATUSES[status])
            self.assertEqual(row["owner_action"] is not None, status == "O")
            if value["row_id"] == "LP-01":
                limitation = "Declarations and named files do not establish owner authority or a release-scoped grant."
                self.assertEqual(limitation in row["observation"], status != "V")
                if value["branch_id"] == "approved-non-copyleft":
                    self.assertEqual(row["status"], "verified")
                    self.assertIsNone(row["owner_action"])
                    self.assertIsNone(row["assessment_follow_up"])
            self.assertEqual(row["not_applicable_rationale"] is not None, status == "A")
            self.assertIn(text, row["observation"])
            if value["row_id"] == "LP-03":
                self.assertIn("npm archive hashes bind caller-designated bytes and do not authenticate publisher archives.",
                              row["observation"])
            self.assertEqual(output["completion_state"], "incomplete")

    def test_result_mutations_fail_closed(self):
        original = next(value for value in frozen_results() if value["decision"] == "deterministic")
        for key, mutation in (("branch_id", "invented-positive"), ("resolver_version", "2.0.0"),
                              ("decision", "escalated"), ("applicability", "unknown"), ("finding", None),
                              ("inputs", [])):
            value = copy.deepcopy(original)
            value[key] = mutation
            with self.subTest(key=key), self.assertRaises(ValueError):
                rows.checked_result(value, original["inputs"])

    def test_versions_are_admitted_only_for_their_reviewed_contracts(self):
        versions = {"LP-01": "1.1.0", "LP-02": "1.2.0", "LP-03": "1.4.0", "LP-04": "2.1.0", "LP-10": "1.1.0", "PI-01": "1.1.0"}
        for row in rows.ROWS:
            original = next(value for value in frozen_results() if value["row_id"] == row)
            self.assertEqual(original["resolver_version"], versions.get(row, "1.0.0"))
            value = copy.deepcopy(original)
            value["resolver_version"] = "1.1.0" if row == "LP-03" or row not in versions else "1.0.0"
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, "version"):
                rows.checked_result(value, original["inputs"])

    def test_lp03_mixed_observations_keep_ecosystems_and_imports_distinct(self):
        facts = empty_observations()
        facts["supplied_dependencies"] = [
            {"id": "Lib", "version": "1.0.0", "license_declarations": [{"type": "expression", "value": "MIT"}]}]
        dependencies = [{"ecosystem": ecosystem, "key": name + "/1.0.0"}
                        for ecosystem, name in (("nuget", "lib"), ("npm", "lib"), ("npm", "@scope/foo"))]
        acquisition = {"sbom_admission": {"admission": {"inventory": {
            "sbom_sha256": "a" * 64, "dependencies": dependencies, "diagnostics": []}}},
            "npm_evidence_imports": [], "inventory_member_outcomes": []}
        for index, name in enumerate(("lib", "@scope/foo")):
            path, digest = f"npm-{index:03}.tgz", str(index + 1) * 64
            acquisition["npm_evidence_imports"].append({
                "result": "retained", "retained_path": path,
                "actual_sha256": digest, "expected_sha256": digest})
            acquisition["inventory_member_outcomes"].append({
                "ecosystem": "npm", "id": name, "version": "1.0.0", "result": "retained",
                "retained_path": path, "sha256": digest})
        observation = rows.partial_facts("LP-03", facts, acquisition)
        self.assertIn("1 supplied exact NuGet dependency versions", observation)
        self.assertIn("3 inventoried exact dependency versions (1 NuGet, 2 npm)", observation)
        self.assertIn("1 retained NuGet matches, 2 retained checksum-matched npm archive candidates", observation)
        self.assertIn('missing {"nuget":[],"npm":[]}', observation)
        self.assertIn("npm import counts do not classify licenses", observation)
        self.assertNotIn("3 inventoried exact NuGet", observation)

    def test_lp03_unchecked_or_conflicting_npm_imports_stay_missing(self):
        facts = empty_observations()
        facts["supplied_dependencies"] = [
            {"id": "Lib", "version": "1.0.0", "license_declarations": []}]
        inventory = {"sbom_sha256": "a" * 64, "diagnostics": [], "dependencies": [
            {"ecosystem": ecosystem, "key": "lib/1.0.0"} for ecosystem in ("nuget", "npm")]}
        for mode in ("absent", "hash-conflict", "missing-or-unsupported", "digest-mismatch", "path-mismatch"):
            acquisition = {"sbom_admission": {"admission": {"inventory": inventory}},
                "inventory_member_outcomes": [{"ecosystem": "npm", "id": "lib", "version": "1.0.0",
                    "result": "retained", "retained_path": "npm-000.tgz", "sha256": "b" * 64}]}
            if mode != "absent":
                acquisition["npm_evidence_imports"] = [{
                    "result": mode if mode in ("hash-conflict", "missing-or-unsupported") else "retained",
                    "retained_path": "other.tgz" if mode == "path-mismatch" else "npm-000.tgz",
                    "actual_sha256": "b" * 64,
                    "expected_sha256": ("c" if mode == "digest-mismatch" else "b") * 64}]
            with self.subTest(mode=mode):
                observation = rows.partial_facts("LP-03", facts, acquisition)
                self.assertIn("1 retained NuGet matches, 0 retained checksum-matched npm archive candidates", observation)
                self.assertIn('missing {"nuget":[],"npm":["lib/1.0.0"]}', observation)

    def test_lp03_nuget_only_observations_preserve_case_insensitive_matching(self):
        facts = empty_observations()
        facts["supplied_dependencies"] = [
            {"id": "Lib", "version": "1.0.0", "license_declarations": []}]
        acquisition = {"sbom_admission": {"admission": {"inventory": {
            "sbom_sha256": "a" * 64, "diagnostics": [],
            "dependencies": [{"ecosystem": "nuget", "key": "lib/1.0.0"}]}}}}
        observation = rows.partial_facts("LP-03", facts, acquisition)
        self.assertIn("1 inventoried exact dependency versions (1 NuGet, 0 npm)", observation)
        self.assertIn('missing {"nuget":[],"npm":[]}', observation)

    def test_partial_observations_preserve_notices_stylesheets_and_each_assembly(self):
        facts = empty_observations()
        license_file = {"path": "LICENSE.txt", "size_bytes": 100, "sha256": "a" * 64,
                        "text_state": "retained-utf8", "utf8_text": "MIT License\nLiteral text, not owner approval."}
        repository = {"type": "git", "url": "https://github.com/example/library", "commit": "b" * 40}
        facts["package"].update(license_declarations=[{"type": "expression", "value": "MIT"}],
                                repository_declarations=[repository], license_or_notice_candidates=[license_file])
        facts["source"] = {"sha256": "c" * 64, "file_count": 3, "declared_root_matches": True,
                           "projects": [], "license_or_notice_candidates": [license_file]}
        facts["package_entries"] = [{"path": path} for path in
                                    ("LICENSE.txt", "scripts/a.js", "scripts/unmatched.js", "styles/bundle.scp.css")]
        facts["exact_source_matches"] = [{"package_entry": path} for path in ("LICENSE.txt", "scripts/a.js")]
        facts["supplied_dependencies"] = [{"license_or_notice_candidates": [license_file]},
                                           {"license_or_notice_candidates": [license_file, {**license_file, "path": "NOTICE.txt"}]}]
        for index, state in enumerate(("unsigned", "public-signed", "unsafe")):
            facts["assembly_candidates"].append({
                "path": f"lib/net{8 + index}.0/Example.dll", "name": None if state == "unsafe" else "Example",
                "version": None if state == "unsafe" else "1.2.3.0", "informational_versions": ["1.2.3"],
                "repository_metadata": [{"type": "RepositoryUrl", "value": repository["url"]}],
                "state": state, "public_key_length": None if state == "unsafe" else 0,
                "strong_name_signed_flag": None if state == "unsafe" else state == "public-signed",
                "strong_name_signature_size": None if state == "unsafe" else 0 if state == "unsigned" else 128,
            })
        license_observation = rows.partial_facts("LP-01", facts, {})
        self.assertIn("MIT License", license_observation)
        self.assertIn('matches ["LICENSE.txt"]', license_observation)
        self.assertNotIn("Literal text, not owner approval.", license_observation)
        for branch in ("approved-non-copyleft", "owner-evidence-accepted"):
            verified_observation = rows.partial_facts("LP-01", facts, {}, branch)
            self.assertIn('"value":"MIT"', verified_observation)
            self.assertIn("MIT License", verified_observation)
            self.assertIn('matches ["LICENSE.txt"]', verified_observation)
            self.assertNotIn("Declarations and named files do not establish owner authority", verified_observation)
        self.assertIn(repository["url"], rows.partial_facts("LP-02", facts, {}))
        notice = rows.partial_facts("LP-04", facts, {})
        self.assertEqual(notice, "")
        attribution = rows.partial_facts("LP-10", facts, {})
        verified_attribution = rows.partial_facts("LP-10", facts, {}, "provenance-attributed")
        signing = rows.partial_facts("PI-01", facts, {})
        for assembly in facts["assembly_candidates"]:
            self.assertIn(assembly["path"], attribution)
            self.assertIn(assembly["path"], verified_attribution)
            self.assertIn(assembly["path"], signing)
            self.assertIn(assembly["state"], signing)
        self.assertIn("1.2.3", attribution)
        self.assertIn(repository["url"], attribution)
        self.assertIn("the deciding resolver separately evaluates any supplied SLSA v1 build provenance packet", verified_attribution)
        self.assertNotIn("separately evaluates any supplied SLSA v1 build provenance packet", attribution)
        self.assertIn('"public_key_length":null', signing)
        self.assertIn("does not sign the contained DLLs", signing)
        facts["source"] = None
        self.assertEqual(rows.partial_facts("LP-04", facts, {}), "")

    def test_large_observation_lists_retain_counts_and_exact_packet_pointers(self):
        facts = empty_observations()
        facts["source"] = {"license_or_notice_candidates": []}
        for index in range(100):
            path = "staticwebassets/" + "x" * 80 + str(index) + ".css"
            facts["package_entries"].append({"path": path})
            facts["exact_source_matches"].append({"package_entry": path})
            facts["assembly_candidates"].append({
                "path": f"lib/net8.0/{index}.dll", "name": "x" * 100, "version": "1.2.3.0",
                "informational_versions": ["1.2.3"], "repository_metadata": [],
                "state": "unsigned", "public_key_length": 0, "strong_name_signed_flag": False,
                "strong_name_signature_size": 0,
            })
        for row in ("LP-10", "PI-01"):
            observation = rows.partial_facts(row, facts, {})
            self.assertLess(len(observation.encode("utf-8")), 3500)
            pointer = "observations#/assembly_candidates"
            self.assertIn("100 items retained at " + pointer, observation)
        self.assertNotIn("lib/net8.0/0.dll", rows.partial_facts("PI-01", facts, {}))

    def test_previous_projection_state_is_rejected_without_rewriting_it(self):
        with tempfile.TemporaryDirectory(prefix="eleven-old-projection-") as directory:
            root = Path(directory).resolve()
            path = root / "state.json"
            for version in ("1.0.0", "1.0.1", "1.3.0"):
                original = json.dumps({"schema_version": 1, "producer": "eleven-row-handoff/" + version,
                                       "captured_at": "2026-01-01T00:00:00Z", "paths": {}, "files": {}}).encode()
                path.write_bytes(original)
                with self.subTest(version=version), self.assertRaisesRegex(ValueError, "Unknown eleven-row state"):
                    tool.open_state(root, path)
                self.assertEqual(path.read_bytes(), original)

    def test_lp04_inventory_binding_and_bounded_display(self):
        from oracles.lp04_dlite_expectations import inventory, result, EMPTY
        assets = [("staticwebassets/" + str(i).zfill(3) + "-" + "x" * 90 + ".js", b"x")
                  for i in range(512)]
        value = result("origin-review-missing", [], inventory(assets))
        rows.checked_result(value, [])
        defaults = {row: next(item for item in frozen_results() if item["row_id"] == row)
                    for row in rows.ROWS}
        defaults["LP-04"] = value
        output = rows.decisions(defaults, empty_observations(), {}, {row: [] for row in rows.ROWS})
        row = next(item for item in output["rows"] if item["id"] == "LP-04")
        self.assertEqual(row["status"], "not tested")
        self.assertIn("512 assets", row["observation"])
        self.assertIn(value["bundled_web_assets"]["inventory_sha256"], row["observation"])
        self.assertLessEqual(len(row["observation"].encode()), 4096)
        self.assertTrue(row["assessment_follow_up"])
        self.assertIsNone(row["not_applicable_rationale"])
        empty = result("no-supported-layout-assets", [], inventory([]))
        defaults["LP-04"] = empty
        row = next(item for item in rows.decisions(defaults, empty_observations(), {},
                   {r: [] for r in rows.ROWS})["rows"] if item["id"] == "LP-04")
        self.assertIn(EMPTY, row["observation"])
        self.assertEqual(row["status"], "not tested")
        for change in (
            lambda v: v.pop("bundled_web_assets"),
            lambda v: v["bundled_web_assets"].update(inventory_sha256="0" * 64),
            lambda v: v["bundled_web_assets"]["assets"].reverse(),
            lambda v: v["bundled_web_assets"]["assets"][0].update(length=2),
            lambda v: v.update(branch_id="no-applicable-surface"),
            lambda v: v.update(decision="deterministic", applicability="not-applicable"),
        ):
            changed = copy.deepcopy(value)
            change(changed)
            with self.assertRaises(ValueError):
                rows.checked_result(changed, [])

    def test_fingerprints_and_policy_bytes(self):
        sibling = SCRIPTS
        pins = tool.load(tool.DATA / "resolver-files.json")
        actual = {p.relative_to(sibling).as_posix() for p in sibling.rglob("*")
                  if p.is_file() and (p.name == "run-resolver.py" or p.relative_to(sibling).parts[0] == "resolver")
                  and not any(part in ("bin", "obj", "__pycache__") for part in p.relative_to(sibling).parts)}
        self.assertEqual(set(pins), actual)
        for path, digest in pins.items():
            self.assertEqual(tool.sha(tool.read(tool.beneath(sibling, path))), digest, path)
        for path, digest in tool.POLICIES.items():
            self.assertEqual(tool.sha(tool.read(tool.DATA / path)), digest)


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eleven-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.capture = self.root / "capture"
        self.capture.mkdir()
        self.package = self.root / "package.nupkg"
        self.package.write_bytes(package())

    def collector(self, online=True, attempts=64, transport=None, nuget_feed="nuget.org"):
        def unexpected(*args):
            raise AssertionError("Unexpected network acquisition")
        return tool.Collector(self.root, self.capture, attempts, online, transport or unexpected, nuget_feed)

    def test_locator_allowlist(self):
        good = "https://api.nuget.org/v3-flatcontainer/a/1.0.0/a.1.0.0.nupkg"
        tool.allowed_url(good)
        for bad in (good.replace("https:", "http:"), good + "?secret=1", good + "#fragment",
                    good.replace("api.nuget.org", "api.nuget.org.evil.test"),
                    good.replace("api.nuget.org", "api.nuget.org:443"),
                    good.replace("api.nuget.org", "user:password@api.nuget.org"),
                    good.replace("api.nuget.org", "127.0.0.1"), good.replace("/a/", "/../"),
                    good.replace("/a/", "/%61/"), good.replace("api.nuget.org", "api.nuget.org.")):
            with self.subTest(url=bad), self.assertRaises(ValueError):
                tool.allowed_url(bad)

    def test_no_redirect_following_or_environment_proxy(self):
        self.assertIsNone(tool.NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.test"))
        with mock.patch.object(tool.urllib.request, "build_opener") as build:
            response = mock.MagicMock()
            response.status, response.headers = 200, {}
            response.read.side_effect = [b"abc", b""]
            response.__enter__.return_value = response
            build.return_value.open.return_value = response
            receipt = tool.fetch_worker("https://codeload.github.com/example/controls/zip/" + "1" * 40,
                                        self.capture / "response.zip", tool.SOURCE_LIMIT)
            self.assertEqual(receipt["result"], "succeeded")
            self.assertEqual(build.call_args.args[0].proxies, {})
            self.assertIsInstance(build.call_args.args[1], tool.NoRedirect)
            request = build.return_value.open.call_args.args[0]
            self.assertEqual(request.get_header("Accept-encoding"), "identity")
            self.assertFalse(request.has_header("Authorization"))

    def test_only_the_named_azure_feed_and_provider_blob_redirect_are_admitted(self):
        source = tool.NUGET_FEEDS["dotnet-public"] + "/a/1.0.0/a.1.0.0.nupkg"
        blob = "https://abc.vsblob.vsassets.io/b-" + "a" * 32 + "/" + "B" * 66 + ".blob?sig=private"
        self.assertEqual(tool.allowed_url(source), source)
        self.assertEqual(tool.azure_blob_url(source, blob), blob)
        for bad in (source.replace("pkgs.dev.azure.com", "pkgs.dev.azure.com.evil.test"),
                    source.replace("/dnceng/", "/other/"), source.replace("45bacae2", "00000000"),
                    source + "?secret=1", blob):
            with self.subTest(url=bad), self.assertRaises(ValueError):
                tool.allowed_url(bad)
        for bad in (blob.replace("abc.vsblob.vsassets.io", "localhost"),
                    blob.replace(".io/", ".io.evil.test/"), blob.replace(".io/", ".io:443/"),
                    blob.replace("https://", "https://user:password@"),
                    blob.replace("https://", "http://"), blob + "#fragment",
                    blob.replace("/b-", "/../b-"), blob.replace("?sig=private", ""),
                    blob + "\n"):
            with self.subTest(url=bad), self.assertRaises(ValueError):
                tool.azure_blob_url(source, bad)
        with self.assertRaises(ValueError):
            tool.azure_blob_url(tool.NUGET_FEEDS["nuget.org"] + "/a/1.0.0/a.1.0.0.nupkg", blob)

    def test_azure_download_records_both_hops_without_signed_url_or_credentials(self):
        source = tool.NUGET_FEEDS["dotnet-public"] + "/a/1.0.0/a.1.0.0.nupkg"
        blob = "https://abc.vsblob.vsassets.io/b-" + "a" * 32 + "/" + "B" * 66 + ".blob?sig=private"
        redirect = tool.urllib.error.HTTPError(source, 303, "Redirect", {"Location": blob}, None)
        with mock.patch.object(tool.urllib.request, "build_opener") as build:
            response = mock.MagicMock()
            response.status, response.headers = 200, {}
            response.read.side_effect = [b"abc", b""]
            response.__enter__.return_value = response
            build.return_value.open.side_effect = [redirect, response]
            result = tool.fetch_worker(source, self.capture / "azure.nupkg", tool.PACKAGE_LIMIT)
            self.assertEqual(result["result"], "succeeded")
            self.assertEqual([hop["http_status"] for hop in result["http_requests"]], [303, 200])
            self.assertNotIn("sig=", json.dumps(result))
            self.assertNotIn("private", json.dumps(result))
            self.assertEqual(build.call_args.args[0].proxies, {})
            for call in build.return_value.open.call_args_list:
                self.assertFalse(call.args[0].has_header("Authorization"))

    def test_redirect_rejection_no_chains_and_blob_errors_do_not_leak_signed_queries(self):
        source = tool.NUGET_FEEDS["dotnet-public"] + "/a/1.0.0/a.1.0.0.nupkg"
        blob = "https://abc.vsblob.vsassets.io/b-" + "a" * 32 + "/" + "B" * 66 + ".blob?sig=private"
        scenarios = (
            ("wrong-host", source, "https://evil.test/blob?sig=private", None, "invalid-content", 1),
            ("ordinary-feed", tool.NUGET_FEEDS["nuget.org"] + "/a/1.0.0/a.1.0.0.nupkg", blob, None, "unavailable", 1),
            ("second-redirect", source, blob,
             tool.urllib.error.HTTPError(blob, 307, "Redirect again", {"Location": blob}, None), "unavailable", 2),
            ("blob-error", source, blob, tool.urllib.error.URLError("failure at " + blob), "network-failure", 2),
        )
        for label, initial, target, second, result, count in scenarios:
            with self.subTest(label=label), mock.patch.object(tool.urllib.request, "build_opener") as build:
                first = tool.urllib.error.HTTPError(initial, 303, "Redirect", {"Location": target}, None)
                build.return_value.open.side_effect = [first] + ([second] if second else [])
                receipt = tool.fetch_worker(initial, self.capture / (label + ".nupkg"), tool.PACKAGE_LIMIT)
                self.assertEqual(receipt["result"], result)
                self.assertEqual(build.return_value.open.call_count, count)
                self.assertEqual(len(receipt["http_requests"]), count)
                self.assertNotIn("sig=", json.dumps(receipt))
                self.assertNotIn("private", json.dumps(receipt))
                self.assertFalse((self.capture / (label + ".nupkg")).exists())

    def test_dotnet_public_dependency_selection_uses_the_confirmed_feed(self):
        self.package.write_bytes(package(dependencies=(
            '<dependencies><dependency id="A" version="[1.0.0]"/></dependencies>')))
        calls = []

        def transport(url, destination, *args):
            calls.append(url)
            destination.write_bytes(package("A"))
            return {"result": "succeeded", "detail_code": "stub", "http_status": 200}

        collector = self.collector(transport=transport, nuget_feed="dotnet-public")
        output = collector.collect(self.package, tool.package_metadata(self.package.read_bytes()), None, [], source_allowed=False)
        self.assertEqual(calls, [tool.NUGET_FEEDS["dotnet-public"] + "/a/1.0.0/a.1.0.0.nupkg"])
        self.assertEqual(output["nuget_feed"], "dotnet-public")
        self.assertEqual(set(collector.dependencies), {("a", "1.0.0")})

    def test_hard_deadline_kills_only_download_worker(self):
        with mock.patch.object(tool.subprocess, "run", side_effect=subprocess.TimeoutExpired("worker", 1)):
            result = tool.fetch("https://codeload.github.com/example/controls/zip/" + "1" * 40,
                                self.capture / "timeout.zip", tool.SOURCE_LIMIT, 0.1)
        self.assertEqual(result["detail_code"], "absolute-deadline")

    def test_offline_never_calls_transport(self):
        dep = self.root / "dependency.nupkg"
        dep.write_bytes(package("Example.Dependency"))
        collector = self.collector(online=False)
        with mock.patch("socket.socket", side_effect=AssertionError("Offline socket use")):
            output = collector.collect(self.package, tool.package_metadata(self.package.read_bytes()), None, [dep])
        self.assertEqual(len(collector.dependencies), 1)
        self.assertEqual(output["attempts"][0]["method"], "local-file")
        self.assertFalse(output["attempts"][0]["request_sent"])

    def test_single_public_fetch_produces_a_bound_lp02_observation(self):
        calls = []
        source = archive({"controls-" + "1" * 40 + "/src/Controls.csproj": (
            b'<Project Sdk="Microsoft.NET.Sdk.Razor"><PropertyGroup Condition="true">'
            b"<PackageId>Example.Controls</PackageId></PropertyGroup></Project>")})
        observed_at = "2026-10-30T12:00:00Z"

        def transport(url, destination, *args):
            calls.append(url)
            destination.write_bytes(source)
            return {"result": "succeeded", "detail_code": "http-200", "http_status": 200,
                    "http_requests": [{"host": "codeload.github.com", "attempted_at_utc": observed_at,
                                       "http_status": 200}]}

        collector = self.collector(transport=transport)
        metadata = tool.package_metadata(self.package.read_bytes())
        collector.collect(self.package, metadata, None, [])
        copied = self.capture / "package.nupkg"
        copied.write_bytes(self.package.read_bytes())
        _, request = tool.requests(self.root, self.capture, copied, metadata, collector, None)
        case = next(case for case in request["cases"] if case["row_id"] == "LP-02")
        self.assertEqual(len(calls), 1)
        pins = {item["role"]: item for item in case["inputs"]}
        self.assertEqual(set(pins), {"package", "source-archive", "source-observation"})
        observation = tool.load(tool.beneath(self.capture, pins["source-observation"]["path"]))
        self.assertEqual(observation["package_id"], "Example.Controls")
        self.assertEqual(observation["package_sha256"], pins["package"]["sha256"])
        self.assertEqual(observation["capture_receipt"]["sha256"], pins["source-archive"]["sha256"])
        self.assertEqual(observation["retrieval_attempt"]["observed_at_utc"], observed_at)
        self.assertEqual(observation["retrieval_attempt"]["url"], calls[0])
        self.assertEqual(observation["source_inventory"], [])
        # Isolate retained-byte accounting from the separate repeated-input occurrence cap.
        extra_retained = ((len(rows.ROWS) - 1) * self.package.stat().st_size
                          + sum((tool.DATA / name).stat().st_size for name in tool.POLICIES))
        reserved = (collector.total + extra_retained + sum((tool.DATA / name).stat().st_size for name in tool.POLICIES)
                    + (self.capture / "lp-03-scope.json").stat().st_size)
        observation_size = (self.capture / "source-observation.json").stat().st_size
        for adjustment in (-1, 0):
            other = self.root / f"budget-capture{adjustment}"
            other.mkdir()
            other_package = other / "package.nupkg"
            other_package.write_bytes(self.package.read_bytes())
            bounded = tool.Collector(self.root, other, 64, True, transport)
            bounded.collect(other_package, metadata, None, [])
            bounded.total += extra_retained
            with self.subTest(budget_adjustment=adjustment), mock.patch.object(
                    tool, "TOTAL_LIMIT", reserved + observation_size + adjustment):
                if adjustment < 0:
                    with self.assertRaisesRegex(ValueError, "Combined checked input bytes"):
                        tool.requests(self.root, other, other_package, metadata, bounded, None)
                else:
                    tool.requests(self.root, other, other_package, metadata, bounded, None)

    def test_local_missing_failed_and_skipped_source_never_becomes_public_capture(self):
        source = self.root / "source.zip"
        source.write_bytes(archive({"controls-" + "1" * 40 + "/README.md": b"retained"}))
        metadata = tool.package_metadata(self.package.read_bytes())
        for label in ("local-online", "local-offline", "missing-offline", "failed", "budget", "closed"):
            with self.subTest(label=label):
                capture = self.root / label
                capture.mkdir()
                calls = []

                def transport(url, *args):
                    calls.append(url)
                    return {"result": "not-found", "detail_code": "http-status", "http_status": 404}

                collector = tool.Collector(self.root, capture, 0 if label == "budget" else 64,
                                           "offline" not in label, transport)
                collector.collect(self.package, metadata, source if label.startswith("local") else None, [],
                                  source_allowed=label != "closed")
                copied = capture / "package.nupkg"
                copied.write_bytes(self.package.read_bytes())
                _, request = tool.requests(self.root, capture, copied, metadata, collector, None)
                case = next(case for case in request["cases"] if case["row_id"] == "LP-02")
                self.assertNotIn("source-observation", {item["role"] for item in case["inputs"]})
                self.assertFalse((capture / "source-observation.json").exists())
                self.assertEqual(len(calls), 1 if label == "failed" else 0)

    def test_source_observation_rejects_tampered_or_incomplete_capture_records(self):
        source = archive({"controls-" + "1" * 40 + "/README.md": b"source"})

        def transport(url, destination, *args):
            destination.write_bytes(source)
            return {"result": "succeeded", "detail_code": "http-200", "http_status": 200,
                    "http_requests": [{"host": "codeload.github.com", "attempted_at_utc": "2026-10-30T12:00:00Z",
                                       "http_status": 200}]}

        collector = self.collector(transport=transport)
        metadata = tool.package_metadata(self.package.read_bytes())
        collector.collect(self.package, metadata, None, [])
        original = copy.deepcopy(collector.records)
        for field, value in (("sha256", "0" * 64), ("locator", tool.source_url(metadata) + "0"),
                             ("http_status", 403), ("request_sent", False), ("result", "invalid-content"),
                             ("http_requests", None), ("http_requests", []),
                             ("http_requests", [{"host": "evil.test", "http_status": 200}]),
                             ("http_requests", [{"host": "codeload.github.com", "http_status": 200,
                                                  "attempted_at_utc": "2026-02-31T12:00:00Z"}])):
            collector.records = copy.deepcopy(original)
            collector.records[0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                tool.source_observation(self.root, self.capture, self.package, metadata, collector)
            self.assertFalse((self.capture / "source-observation.json").exists())
        collector.records = original
        collector.source.write_bytes(source + b"changed")
        with self.assertRaisesRegex(ValueError, "bound anonymous"):
            tool.source_observation(self.root, self.capture, self.package, metadata, collector)

    def test_exact_and_minimum_walk_ranges_groups_cycles_and_dedup(self):
        dependencies = ('<dependencies><group targetFramework="net8.0">'
                        '<dependency id="A" version="[1.0.0]"/><dependency id="B" version="1.0.0"/>'
                        '<dependency id="C" version="[1.0.0,2.0.0)"/><dependency id="D" version="1.*"/>'
                        '</group><group targetFramework="net9.0"><dependency id="B" version="1.0.0"/></group></dependencies>')
        self.package.write_bytes(package(dependencies=dependencies))
        calls = []

        def transport(url, destination, maximum, seconds):
            calls.append(url)
            package_id = url.split("/")[-3]
            child = ('<dependencies><dependency id="Example.Controls" version="1.0.0"/>'
                     '<dependency id="B" version="1.0.0"/></dependencies>') if package_id == "a" else ""
            destination.write_bytes(package(package_id, dependencies=child))
            return {"result": "succeeded", "detail_code": "stub", "http_status": 200}

        collector = self.collector(transport=transport)
        # Retained source avoids a separate transport request in this unit test.
        source = self.root / "source.zip"
        source.write_bytes(archive({"controls-" + "1" * 40 + "/README.md": b"source"}))
        output = collector.collect(self.package, tool.package_metadata(self.package.read_bytes()), source, [])
        self.assertEqual(len(calls), 2)
        self.assertEqual(set(collector.dependencies), {("a", "1.0.0"), ("b", "1.0.0")})
        self.assertTrue(any(edge["selection_basis"] == "exact-declaration" for edge in output["declaration_sample_edges"]))
        self.assertTrue(any(edge["selection_basis"] == "literal-minimum-sample" for edge in output["declaration_sample_edges"]))
        self.assertEqual(sum("Unsupported range" in edge.get("limitation", "") for edge in output["declaration_sample_edges"]), 2)

    def test_failed_candidate_is_not_retried_for_other_framework(self):
        self.package.write_bytes(package(dependencies=(
            '<dependencies><group targetFramework="net8.0"><dependency id="A" version="1.0.0"/></group>'
            '<group targetFramework="net9.0"><dependency id="A" version="1.0.0"/></group></dependencies>')))
        calls = []

        def transport(url, *args):
            calls.append(url)
            return {"result": "not-found", "detail_code": "http-status", "http_status": 404}

        collector = self.collector(transport=transport)
        collector.collect(self.package, tool.package_metadata(self.package.read_bytes()), None, [])
        self.assertEqual(len([url for url in calls if "flatcontainer" in url]), 1)

    def test_budgets_and_wrong_identity(self):
        collector = self.collector(attempts=0)
        self.assertIsNone(collector.obtain("package", "no.nupkg", tool.PACKAGE_LIMIT, url="https://api.nuget.org/v3-flatcontainer/a/1.0.0/a.1.0.0.nupkg"))
        self.assertIn("budget", collector.diagnostics[0])

        def transport(url, destination, *args):
            destination.write_bytes(package("Wrong.Identity"))
            return {"result": "succeeded", "detail_code": "stub", "http_status": 200}

        collector = self.collector(transport=transport)
        self.assertIsNone(collector.obtain("package", "wrong.nupkg", tool.PACKAGE_LIMIT,
                                          url="https://api.nuget.org/v3-flatcontainer/a/1.0.0/a.1.0.0.nupkg", identity=("a", "1.0.0")))
        self.assertEqual(collector.records[0]["result"], "invalid-content")
        self.assertTrue((self.capture / "wrong.nupkg").exists())
        self.assertEqual(collector.total, (self.capture / "wrong.nupkg").stat().st_size)
        collector.total = tool.TOTAL_LIMIT - tool.PACKAGE_LIMIT + 1
        self.assertIsNone(collector.obtain("package", "large.nupkg", tool.PACKAGE_LIMIT, local=self.package))

    def test_failed_partial_download_never_reuses_another_attempts_file(self):
        self.package.write_bytes(package(dependencies=(
            '<dependencies><dependency id="A" version="1.0.0"/><dependency id="B" version="1.0.0"/></dependencies>')))
        destinations = []

        def transport(url, destination, *args):
            destinations.append(destination)
            if "codeload" in url:
                return {"result": "not-found", "detail_code": "stub", "http_status": 404}
            destination.write_bytes(b"partial body")
            return {"result": "network-failure", "detail_code": "stub-disconnect", "http_status": None}

        collector = self.collector(transport=transport)
        collector.collect(self.package, tool.package_metadata(self.package.read_bytes()), None, [])
        self.assertEqual(len(destinations), len(set(destinations)))
        self.assertEqual(len(collector.dependencies), 0)
        self.assertEqual([r["bytes_received"] for r in collector.records], [0, 12, 12])
        self.assertEqual(collector.total, self.package.stat().st_size + 24)

    def test_partial_outcomes_consume_collection_byte_budget(self):
        source = self.root / "source.zip"
        source.write_bytes(b"partial source")
        collector = self.collector(online=False)
        with mock.patch.object(tool, "TOTAL_LIMIT", tool.PACKAGE_LIMIT + source.stat().st_size - 1):
            self.assertIsNone(collector.obtain("source", "invalid-source.zip", tool.SOURCE_LIMIT, local=source))
            collector.total = tool.PACKAGE_LIMIT - 1
            self.assertIsNone(collector.obtain("package", "invalid-package.nupkg", tool.PACKAGE_LIMIT, local=source))
        # Isolate retained failed bytes from the per-attempt maximum reservation.
        self.assertIsNone(collector.obtain("package", "partial.nupkg", tool.PACKAGE_LIMIT, local=source))
        self.assertEqual(collector.total, tool.PACKAGE_LIMIT - 1 + source.stat().st_size)
        with mock.patch.object(tool, "TOTAL_LIMIT", collector.total + tool.PACKAGE_LIMIT - 1):
            self.assertIsNone(collector.obtain("package", "blocked.nupkg", tool.PACKAGE_LIMIT, local=self.package))
        self.assertFalse((self.capture / "blocked.nupkg").exists())

    def test_supplied_packets_copy_checked_pins_and_enforce_remaining_bytes(self):
        packets = self.root / "packets"
        packets.mkdir()
        content = b'{"retained":"actual packet bytes"}'
        (packets / "packet.json").write_bytes(content)
        request = packets / "request.json"
        tool.dump(request, {"schema_version": 1, "cases": [{
            "case_id": "supplied-lp02", "row_id": "LP-02", "inputs": [
                {"role": "package", "path": "../package.nupkg", "sha256": tool.sha(self.package.read_bytes())}
            ]}]})
        collector = self.collector(online=False)
        collector.total = self.package.stat().st_size
        copy = self.capture / "package.nupkg"
        copy.write_bytes(self.package.read_bytes())
        metadata = tool.package_metadata(copy.read_bytes())
        with self.assertRaisesRegex(ValueError, "Noncanonical"):
            tool.requests(self.root, self.capture, copy, metadata, collector, request)
        pins = [{"role": "observation", "path": "packet.json", "sha256": tool.sha(content)}]
        request.write_text(json.dumps({"schema_version": 1, "cases": [
            {"case_id": "supplied-lp02", "row_id": "LP-02", "inputs": pins}]}))
        packet_base = collector.total + sum((tool.DATA / name).stat().st_size for name in tool.POLICIES)
        for label, digest, budget, succeeds in (
                ("valid", tool.sha(content), tool.TOTAL_LIMIT, True),
                ("wrong-digest", "0" * 64, tool.TOTAL_LIMIT, False),
                ("over-budget", tool.sha(content), packet_base + len(content) - 1, False)):
            with self.subTest(label=label):
                capture = self.root / label
                capture.mkdir()
                copied = capture / "package.nupkg"
                copied.write_bytes(copy.read_bytes())
                pins[0]["sha256"] = digest
                request.write_text(json.dumps({"schema_version": 1, "cases": [
                    {"case_id": "supplied-lp02", "row_id": "LP-02", "inputs": pins}]}))
                with mock.patch.object(tool, "TOTAL_LIMIT", budget):
                    if succeeds:
                        _, resolve = tool.requests(self.root, capture, copied, metadata, collector, request)
                        chosen = next(case for case in resolve["cases"] if case["row_id"] == "LP-02")
                        self.assertEqual(tool.read(tool.beneath(capture, chosen["inputs"][0]["path"])), content)
                        self.assertEqual(chosen["inputs"][0]["sha256"], tool.sha(content))
                    else:
                        with self.assertRaises(ValueError):
                            tool.requests(self.root, capture, copied, metadata, collector, request)
                        self.assertFalse((capture / "packet-lp-02-000.bin").exists())

    def test_closed_source_suppresses_only_source_and_sixty_four_dependency_cap(self):
        declarations = "".join(f'<dependency id="D{number:02}" version="1.0.0"/>' for number in range(65))
        self.package.write_bytes(package(dependencies=f"<dependencies>{declarations}</dependencies>"))
        calls = []

        def transport(url, destination, *args):
            self.assertNotIn("codeload", url)
            calls.append(url)
            destination.write_bytes(package(url.split("/")[-3]))
            return {"result": "succeeded", "detail_code": "stub", "http_status": 200}

        # A unit-level larger attempt budget isolates the inspector's independent 64-version cap.
        collector = self.collector(attempts=100, transport=transport)
        output = collector.collect(self.package, tool.package_metadata(self.package.read_bytes()), None, [], source_allowed=False)
        self.assertEqual(len(collector.dependencies), 64)
        self.assertEqual(len(calls), 64)
        self.assertTrue(any("64 dependency" in edge.get("limitation", "") for edge in output["declaration_sample_edges"]))

    def test_unsafe_archives_dtd_and_immutable_outputs(self):
        for name in ("../escape", "/absolute", "a\\b", " a.txt", "a/../b", "a:stream"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                tool.archive_inventory(archive({name: b"x"}))
        link = zipfile.ZipInfo("symlink")
        link.external_attr = 0o120777 << 16
        with self.assertRaises(ValueError):
            tool.archive_inventory(archive({link: b"target"}))
        with self.assertRaises(ValueError):
            tool.package_metadata(archive({"a.nuspec": b'<!DOCTYPE x><package/>'}))
        with self.assertRaises(ValueError):
            tool.archive_inventory(b"x" * (tool.PACKAGE_LIMIT + 1))
        path = self.capture / "immutable.json"
        tool.dump(path, {"original": True})
        with self.assertRaises(FileExistsError):
            tool.dump(path, {"replacement": True})
        self.assertEqual(tool.load(path), {"original": True})

    def test_saved_artifact_tampering_is_rejected(self):
        original = self.root / "result.json"
        tool.dump(original, {"finding": "original"})
        state = self.root / "state.json"
        tool.dump(state, {"schema_version": 1, "producer": rows.VERSION, "captured_at": tool.utc(),
                          "paths": {"results": "result.json"}, "files": {"result.json": tool.sha(original.read_bytes())}})
        tool.open_state(self.root, state)
        original.write_text('{"finding":"invented"}')
        with self.assertRaisesRegex(ValueError, "Changed retained"):
            tool.open_state(self.root, state)

    def test_bind_and_continue_command_verify_expected_digests_and_sixty_rows(self):
        scratch = self.root / "scratch"
        scratch.mkdir()
        tools = tool.Tools(self.root, scratch)
        row_ids = tool.package_row_ids(tools)
        self.assertEqual(len(row_ids), 60)
        self.assertTrue(all(row_id in row_ids for row_id in rows.ROWS))
        copied = self.capture / "package.nupkg"
        copied.write_bytes(self.package.read_bytes())
        metadata = tool.package_metadata(copied.read_bytes())
        collector = self.collector(online=False)
        collector.total = copied.stat().st_size
        inspection_req, resolve_req = tool.requests(self.root, self.capture, copied, metadata, collector, None)
        outputs = {
            "acquisition": self.capture / "acquisition.json",
            "inspection_request": self.capture / "inspection-request.json",
            "resolve_request": self.capture / "resolve-request.json",
            "results": self.capture / "results.json",
            "observations": self.capture / "observations.json",
        }
        tool.dump(outputs["acquisition"], {"schema_version": 1, "producer": rows.VERSION,
                                           "package": {"path": "capture/package.nupkg",
                                                       "sha256": tool.sha(copied.read_bytes())},
                                           "nuget_feed": "nuget.org", "attempts": [], "diagnostics": []})
        cases = []
        valid_branches = {
            "LP-01": "approved-non-copyleft", "LP-02": "observation-missing", "LP-03": "scope-missing",
            "LP-04": "no-supported-layout-assets", "LP-05": "expression", "LP-06": "populated",
            "LP-07": "full-sha1", "LP-08": "populated", "LP-09": "populated",
            "LP-10": "missing-package", "PI-01": "verified-signed",
        }
        for item in resolve_req["cases"]:
            rid = item["row_id"]
            pins = item["inputs"]
            refs = [f"input:{p['role']}:{p['sha256']}" for p in pins]
            branch = valid_branches[rid]
            escalated = rid in ("LP-02", "LP-03", "LP-04", "LP-10")
            res = {"row_id": rid, "resolver_id": rows.RESOLVERS[rid], "resolver_version": rows.RESOLVER_VERSIONS[rid],
                   "decision": "escalated" if escalated else "deterministic", "applicability": "applicable",
                   "branch_id": branch, "evidence_contract": "unit-contract/1",
                   "finding": None if escalated else f"Unit stub finding for {rid}.",
                   "missing_fact": f"Missing fact for {rid}." if escalated else None,
                   "required_input": "evidence" if escalated else None,
                   "next_category": "evidence" if escalated else None,
                   "inputs": pins, "evidence_references": refs}
            if rid == "LP-04":
                res["bundled_web_assets"] = {
                    "profile": "bundled-web-assets/1", "assets": [], "unsupported_candidates": [],
                    "inventory_sha256": tool.sha(b"bundled-web-assets/1\n")}
            cases.append({"case_id": item["case_id"], "result": res})
        results_bytes = (json.dumps({"schema_version": 1, "cases": cases}, indent=2) + "\n").encode()
        obs_doc = {"schema_version": 1, "producer": "package-evidence-observations/1.1.0",
                   "inputs": inspection_req, **empty_observations()}
        obs_bytes = (json.dumps(obs_doc, indent=2) + "\n").encode()
        outputs["results"].write_bytes(results_bytes)
        outputs["observations"].write_bytes(obs_bytes)
        expected = {"results": tool.sha(results_bytes), "observations": tool.sha(obs_bytes)}
        bound, captured_at = tool.bind(tools, self.root, scratch, self.package, outputs,
                                       expected_digests=expected)
        bad_dir = self.root / "bad-digest"
        bad_dir.mkdir()
        with self.assertRaisesRegex(ValueError, "Trusted results output changed before binding"):
            tool.bind(tools, self.root, bad_dir, self.package, outputs,
                      expected_digests={"results": "0" * 64, "observations": expected["observations"]})
        assessment = tool.load(bound["assessment"])
        self.assertEqual(len(assessment["rows"]), 60)
        self.assertEqual(assessment["selected_ids"], row_ids)
        state_path = tool.save_state(self.root, scratch, outputs, bound, captured_at)
        checked = tool.continue_command(tool.argparse.Namespace(
            root=str(self.root), state=str(state_path), assessment=str(bound["assessment"])), self.root)
        self.assertEqual(checked, {"checked_rows": 11, "unchanged": True, "completion_claim": False})
        for label, mutate, expected_err in (
            ("missing_producer", lambda d: d.pop("producer"), "missing or unexpected top-level fields"),
            ("extra_field", lambda d: d.update(extra=True), "missing or unexpected top-level fields"),
            ("changed_producer", lambda d: d.update(producer="forged/1.0"), "changed schema_version or producer"),
            ("changed_schema", lambda d: d.update(schema_version=2), "changed schema_version or producer"),
            ("bool_schema", lambda d: d.update(schema_version=True), "changed schema_version or producer"),
            ("float_schema", lambda d: d.update(schema_version=1.0), "changed schema_version or producer"),
            ("bad_findings", lambda d: d.update(findings="not-a-list"), "findings and summary_groups must be lists"),
        ):
            bad_doc = json.loads(json.dumps(assessment))
            mutate(bad_doc)
            bad_path = self.root / f"bad-{label}.json"
            bad_path.write_text(json.dumps(bad_doc), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, expected_err):
                tool.continue_command(tool.argparse.Namespace(
                    root=str(self.root), state=str(state_path), assessment=str(bad_path)), self.root)


if __name__ == "__main__":
    unittest.main()
