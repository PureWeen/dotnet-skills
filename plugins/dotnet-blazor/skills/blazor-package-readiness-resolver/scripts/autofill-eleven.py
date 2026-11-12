#!/usr/bin/env python3
"""Collect bounded static inputs and produce a resumable eleven-row package draft; no model calls."""
import argparse
import base64
from collections import deque
from copy import copy
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
from eleven_rows import VERSION, ROWS, checked_result, decisions

MIB = 1024 * 1024
PACKAGE_LIMIT = 8 * MIB
SBOM_LIMIT = MIB
SBOM_ZIP_LIMIT = SBOM_LIMIT + 65536
SOURCE_LIMIT = 64 * MIB
TOTAL_LIMIT = 256 * MIB
NUGET_FEEDS = {
    "nuget.org": "https://api.nuget.org/v3-flatcontainer",
    "dotnet-public": (
        "https://pkgs.dev.azure.com/dnceng/9ee6d478-d288-47f7-aacc-f6e6d082ae6d/"
        "_packaging/45bacae2-5efb-47c8-91e5-8ec20c22b4f8/nuget/v3/flat2"),
}
ID = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}\Z", re.ASCII)
NUMBER = r"(?:0|[1-9][0-9]{0,4})"
VER = re.compile(NUMBER + r"(?:\." + NUMBER + r"){2}\Z", re.ASCII)
RELATIVE = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\Z", re.ASCII)
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
DATA = Path(__file__).absolute().parent / "eleven-row-data"
POLICIES = {
    "policy.json": "b395256c51e7c0ae68bf3a213aab90bee0479f6115c3507e456269d0cdd41f47",
    "corpus.json": "157789ba91984aecba5c67b84168dbbd41a235b910a7569aa64bf42a88b24290",
}


class ToolFailure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def regular(path, directory=False):
    path = Path(os.path.abspath(path))
    for item in reversed((path, *path.parents)):
        if not item.exists():
            raise ValueError(f"Missing path: {item}")
        info = item.lstat()
        require(not item.is_symlink() and not getattr(info, "st_file_attributes", 0) &
                stat.FILE_ATTRIBUTE_REPARSE_POINT, f"Linked paths are unsupported: {item}")
    require(path.is_dir() if directory else path.is_file(), f"Not a regular {'directory' if directory else 'file'}: {path}")
    return path


def read(path, maximum=64 * MIB):
    path = regular(path)
    require(path.stat().st_size <= maximum, f"Input exceeds {maximum} bytes: {path.name}")
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, f"Input grew beyond its bound: {path.name}")
    return data


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate JSON property.")
        value[key] = item
    return value


def load(path, maximum=4 * MIB):
    return json.loads(read(path, maximum), object_pairs_hook=unique,
                      parse_constant=lambda value: require(False, "Nonfinite JSON value."))


def write(path, data):
    regular(path.parent, directory=True)
    with path.open("xb") as stream:
        stream.write(data)


def dump(path, value):
    data = (json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode()
    require(len(data) <= 4 * MIB, f"Output exceeds 4 MiB: {path.name}")
    write(path, data)


def beneath(root, relative):
    require(isinstance(relative, str) and len(relative) <= 256 and RELATIVE.fullmatch(relative) and
            all(part not in (".", "..") for part in relative.split("/")), "Noncanonical retained path.")
    return root.joinpath(*relative.split("/"))


def pin(root, path, role):
    return {"role": role, "path": path.relative_to(root).as_posix(), "sha256": sha(read(path))}


def package_metadata(data):
    """Bounded discovery only; the bundled native inspector still owns final admission."""
    inventory = archive_inventory(data)
    names = [name for name in inventory if "/" not in name and name.lower().endswith(".nuspec")]
    require(len(names) == 1, "Package needs one root nuspec.")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        xml = archive.read(names[0])
    require(len(xml) <= MIB, "Nuspec exceeds 1 MiB.")
    text = xml.decode("utf-8-sig")
    require(not re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.I), "DTD or entity declaration is unsupported.")
    encoding = re.match(r"""<\?xml\s+[^?]*?\bencoding\s*=\s*['"]([^'"]+)['"]""", text, re.I)
    require(encoding is None or encoding[1].lower().replace("-", "") == "utf8", "Unsupported XML encoding.")
    document = ET.fromstring(text)
    namespaces = ("", "{http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd}",
                  "{http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd}",
                  "{http://schemas.microsoft.com/packaging/2011/10/nuspec.xsd}",
                  "{http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd}",
                  "{http://schemas.microsoft.com/packaging/2013/01/nuspec.xsd}",
                  "{http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd}")
    namespace = next((ns for ns in namespaces if document.tag == ns + "package"), None)
    require(namespace is not None, "Unrecognized NuGet namespace.")
    metadata = [child for child in document if child.tag.split("}")[-1] == "metadata"]
    require(len(metadata) == 1 and metadata[0].tag == namespace + "metadata", "Ambiguous package metadata.")
    metadata = metadata[0]

    def field(name):
        elements = [child for child in metadata if child.tag.split("}")[-1] == name]
        require(len(elements) == 1 and elements[0].tag == namespace + name and not len(elements[0]),
                f"Ambiguous package {name}.")
        return elements[0].text or ""

    declared_id, version = field("id"), field("version")
    package_id = declared_id.lower()
    require(ID.fullmatch(package_id) and VER.fullmatch(version), "Unsupported package identity or version.")
    repositories = [child for child in metadata if child.tag == namespace + "repository"]
    repository = repositories[0].attrib if len(repositories) == 1 else {}
    groups, dependencies = set(), []
    for declarations in metadata.findall(namespace + "dependencies"):
        for item in declarations:
            children = list(item) if item.tag == namespace + "group" else [item]
            framework = item.get("targetFramework") if item.tag == namespace + "group" else None
            if framework is not None:
                groups.add(framework)
            for child in children:
                if child.tag == namespace + "dependency":
                    dependencies.append({"id": child.get("id"), "version": child.get("version"),
                                         "target_framework": framework})
    require(len(dependencies) <= 1024, "Dependency declaration count exceeds 1024.")
    return {"id": package_id, "declared_id": declared_id, "version": version, "repository": repository.get("url"),
            "commit": repository.get("commit"), "groups": sorted(groups), "dependencies": dependencies}


def read_zip_member_bounded(archive, entry, capture=False):
    bounded = copy(entry)
    # ZipExtFile otherwise truncates at file_size, hiding surplus inflated bytes.
    bounded.file_size = entry.file_size + 1
    chunks, consumed = [], 0
    with archive.open(bounded) as stream:
        while chunk := stream.read(min(65536, entry.file_size + 1 - consumed)):
            consumed += len(chunk)
            require(consumed <= entry.file_size, "ZIP entry exceeds declared size.")
            if capture:
                chunks.append(chunk)
    require(consumed == entry.file_size, "Incomplete ZIP entry.")
    return b"".join(chunks)


def archive_inventory(data, source=False):
    require(0 < len(data) <= (SOURCE_LIMIT if source else PACKAGE_LIMIT), "Archive byte limit.")
    # ZipFile otherwise accepts arbitrarily large central-directory allocations before entry checks.
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    require(end >= 0 and end + 22 <= len(data), "Missing bounded ZIP end directory.")
    count = int.from_bytes(data[end + 10:end + 12], "little")
    size = int.from_bytes(data[end + 12:end + 16], "little")
    require(count <= 4096 and size <= 8 * MIB, "ZIP directory exceeds the supported profile.")
    names, folded, total = [], set(), 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require(len(archive.infolist()) == count, "Ambiguous or unsupported ZIP directory.")
        for entry in archive.infolist():
            name = (entry.filename[:-1] if source else entry.filename.rstrip("/")) if entry.is_dir() else entry.filename
            allowed = r"[A-Za-z0-9._$ /-]+" if source else r"[A-Za-z0-9._/-]+"
            require(entry.orig_filename == entry.filename and name and
                    (re.fullmatch(allowed, name, re.ASCII) or name == "[Content_Types].xml") and
                    all(part and part not in (".", "..") and part == part.strip() for part in name.split("/")) and
                    len(name) <= 1024 and name.lower() not in folded and
                    stat.S_IFMT(entry.external_attr >> 16) != stat.S_IFLNK and not entry.flag_bits & 1,
                    "Unsafe, duplicate, linked or encrypted ZIP entry.")
            if source:
                require(len(name) <= 256 and all(not part.endswith(".") and not re.fullmatch(
                    r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CONIN\$|CONOUT\$|CLOCK\$)",
                    part.split(".")[0], re.I | re.ASCII) for part in name.split("/")),
                    "Unsafe source member Windows name or length.")
            folded.add(name.lower())
            total += entry.file_size
            require(total <= 64 * MIB and entry.file_size <= 64 * MIB and
                    (not entry.is_dir() or entry.file_size == 0), "Expanded ZIP byte limit.")
            if not entry.is_dir():
                read_zip_member_bounded(archive, entry)
                names.append(name)
    return names


def release_sbom_from_zip(data):
    require(0 < len(data) <= SBOM_ZIP_LIMIT, "Release SBOM ZIP byte limit.")
    end = data.rfind(b"PK\x05\x06")
    require(end >= 0 and end + 22 == len(data) and data[end + 20:end + 22] == b"\0\0" and
            1 <= int.from_bytes(data[end + 10:end + 12], "little") <= 2,
            "Release SBOM ZIP needs one manifest and an optional checksum, without trailing bytes.")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = {entry.filename for entry in entries}
        require(len(entries) == len(names) and
                names in ({"manifest.spdx.json"}, {"manifest.spdx.json", "manifest.spdx.json.sha256"}),
                "Release SBOM ZIP needs root manifest.spdx.json and only its optional .sha256 sidecar.")
        for entry in entries:
            maximum = SBOM_LIMIT if entry.filename == "manifest.spdx.json" else 64
            require(entry.file_size <= maximum and
                    entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    "Release SBOM ZIP member size or compression is unsupported.")
        archive_inventory(data)
        manifest = read_zip_member_bounded(archive, archive.getinfo("manifest.spdx.json"), capture=True)
        if "manifest.spdx.json.sha256" in names:
            require(read_zip_member_bounded(archive, archive.getinfo("manifest.spdx.json.sha256"),
                                           capture=True) == sha(manifest).encode("ascii"),
                    "Release SBOM ZIP checksum differs from manifest bytes.")
        return manifest


def source_url(metadata):
    repository, commit = metadata["repository"], metadata["commit"]
    if not isinstance(repository, str) or not isinstance(commit, str):
        return None
    match = re.fullmatch(r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_.-]{1,100})", repository)
    if not match or not re.fullmatch(r"[a-f0-9]{40}", commit) or commit == "0" * 40:
        return None
    owner, repo = match.groups()
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not repo or repo in (".", ".."):
        return None
    return f"https://codeload.github.com/{owner}/{repo}/zip/{commit}"


def allowed_url(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.netloc in ("api.nuget.org", "pkgs.dev.azure.com", "codeload.github.com") and
            not parsed.query and not parsed.fragment and
            re.fullmatch(r"/[A-Za-z0-9._/-]+", parsed.path, re.ASCII) and
            all(part not in (".", "..", "") for part in parsed.path[1:].split("/")),
            "Transport locator is outside the credential-free HTTPS allowlist.")
    if parsed.netloc == "api.nuget.org":
        require(re.fullmatch(r"/v3-flatcontainer/[a-z0-9.-]+/[0-9.]+/[a-z0-9.-]+\.nupkg", parsed.path),
                "Unsupported NuGet transport path.")
    elif parsed.netloc == "pkgs.dev.azure.com":
        prefix = NUGET_FEEDS["dotnet-public"] + "/"
        require(url.startswith(prefix) and
                re.fullmatch(r"[a-z0-9.-]+/[0-9.]+/[a-z0-9.-]+\.nupkg", url[len(prefix):]),
                "Unsupported Azure NuGet feed or package path.")
    else:
        require(re.fullmatch(r"/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+/zip/[a-f0-9]{40}", parsed.path),
                "Unsupported source transport path.")
    return url


def azure_blob_url(source, target):
    allowed_url(source)
    parsed = urllib.parse.urlsplit(target)
    require(source.startswith(NUGET_FEEDS["dotnet-public"] + "/") and
            len(target) <= 8192 and all("!" <= c <= "~" for c in target) and
            parsed.scheme == "https" and
            re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}\.vsblob\.vsassets\.io", parsed.netloc) and
            re.fullmatch(r"/b-[a-f0-9]{32}/[A-Fa-f0-9]{64,128}\.blob", parsed.path) and
            parsed.query and not parsed.fragment,
            "Azure feed redirected outside the supported signed blob profile.")
    return target


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_worker(url, destination, maximum):
    allowed_url(url)
    require(maximum in (PACKAGE_LIMIT, SOURCE_LIMIT), "Unsupported fetch limit.")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    hops = []

    def open_response(target):
        # Never retain signed redirect URLs, queries or credentials in command/acquisition receipts.
        hop = {"host": urllib.parse.urlsplit(target).netloc, "attempted_at_utc": utc(), "http_status": None}
        hops.append(hop)
        request = urllib.request.Request(target, headers={"Accept-Encoding": "identity", "User-Agent": VERSION})
        try:
            response = opener.open(request, timeout=10)
            hop["http_status"] = response.status
            return response
        except urllib.error.HTTPError as error:
            hop["http_status"] = error.code
            raise

    try:
        try:
            response = open_response(url)
        except urllib.error.HTTPError as error:
            if error.code not in (302, 303, 307, 308) or not url.startswith(NUGET_FEEDS["dotnet-public"] + "/"):
                raise
            try:
                target = azure_blob_url(url, error.headers.get("Location", ""))
            finally:
                error.close()
            response = open_response(target)
        # The parent's hard deadline covers both requests, including DNS and TLS setup.
        with response:
            require(response.status == 200 and
                    response.headers.get("Content-Encoding", "identity").lower() == "identity" and
                    len(str(response.headers).encode()) <= 65536, "Unsupported HTTP response.")
            length = response.headers.get("Content-Length")
            require(length is None or length.isdigit() and int(length) <= maximum, "HTTP body byte limit.")
            with destination.open("xb") as stream:
                total = 0
                while chunk := response.read(65536):
                    total += len(chunk)
                    require(total <= maximum, "HTTP body byte limit.")
                    stream.write(chunk)
            require(length is None or total == int(length), "Incomplete HTTP body.")
        outcome = {"result": "succeeded", "detail_code": "http-200", "http_status": 200}
    except urllib.error.HTTPError as error:
        outcome = {"result": "not-found" if error.code == 404 else "access-denied" if error.code in (401, 403) else "unavailable",
                   "detail_code": "http-status", "http_status": error.code}
        error.close()
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as error:
        reason = error.reason if isinstance(error, urllib.error.URLError) else error
        detail = type(reason).__name__
        if len(hops) < 2:
            detail += ": " + str(reason)
        detail = "".join(c if " " <= c <= "~" else "?" for c in detail)[:300]
        outcome = {"result": "network-failure", "detail_code": "transport-failure", "http_status": None, "detail": detail}
    except ValueError:
        outcome = {"result": "invalid-content", "detail_code": "transport-content-profile", "http_status": None}
    return {**outcome, "http_requests": hops}


def fetch(url, destination, maximum, seconds):
    allowed_url(url)
    command = [sys.executable, "-I", str(Path(__file__).absolute()), "_fetch", url, str(destination), str(maximum)]
    try:
        result = subprocess.run(command, capture_output=True, timeout=max(0.01, seconds), check=False)
    except subprocess.TimeoutExpired:
        return {"result": "network-failure", "detail_code": "absolute-deadline", "http_status": None,
                "http_requests": None}
    require(result.returncode == 0, "Download worker failed without a transport receipt.")
    receipt = json.loads(result.stdout, object_pairs_hook=unique)
    require(receipt["result"] in ("succeeded", "not-found", "access-denied", "unavailable",
                                 "invalid-content", "network-failure"), "Invalid download receipt.")
    return receipt


def release_scope(package, metadata, sbom=None):
    root = {"id": metadata["id"], "version": metadata["version"], "sha256": sha(read(package, PACKAGE_LIMIT))}
    digest = sha(read(sbom, SBOM_LIMIT)) if sbom else None
    return {"schema_version": 2, "root": root, "inventory_scope": "release-wide", "sbom_sha256": digest,
            "designation": {"basis": "caller-authoritative-release-inventory/1", "scope": "release-wide",
                            "root": root, "sbom_sha256": digest} if sbom else None}


class Collector:
    def __init__(self, root, capture, remaining_attempts, online, transport=fetch, nuget_feed="nuget.org", admit=None):
        self.root, self.capture = root, capture
        self.remaining = remaining_attempts
        self.online, self.transport = online, transport
        require(nuget_feed in NUGET_FEEDS, "Unsupported NuGet feed selection.")
        self.nuget_feed = nuget_feed
        self.deadline = time.monotonic() + 15 * 60
        self.records, self.diagnostics, self.edges = [], [], []
        self.total = 0
        self.dependencies, self.attempted_dependencies = {}, set()
        self.source = None
        self.sbom, self.sbom_admission, self.admit = None, None, admit
        self.admission_paths = {}
        self.npm_dependencies, self.npm_imports = {}, []
        self.npm_designation = None

    def obtain(self, subject, name, maximum, url=None, local=None, identity=None, kind=None):
        if self.remaining == 0:
            self.diagnostics.append(f"Retrieval-record budget exhausted before {name}; no request sent.")
            return None
        if self.total + maximum > TOTAL_LIMIT:
            self.diagnostics.append(f"Checked-byte budget cannot admit another bounded {subject}; no request sent.")
            return None
        if local is None and (not self.online or time.monotonic() >= self.deadline):
            self.diagnostics.append(f"No acquisition for {name}: offline mode or collection deadline; no request sent.")
            return None
        path = self.capture / name
        relative = path.relative_to(self.root).as_posix()
        record = {"sequence": len(self.records) + 1, "subject": subject,
                  "locator": relative if local is not None else allowed_url(url),
                  "method": "local-file" if local is not None else "direct-download" if subject == "source" else "package-feed",
                  "attempted_at_utc": utc(), "request_sent": local is None, "bytes_received": 0,
                  "retained_path": None, "sha256": None}
        if identity is not None:
            record["identity"] = {"id": identity[0], "version": identity[1]}
        self.remaining -= 1
        try:
            if local is not None:
                write(path, read(local, maximum))
                outcome = {"result": "succeeded", "detail_code": "retained-local-file", "http_status": None}
            else:
                outcome = self.transport(url, path, maximum, min(60, self.deadline - time.monotonic()))
            record.update(outcome)
            if path.exists():
                data = read(path, maximum)
                record.update(bytes_received=len(data), retained_path=relative, sha256=sha(data))
                self.total += len(data)
            if record["result"] != "succeeded":
                return None
            data = read(path, maximum)
            if kind == "sbom-zip":
                manifest = release_sbom_from_zip(data)
                path = self.capture / "release.spdx.json"
                write(path, manifest)
                self.total += len(manifest)
                metadata = None
            elif kind == "sbom":
                metadata = None
            elif subject == "source":
                archive_inventory(data, source=True)
                metadata = None
            else:
                metadata = package_metadata(data)
                if identity is not None:
                    require((metadata["id"], metadata["version"]) == identity, "Downloaded identity differs from requested ID/version.")
            return path, metadata
        except (ValueError, ET.ParseError, UnicodeError, zipfile.BadZipFile, NotImplementedError) as error:
            record.update(result="invalid-content", detail_code="unsupported-or-invalid-content")
            if kind == "sbom-zip":
                self.diagnostics.append(f"Release SBOM ZIP not admitted: {error}")
            return None
        except OSError:
            record.update(result="unavailable", detail_code="local-io-failure")
            return None
        finally:
            self.records.append(record)

    def collect(self, package, metadata, source, supplied, source_allowed=True, release_sbom=None, npm_archives=None):
        require(len(supplied) <= (128 if release_sbom else 64), "Explicit dependency file cap.")
        require(npm_archives is None or release_sbom is not None, "npm archive packets require --release-sbom.")
        self.total = package.stat().st_size
        if not source_allowed:
            require(source is None, "A retained source archive conflicts with the confirmed closed-source boundary.")
            self.diagnostics.append("Confirmed closed-source boundary; no source request sent.")
        elif source is not None:
            item = self.obtain("source", "source.zip", SOURCE_LIMIT, local=source)
            self.source = item[0] if item else None
        elif self.online:
            url = source_url(metadata)
            if url:
                item = self.obtain("source", "source.zip", SOURCE_LIMIT, url=url)
                self.source = item[0] if item else None
            else:
                self.diagnostics.append("Unsupported package-declared GitHub repository or exact revision; no source request sent.")
        else:
            self.diagnostics.append("No retained source supplied; offline mode made no source request.")
        for number, path in enumerate(supplied):
            item = self.obtain("package", f"supplied-{number:03}.nupkg", PACKAGE_LIMIT, local=path)
            if item:
                key = item[1]["id"], item[1]["version"]
                require(key != (metadata["id"], metadata["version"]) and key not in self.dependencies,
                        "Supplied dependencies must be distinct and exclude the root.")
                self.dependencies[key] = item
        if release_sbom is not None:
            zipped = Path(release_sbom).suffix.lower() == ".zip"
            maximum = SBOM_ZIP_LIMIT if zipped else SBOM_LIMIT
            if self.total + maximum + (SBOM_LIMIT if zipped else 0) + 324 * 1024 > TOTAL_LIMIT:
                self.diagnostics.append("Checked-byte budget cannot reserve raw SBOM plus bounded native admission packet; no import/request sent.")
                return self.report()
            retained = self.obtain("documentation", "release-sbom.zip" if zipped else "release.spdx.json",
                                   maximum, local=release_sbom, kind="sbom-zip" if zipped else "sbom")
            self.sbom = retained[0] if retained else None
            if self.sbom:
                require(self.admit is not None, "SBOM collection requires the bundled native admission component.")
                scope = self.capture / "lp-03-scope.json"
                dump(scope, release_scope(package, metadata, self.sbom))
                request = self.capture / "sbom-admission-request.json"
                pins = [pin(self.capture, path, role) for path, role in
                        ((package, "package"), (scope, "assessment"), (self.sbom, "sbom"))]
                dump(request, {"schema_version": 1, "inputs": pins})
                result = self.capture / "sbom-admission.json"
                self.admit(request, result)
                self.sbom_admission = load(result, 256 * 1024)
                require(self.sbom_admission["schema_version"] == 2 and
                        self.sbom_admission["producer"] == "sbom-inventory/2.0.0" and
                        self.sbom_admission["inputs"] == pins, "Native SBOM admission bindings differ.")
                self.admission_paths = {"sbom_admission_request": request, "sbom_admission": result}
                self.total += sum(path.stat().st_size for path in (scope, request, result))
                require(self.total <= TOTAL_LIMIT, "Native inventory packet exceeds the checked-byte budget.")
                admission = self.sbom_admission["admission"]
                if admission["disposition"] == "admitted":
                    require(admission["structural_admission"] == "admitted" and
                            admission["designation_admission"] == "designated" and
                            admission["inventory"]["profile"] == "spdx22-release-nuget-npm-union/1.0.0",
                            "Unexpected native inventory profile/designation.")
                    for component in admission["inventory"]["dependencies"]:
                        if component["ecosystem"] == "npm":
                            continue
                        require(component["ecosystem"] == "nuget", "Unknown native inventory ecosystem.")
                        identity = component["id"], component["version"]
                        require(ID.fullmatch(identity[0]) and VER.fullmatch(identity[1]), "Invalid native component key.")
                        if identity in self.dependencies or not self.online:
                            continue
                        if len(self.dependencies) >= 128:
                            self.diagnostics.append(f"No SBOM-member request for {identity[0]}/{identity[1]}: dependency cap.")
                            continue
                        package_id, version = identity
                        url = f"{NUGET_FEEDS[self.nuget_feed]}/{package_id}/{version}/{package_id}.{version}.nupkg"
                        item = self.obtain("package", f"sbom-{len(self.records):03}.nupkg", PACKAGE_LIMIT, url=url, identity=identity)
                        if item:
                            self.dependencies[identity] = item
                    if npm_archives is not None:
                        self.import_npm_packet(npm_archives, admission["inventory"])
                else:
                    self.diagnostics.append("SBOM not admitted: " + admission["detail"])
            return self.report()
        queue = deque((metadata, framework) for framework in (metadata["groups"] or [None]))
        visited = set()
        while queue:
            parent, framework = queue.popleft()
            parent_key = parent["id"], parent["version"], framework
            if parent_key in visited:
                continue
            visited.add(parent_key)
            exact = framework in parent["groups"]
            relevant = [dep for dep in parent["dependencies"] if
                        dep["target_framework"] == (framework if exact else None)]
            if not relevant and parent["groups"] and not exact:
                self.diagnostics.append(f"No exact or ungrouped dependency group for {parent['id']}/{parent['version']} at {framework}.")
            for dependency in sorted(relevant, key=lambda dep: (dep["id"] or "", dep["version"] or "")):
                require(len(self.edges) < 4096, "Dependency declaration walk exceeds 4096 edges.")
                declared = dependency["version"] or ""
                candidate = declared[1:-1] if declared.startswith("[") and declared.endswith("]") else declared
                identity = (dependency["id"] or "").lower(), candidate
                supported = bool(ID.fullmatch(identity[0]) and VER.fullmatch(candidate))
                edge = {"parent": parent["id"] + "/" + parent["version"], "target_framework": framework,
                        "id": dependency["id"], "declared_range": declared, "candidate": candidate if supported else None,
                        "selection_basis": "exact-declaration" if declared == f"[{candidate}]" else "literal-minimum-sample"}
                self.edges.append(edge)
                if not supported:
                    edge["limitation"] = "Unsupported range or identity; no resolution or request attempted."
                    continue
                if identity == (metadata["id"], metadata["version"]):
                    edge["limitation"] = "Root cycle observed; no duplicate download."
                    continue
                if identity not in self.dependencies and identity not in self.attempted_dependencies and self.online:
                    if len(self.dependencies) == 64:
                        edge["limitation"] = "64 dependency-version cap; no request sent."
                        continue
                    package_id, version = identity
                    self.attempted_dependencies.add(identity)
                    url = f"{NUGET_FEEDS[self.nuget_feed]}/{package_id}/{version}/{package_id}.{version}.nupkg"
                    item = self.obtain("package", f"fetched-{len(self.records):03}.nupkg", PACKAGE_LIMIT, url=url, identity=identity)
                    if item:
                        self.dependencies[identity] = item
                item = self.dependencies.get(identity)
                if item:
                    queue.append((item[1], framework))
                else:
                    edge["limitation"] = "Exact candidate not retained; see attempt records or offline boundary."
        return self.report()

    def import_npm_packet(self, manifest, inventory):
        manifest = regular(manifest)
        raw = read(manifest, 65536)
        packet = json.loads(raw, object_pairs_hook=unique)
        require(set(packet) == {"schema_version", "basis", "root_sha256", "sbom_sha256", "archives"} and
                packet["schema_version"] == 1 and packet["basis"] == "caller-designated-exact-npm-archives/1" and
                packet["root_sha256"] == inventory["root_sha256"] and packet["sbom_sha256"] == inventory["sbom_sha256"] and
                isinstance(packet["archives"], list) and len(packet["archives"]) <= 128,
                "Invalid npm archive packet/root/SBOM binding.")
        members = {}
        for component in inventory["dependencies"]:
            if component["ecosystem"] == "npm":
                name, version = component["id"], component["version"]
                members[f"pkg:npm/{name}@{version}"] = (name, version)
                if name.startswith("@"):
                    members[f"pkg:npm/%40{name[1:]}@{version}"] = (name, version)
        self.npm_designation = self.capture / "npm-archives.json"
        write(self.npm_designation, raw)
        self.total += len(raw)
        seen = set()
        for number, item in enumerate(packet["archives"]):
            require(set(item) == {"purl", "path", "sha256"} and item["purl"] in members and
                    isinstance(item["sha256"], str) and DIGEST.fullmatch(item["sha256"]),
                    "Unknown or malformed npm archive pin.")
            identity = members[item["purl"]]
            require(identity not in seen, "Duplicate canonical npm archive pin.")
            seen.add(identity)
            path = beneath(manifest.parent, item["path"])
            outcome = {"purl": item["purl"], "path": item["path"], "expected_sha256": item["sha256"],
                       "actual_sha256": None, "retained_path": None, "bytes": 0,
                       "method": "local-checked-evidence", "request_sent": False, "result": "missing"}
            self.npm_imports.append(outcome)
            try:
                content = read(path, min(PACKAGE_LIMIT, TOTAL_LIMIT - self.total))
                retained = self.capture / f"npm-{number:03}.tgz"
                write(retained, content)
                self.total += len(content)
                outcome.update(actual_sha256=sha(content), bytes=len(content),
                               retained_path=retained.relative_to(self.root).as_posix(),
                               result="retained" if sha(content) == item["sha256"] else "hash-conflict")
                self.npm_dependencies[identity] = (retained, {"id": identity[0], "version": identity[1]})
            except (OSError, ValueError):
                outcome["result"] = "missing-or-unsupported"
        require(self.total <= TOTAL_LIMIT, "npm packet exceeds total checked-byte budget.")

    def member_outcomes(self):
        if not self.sbom_admission or self.sbom_admission["admission"]["disposition"] != "admitted":
            return []
        outcomes = []
        for component in self.sbom_admission["admission"]["inventory"]["dependencies"]:
            identity = component["id"], component["version"]
            ecosystem = component["ecosystem"]
            item = (self.dependencies if ecosystem == "nuget" else self.npm_dependencies).get(identity)
            records = [r for r in self.records if r.get("identity") == {"id": identity[0], "version": identity[1]}]
            outcomes.append({"ecosystem": ecosystem, "id": identity[0], "version": identity[1],
                             "result": "retained" if item else records[-1]["result"] if records else "not-retained",
                             "retained_path": item[0].relative_to(self.root).as_posix() if item else None,
                             "sha256": sha(read(item[0], PACKAGE_LIMIT)) if item else None,
                             "attempts": records, "nuget_feed": self.nuget_feed if ecosystem == "nuget" else None})
        return outcomes

    def report(self):
        return {"schema_version": 1, "producer": VERSION, "mode": "network" if self.online else "offline",
                "nuget_feed": self.nuget_feed,
                "sbom_admission": self.sbom_admission,
                "npm_evidence_imports": self.npm_imports,
                "inventory_member_outcomes": self.member_outcomes(),
                "attempts": self.records, "declaration_sample_edges": self.edges,
                "diagnostics": self.diagnostics,
                "limitations": [("Caller designation supplies authoritative release-wide inventory scope; structural admission does not independently prove completeness or publication."
                                 if self.sbom is not None else
                                 "Literal minimum candidates and exact-TFM or ungrouped traversal are a bounded declaration sample, not a resolved closure."),
                                "Only a successful direct anonymous source capture produces an LP-02 observation; local imports do not.",
                                "Downloads and local imports do not produce owner, grant, review, notice or build-mapping packets."]}


def source_observation(root, capture, package, metadata, collector):
    if collector.source is None:
        return None
    relative = collector.source.relative_to(root).as_posix()
    attempts = [item for item in collector.records if item["subject"] == "source" and item["retained_path"] == relative]
    require(len(attempts) == 1, "Retained source lacks one matching acquisition record.")
    attempt = attempts[0]
    if attempt["method"] == "local-file":
        return None
    url = source_url(metadata)
    hops = attempt.get("http_requests")
    digest = sha(read(collector.source, SOURCE_LIMIT))
    require(collector.online and url is not None and attempt["method"] == "direct-download" and
            attempt["request_sent"] is True and attempt["locator"] == url and
            attempt["result"] == "succeeded" and attempt["http_status"] == 200 and
            attempt["sha256"] == digest and isinstance(hops, list) and len(hops) == 1 and
            hops[0].get("host") == "codeload.github.com" and hops[0].get("http_status") == 200,
            "Public source observation requires one successful bound anonymous codeload capture.")
    observed_at = hops[0].get("attempted_at_utc")
    require(isinstance(observed_at, str) and
            re.fullmatch(r"[0-9]{4}(?:-[0-9]{2}){2}T[0-9]{2}(?::[0-9]{2}){2}Z", observed_at),
            "Source capture lacks its actual UTC request time.")
    datetime.strptime(observed_at, "%Y-%m-%dT%H:%M:%SZ")
    owner, repo = urllib.parse.urlsplit(url).path.split("/")[1:3]
    path = capture / "source-observation.json"
    observation = {
        "schema_version": 1, "producer": "lp02-anonymous-github/1.0.0",
        "package_id": metadata["declared_id"], "package_version": metadata["version"],
        "package_sha256": sha(read(package, PACKAGE_LIMIT)),
        "repository_url": f"https://github.com/{owner}/{repo}", "commit": metadata["commit"],
        "retrieval_attempt": {"url": url, "observed_at_utc": observed_at,
                              "transport": "direct-https-no-credentials/1", "result": "retrieved", "http_status": 200},
        "capture_receipt": {"role": "source-archive", "sha256": digest},
        "source_inventory": [],
        "mapping_rationale": "The exact package declares this repository and revision; one anonymous download retained this archive."
    }
    if path.exists():
        require(load(path) == observation, "Source observation changed within the helper admission.")
    else:
        dump(path, observation)
    return pin(capture, path, "source-observation")


class Tools:
    def __init__(self, root, work):
        self.root, self.work, self.sequence = root, work, 0
        self.skill = regular(Path(__file__).absolute().parent.parent, directory=True)
        self.resolver = self.skill / "scripts" / "run-resolver.py"
        require(self.resolver.is_file(), "Bundled resolver launcher is missing; no acquisition attempted.")
        fingerprints = load(DATA / "resolver-files.json")
        sibling = self.resolver.parent
        actual = {p.relative_to(sibling).as_posix() for p in sibling.rglob("*")
                  if p.is_file() and (p.name == "run-resolver.py" or p.relative_to(sibling).parts[0] == "resolver")
                  and not any(part in ("bin", "obj", "__pycache__") for part in p.relative_to(sibling).parts)}
        require(set(fingerprints) == actual, "Bundled resolver file inventory changed; mapping review is required.")
        for relative, digest in fingerprints.items():
            require(sha(read(beneath(sibling, relative))) == digest, f"Bundled resolver changed: {relative}; mapping review is required.")
        for name, digest in POLICIES.items():
            require(sha(read(DATA / name)) == digest, f"Bundled frozen policy asset changed: {name}")
        self.env = os.environ.copy()
        self.admission_key = os.urandom(32)
        self.env["BLAZOR_PROVENANCE_ADMISSION_KEY"] = self.admission_key.hex()
        self.env.update(DOTNET_GENERATE_ASPNET_CERTIFICATE="false", DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1",
                        DOTNET_CLI_TELEMETRY_OPTOUT="1", READINESS_SKILL_ROOT=str(self.skill),
                        TEMP=str(work), TMP=str(work), TMPDIR=str(work))
        for key in list(self.env):
            if key.upper() in ("DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS", "PYTHONPATH", "PYTHONHOME"):
                self.env.pop(key)

    def command(self, args, output=None):
        self.sequence += 1
        name = f"command-{self.sequence:03}"
        try:
            result = subprocess.run(args, cwd=self.work, env=self.env, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=240, check=False)
        except subprocess.TimeoutExpired as error:
            dump(self.work / (name + ".json"), {"command": args, "exit": None, "error": "240-second tool timeout"})
            raise ToolFailure("Trusted tool exceeded its timeout; no handoff produced.") from error
        require(len(result.stdout) <= 8 * MIB and len(result.stderr) <= 8 * MIB, "Tool output exceeds receipt bounds.")
        write(self.work / (name + ".stdout"), result.stdout)
        write(self.work / (name + ".stderr"), result.stderr)
        dump(self.work / (name + ".json"), {"command": args, "exit": result.returncode,
                                          "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)})
        if result.returncode:
            raise ToolFailure(f"Trusted tool failed with exit {result.returncode}; see {self.work.name}/{name}.stderr.")
        if output is not None:
            write(output, result.stdout)
        return result.stdout

    def r(self, command, request=None, output=None):
        args = [sys.executable, "-I", str(self.resolver), command]
        if request is not None:
            args.append(str(request))
        return self.command(args, output)


def new_work(root):
    for number in range(1, 10000):
        path = root / f"eleven-{number:04}"
        try:
            path.mkdir()
            return path
        except FileExistsError:
            continue
    raise ValueError("No unused eleven-row revision directory.")


def package_row_ids(tools):
    rubric = load(tools.resolver.parent / "resolver" / "data" / "rubric.json", MIB)
    core = rubric["core"]["requirements"]
    selected = [item["id"] for item in core if item["scope"] == "repository-wide"]
    require(len(core) == 112 and len(selected) == 60 and len(set(selected)) == 60 and set(ROWS).issubset(selected),
            "Expected 60 unique repository-wide package rows in the pinned rubric.")
    return selected


def resolve_executable(name, safe_dirs):
    if os.name == "nt":
        pathext = [
            ext for ext in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(os.pathsep)
            if ext and ext.startswith(".") and os.sep not in ext and (os.altsep is None or os.altsep not in ext)
        ] or [".COM", ".EXE", ".BAT", ".CMD"]
        exts = [""] + pathext if any(name.lower().endswith(ext.lower()) for ext in pathext) else pathext
    else:
        exts = [""]
    for directory in safe_dirs:
        if not directory or not os.path.isabs(directory) or not os.path.isdir(directory):
            continue
        for ext in exts:
            candidate = os.path.abspath(os.path.join(directory, name + ext))
            if os.path.isabs(candidate) and os.path.isfile(candidate) and os.access(candidate, os.F_OK | os.X_OK):
                return candidate
    return None


def provenance_inputs(capture, package_pin, metadata, collector, args, admission_key=None):
    release_nupkg = getattr(args, "release_nupkg", None)
    provenance_bundle = getattr(args, "provenance_bundle", None)
    if not (release_nupkg or provenance_bundle):
        return []
    require(release_nupkg and provenance_bundle,
            "Both --release-nupkg and --provenance-bundle are required when supplying LP-10 build provenance.")
    require(collector.source is not None,
            "A retained source archive is required when supplying LP-10 build provenance.")
    release_copy = capture / "release-package.nupkg"
    write(release_copy, read(regular(release_nupkg), PACKAGE_LIMIT))
    bundle_source = regular(provenance_bundle)
    bundle_doc = load(bundle_source, 4 * MIB)
    bundle_copy = capture / "provenance-bundle.json"
    if isinstance(bundle_doc, dict) and isinstance(bundle_doc.get("attestations"), list):
        selected = None
        for item in bundle_doc["attestations"]:
            if not isinstance(item, dict) or not isinstance(item.get("bundle"), dict):
                continue
            dsse = item["bundle"].get("dsseEnvelope")
            if isinstance(dsse, dict) and isinstance(dsse.get("payload"), str):
                try:
                    stmt = json.loads(
                        base64.b64decode(dsse["payload"]).decode("utf-8"),
                        object_pairs_hook=unique,
                        parse_constant=lambda value: require(False, "Nonfinite JSON value."),
                    )
                except Exception:
                    stmt = {}
                if isinstance(stmt, dict) and stmt.get("predicateType") == "https://slsa.dev/provenance/v1":
                    selected = item["bundle"]
                    break
        require(selected is not None, "No SLSA v1 provenance bundle found in attestations document.")
        dump(bundle_copy, selected)
    else:
        require(isinstance(bundle_doc, dict), "Provenance bundle must be a JSON object.")
        write(bundle_copy, read(bundle_source, 4 * MIB))
    codeload = source_url(metadata)
    require(codeload is not None, "LP-10 provenance verification requires a canonical GitHub repository and 40-hex commit.")
    owner_repo = "/".join(codeload.split("/")[3:5])
    os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"
    safe_dirs = [
        entry for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry and os.path.isabs(entry) and os.path.isdir(entry)
    ]
    safe_path = os.pathsep.join(safe_dirs)
    gh_exe = resolve_executable("gh", safe_dirs) or str((capture / "gh-missing").resolve())
    require(Path(gh_exe).is_absolute(), "gh executable path must be absolute.")
    env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GH_HOST", "GITHUB_TOKEN")}
    env["PATH"] = safe_path
    env["NoDefaultCurrentDirectoryInExePath"] = "1"
    cmd = [gh_exe, "attestation", "verify", str(release_copy), "-b", str(bundle_copy),
           "--repo", owner_repo, "--predicate-type", "https://slsa.dev/provenance/v1", "--format", "json"]
    try:
        completed = subprocess.run(cmd, cwd=capture, env=env, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=60, check=False)
    except FileNotFoundError as error:
        raise ToolFailure("gh attestation verify requires gh on an absolute PATH directory.") from error
    except subprocess.TimeoutExpired as error:
        raise ToolFailure("gh attestation verify exceeded its 60-second timeout.") from error
    verification = []
    verification_status = "unverified"
    if completed.returncode == 0:
        try:
            verification = json.loads(
                completed.stdout,
                object_pairs_hook=unique,
                parse_constant=lambda value: require(False, "Nonfinite JSON value."),
            )
        except (ValueError, TypeError):
            verification = []
        if isinstance(verification, list) and verification:
            verification_status = "verified"
        else:
            verification = []
    release_pin = pin(capture, release_copy, "release-package")
    bundle_pin = pin(capture, bundle_copy, "provenance-bundle")
    source_pin = pin(capture, collector.source, "source-archive")
    attestation_copy = capture / "provenance-attestation.json"
    observation_pin = source_observation(collector.root, capture, capture / package_pin["path"], metadata, collector)
    acquisition = load(capture / observation_pin["path"]) if observation_pin else None
    if acquisition:
        acquisition["archive_size"] = collector.source.stat().st_size
    receipt = {
        "schema_version": 1,
        "producer": "lp10-gh-attestation-verify/1.0.0",
        "package_sha256": package_pin["sha256"],
        "release_package_sha256": release_pin["sha256"],
        "provenance_bundle_sha256": bundle_pin["sha256"],
        "source_archive_sha256": source_pin["sha256"],
        "verification_status": verification_status,
        "verification": verification,
        "source_acquisition": acquisition,
    }
    require(isinstance(admission_key, bytes) and len(admission_key) == 32,
            "Provenance admission requires the trusted helper's process-local key.")
    payload = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    dump(attestation_copy, {"payload": base64.b64encode(payload).decode("ascii"),
                            "hmac_sha256": hmac.new(admission_key, payload, hashlib.sha256).hexdigest()})
    attestation_pin = pin(capture, attestation_copy, "provenance-attestation")
    return [release_pin, bundle_pin, attestation_pin, source_pin]


def requests(root, capture, package, metadata, collector, supplied_request, provenance_pins=()):
    package_pin = pin(capture, package, "package")
    inspection = [package_pin]
    if collector.source:
        inspection.append(pin(capture, collector.source, "source-archive"))
    inspection.extend(pin(capture, item[0], f"dependency-{number:03}")
                      for number, (_, item) in enumerate(sorted(collector.dependencies.items())))
    dump(capture / "inspection-request.json", {"schema_version": 1, "inputs": inspection})
    observation_pin = source_observation(root, capture, package, metadata, collector)
    policy_pins = []
    for name in POLICIES:
        path = capture / name
        write(path, read(DATA / name))
        policy_pins.append(pin(capture, path, "policy" if name == "policy.json" else "corpus"))
    scopes = {}
    lp03_scope = capture / "lp-03-scope.json"
    if not lp03_scope.exists():
        dump(lp03_scope, release_scope(package, metadata, collector.sbom))
    scopes["LP-03"] = pin(capture, lp03_scope, "assessment")
    retained_bytes = collector.total + sum(len(read(beneath(capture, item["path"]))) for item in policy_pins)
    retained_bytes += sum(len(read(beneath(capture, item["path"]))) for item in scopes.values())
    retained_bytes += sum(len(read(beneath(capture, item["path"]))) for item in provenance_pins
                          if item["role"] != "source-archive")
    if observation_pin:
        retained_bytes += len(read(beneath(capture, observation_pin["path"])))
    require(retained_bytes <= TOTAL_LIMIT, "Combined checked input bytes exceed 256 MiB.")
    cases = {}
    for row in ROWS:
        inputs = [package_pin]
        if row == "LP-01":
            inputs += policy_pins
        elif row == "LP-02":
            inputs += [p for p in inspection if p["role"] == "source-archive"]
            if observation_pin:
                inputs.append(observation_pin)
        elif row in scopes:
            inputs += [scopes[row]]
            if row == "LP-03":
                inputs += policy_pins
                if collector.sbom:
                    inputs.append(pin(capture, collector.sbom, "sbom"))
                if collector.npm_designation:
                    inputs.append(pin(capture, collector.npm_designation, "npm-archives"))
                admission = collector.sbom_admission
                if admission and admission["admission"]["disposition"] == "admitted":
                    for number, component in enumerate(admission["admission"]["inventory"]["dependencies"]):
                        item = (collector.dependencies if component["ecosystem"] == "nuget" else
                                collector.npm_dependencies).get((component["id"], component["version"]))
                        if item:
                            inputs.append(pin(capture, item[0], f"dependency-{number:03}"))
        elif row in ("LP-04", "LP-10") and provenance_pins:
            inputs += list(provenance_pins)
        cases[row] = {"case_id": "eleven-" + row.lower(), "row_id": row, "inputs": inputs}
    if supplied_request:
        supplied_request = regular(supplied_request)
        supplied = load(supplied_request, MIB)
        require(set(supplied) == {"schema_version", "cases"} and supplied["schema_version"] == 1 and
                0 < len(supplied["cases"]) <= 11, "Unsupported supplied row-packet request.")
        seen = set()
        for case in supplied["cases"]:
            require(set(case) == {"case_id", "row_id", "inputs"} and case["row_id"] in ROWS and
                    case["row_id"] not in seen and len(case["inputs"]) <= 512, "Duplicate, unknown or invalid supplied row packet.")
            row = case["row_id"]
            seen.add(row)
            require(not (provenance_pins and row in ("LP-04", "LP-10")),
                    "LP-04 and LP-10 row-packet overrides are forbidden when provenance pins are supplied.")
            require(row not in ("LP-04", "LP-10") or [item.get("role") for item in case["inputs"]] == ["package"],
                    "LP-04 and LP-10 provenance packets must be admitted via --release-nupkg and --provenance-bundle.")
            copied, roles = [], set()
            for number, item in enumerate(case["inputs"]):
                require(set(item) == {"role", "path", "sha256"} and item["role"] not in roles and
                        DIGEST.fullmatch(item["sha256"]), "Invalid supplied packet pin.")
                roles.add(item["role"])
                require(retained_bytes <= TOTAL_LIMIT, "Combined checked input bytes exceed 256 MiB.")
                content = read(beneath(supplied_request.parent, item["path"]), min(64 * MIB, TOTAL_LIMIT - retained_bytes))
                retained_bytes += len(content)
                require(sha(content) == item["sha256"], "Supplied row-packet digest mismatch.")
                require(item["role"] != "package" or item["sha256"] == package_pin["sha256"],
                        "Supplied row packet names a different root package.")
                path = capture / f"packet-{row.lower()}-{number:03}.bin"
                write(path, content)
                copied.append(pin(capture, path, item["role"]))
            cases[row]["inputs"] = copied
    resolve = {"schema_version": 1, "cases": [cases[row] for row in ROWS]}
    require(sum(len(read(beneath(capture, item["path"]))) for case in resolve["cases"] for item in case["inputs"]) <= TOTAL_LIMIT,
            "Resolver summed input occurrences exceed 256 MiB.")
    dump(capture / "resolve-request.json", resolve)
    return inspection, resolve


def results_from(request, results_path):
    value = load(results_path)
    require(set(value) == {"schema_version", "cases"} and value["schema_version"] == 1 and
            len(value["cases"]) == 11, "Resolver did not return exactly eleven results.")
    expected = {item["case_id"]: item for item in request["cases"]}
    results = {}
    for case in value["cases"]:
        require(set(case) == {"case_id", "result"} and case["case_id"] in expected, "Unexpected resolver case.")
        item = expected.pop(case["case_id"])
        result = checked_result(case["result"], item["inputs"])
        require(result["row_id"] == item["row_id"] and result["row_id"] not in results, "Wrong or duplicate result row.")
        results[result["row_id"]] = result
    require(not expected, "Missing resolver result.")
    return results


def checked_facts(path, inspection):
    facts = load(path, 2 * MIB)
    require(facts["schema_version"] == 1 and facts["producer"] == "package-evidence-observations/1.1.0" and
            facts["inputs"] == inspection and len(facts["supplied_dependencies"]) <= 128 and
            "decision" not in facts and "status" not in facts, "Unexpected inspection producer or bindings.")
    return facts


def bind(tools, root, work, package, outputs, capture_time=None, source_availability="unresolved", expected_digests=None):
    require(source_availability in ("unresolved", "public-source", "closed-source"),
            "Unsupported source availability.")
    if expected_digests is not None:
        for key, digest in expected_digests.items():
            require(sha(read(outputs[key])) == digest, f"Trusted {key} output changed before binding.")
    request_doc = load(outputs["resolve_request"], MIB)
    inspection_doc = load(outputs["inspection_request"], MIB)
    for item in inspection_doc["inputs"] + [p for case in request_doc["cases"] for p in case["inputs"]]:
        base = outputs["inspection_request"].parent if item in inspection_doc["inputs"] else outputs["resolve_request"].parent
        path = beneath(base, item["path"])
        require(sha(read(path)) == item["sha256"], f"Checked input missing or changed before handoff: {item['path']}")
    results = results_from(request_doc, outputs["results"])
    for row, result in results.items():
        attestation_pins = [p for p in result["inputs"] if p["role"] == "provenance-attestation"]
        if result["branch_id"].startswith("provenance-") or attestation_pins:
            require(len(attestation_pins) == 1, f"Row {row} provenance branch requires a pinned provenance-attestation.")
            att_doc = load(beneath(outputs["resolve_request"].parent, attestation_pins[0]["path"]))
            require(isinstance(att_doc, dict) and isinstance(att_doc.get("payload"), str) and
                    isinstance(att_doc.get("hmac_sha256"), str), "Malformed provenance attestation.")
            raw_payload = base64.b64decode(att_doc["payload"])
            expected_mac = hmac.new(tools.admission_key, raw_payload, hashlib.sha256).hexdigest()
            require(hmac.compare_digest(att_doc["hmac_sha256"], expected_mac),
                    "Unauthenticated provenance attestation in eleven-row handoff.")
    facts = checked_facts(outputs["observations"], inspection_doc["inputs"])
    acquisition = load(outputs["acquisition"])
    captured = capture_time or utc()
    raw_package = read(package, PACKAGE_LIMIT)
    metadata = package_metadata(raw_package)
    package_digest = sha(raw_package)
    ids = {row: [] for row in ROWS}
    for row in ROWS:
        records = [("results", f"The retained resolver result for {row} has branch {results[row]['branch_id']} and decision {results[row]['decision']}.")]
        if row in ("LP-01", "LP-02", "LP-03", "LP-04", "LP-10", "PI-01"):
            records += [("observations", f"The retained checked byte observations supplement {row} without establishing its stronger unadmitted evidence requirements."),
                        ("acquisition", f"The retained acquisition attempts and declaration sample bound the inputs inspected for {row}.")]
        for kind, claim in records:
            doc_digest = sha(read(outputs[kind]))
            token = json.dumps([VERSION, package_digest, captured, row, kind, doc_digest, claim],
                               separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            ids[row].append("EV1-" + sha(token))
        ids[row].sort()
    decision_doc = decisions(results, facts, acquisition, ids)
    decision_path = work / "decisions.json"
    dump(decision_path, decision_doc)
    selected_ids = package_row_ids(tools)
    assigned_by_id = {row["id"]: row for row in decision_doc["rows"]}
    assessment_rows = []
    for row_id in selected_ids:
        if row_id in assigned_by_id:
            assessment_rows.append(assigned_by_id[row_id])
        else:
            assessment_rows.append({
                "id": row_id,
                "status": None,
                "observation": None,
                "evidence_ids": [],
                "owner_action": None,
                "assessment_follow_up": None,
                "not_applicable_rationale": None,
            })
    identity = {
        "package_id": metadata["declared_id"],
        "version": metadata["version"],
        "nupkg_sha256": package_digest,
        "source_availability": source_availability,
    }
    canonical = work / "eleven.canonical.json"
    dump(canonical, {
        "schema_version": 1,
        "producer": VERSION,
        "identity": identity,
        "selected_ids": selected_ids,
        "rows": assessment_rows,
        "findings": [],
        "summary_groups": [],
        "completion_state": "incomplete",
    })
    return {"package": package, "decisions": decision_path, "assessment": canonical}, captured


def save_state(root, work, outputs, bound, captured):
    paths = {**outputs, **bound}
    request = load(paths["resolve_request"], MIB)
    inspection = load(paths["inspection_request"], MIB)
    raw = set()
    for item in inspection["inputs"] + [p for case in request["cases"] for p in case["inputs"]]:
        base = paths["inspection_request"].parent if item in inspection["inputs"] else paths["resolve_request"].parent
        path = beneath(base, item["path"])
        require(sha(read(path)) == item["sha256"], "Checked input changed before handoff.")
        raw.add(path)
    tracked = set(paths.values()) | raw
    for attempt in load(paths["acquisition"])["attempts"]:
        if attempt["retained_path"]:
            path = beneath(root, attempt["retained_path"])
            require(sha(read(path)) == attempt["sha256"], "A retained acquisition outcome changed before handoff.")
            tracked.add(path)
    state = {"schema_version": 1, "producer": VERSION, "captured_at": captured,
             "paths": {key: value.relative_to(root).as_posix() for key, value in paths.items()},
             "files": {p.relative_to(root).as_posix(): sha(read(p)) for p in sorted(tracked)}}
    path = work / "eleven-state.json"
    dump(path, state)
    return path


def open_state(root, path):
    state = load(path)
    require(set(state) == {"schema_version", "producer", "captured_at", "paths", "files"} and
            state["schema_version"] == 1 and state["producer"] == VERSION, "Unknown eleven-row state.")
    for relative, digest in state["files"].items():
        require(sha(read(beneath(root, relative))) == digest, f"Changed retained handoff artifact: {relative}")
    paths = {key: beneath(root, value) for key, value in state["paths"].items()}
    require(all(path.relative_to(root).as_posix() in state["files"] for path in paths.values()), "Unpinned state path.")
    return state, paths


def run_command(args, root):
    work = new_work(root)
    tools = Tools(root, work)
    package = regular(args.nupkg)
    metadata = package_metadata(read(package, PACKAGE_LIMIT))
    source_availability = getattr(args, "source_availability", "unresolved") or "unresolved"
    require(source_availability in ("unresolved", "public-source", "closed-source"),
            "Unsupported source availability.")
    require(source_availability != "closed-source" or not args.source_archive,
            "A retained source archive conflicts with the confirmed closed-source boundary.")
    capture = work / "inputs"
    capture.mkdir()
    package_copy = capture / "package.nupkg"
    write(package_copy, read(package, PACKAGE_LIMIT))
    supplied = [regular(path) for path in args.dependency]
    if args.dependency_directory:
        directory = regular(args.dependency_directory, directory=True)
        supplied += sorted(path for path in directory.iterdir() if path.suffix.lower() == ".nupkg")
    require(len(set(supplied)) == len(supplied), "Duplicate supplied dependency paths.")
    collector = Collector(root, capture, 64, args.allow_network,
                          nuget_feed=args.nuget_feed,
                          admit=lambda request, result: tools.r("admit-sbom", request, result))
    acquisition = collector.collect(package_copy, metadata, args.source_archive, supplied,
                                    source_allowed=source_availability != "closed-source",
                                    release_sbom=args.release_sbom, npm_archives=getattr(args, "npm_archives", None))
    names = {key: root / f"{work.name}-{name}.json" for key, name in
             (("results", "resolver-results"), ("observations", "observations"), ("acquisition", "acquisition"))}
    dump(names["acquisition"], acquisition)
    provenance_pins = provenance_inputs(capture, pin(capture, package_copy, "package"), metadata, collector, args,
                                       tools.admission_key)
    requests(root, capture, package_copy, metadata, collector, args.row_packets, provenance_pins)
    names.update(resolve_request=capture / "resolve-request.json", inspection_request=capture / "inspection-request.json")
    names.update(collector.admission_paths)
    inspect_stdout = tools.r("inspect", names["inspection_request"], names["observations"])
    resolve_stdout = tools.r("resolve", names["resolve_request"], names["results"])
    results_from(load(names["resolve_request"], MIB), names["results"])
    checked_facts(names["observations"], load(names["inspection_request"], MIB)["inputs"])
    bound, captured = bind(tools, root, work, package_copy, names,
                           source_availability=source_availability,
                           expected_digests={"results": sha(resolve_stdout), "observations": sha(inspect_stdout)})
    state = save_state(root, work, names, bound, captured)
    return {"state": str(state), "assessment": str(bound["assessment"]), "decisions": str(bound["decisions"]),
            "completion_state": "incomplete", "assigned_rows": 11, "unassigned_rows": 49}


def continue_command(args, root):
    _, paths = open_state(root, regular(args.state))
    assessment = load(regular(args.assessment))
    expected = load(paths["assessment"])
    with tempfile.TemporaryDirectory(prefix="eleven-check-", dir=root) as scratch:
        tools = Tools(root, Path(scratch))
        selected_ids = package_row_ids(tools)
    require(expected.get("selected_ids") == selected_ids, "Saved assessment row selection differs from pinned rubric.")
    results = results_from(load(paths["resolve_request"], MIB), paths["results"])
    facts = checked_facts(paths["observations"], load(paths["inspection_request"], MIB)["inputs"])
    expected_ids = {row["id"]: row["evidence_ids"] for row in expected["rows"] if row["id"] in ROWS}
    mapped = decisions(results, facts, load(paths["acquisition"]), expected_ids)
    for row in mapped["rows"]:
        original = next(item for item in expected["rows"] if item["id"] == row["id"])
        require(all(original[key] == value for key, value in row.items()),
                "The saved draft no longer matches the current reviewed mapping; run again.")
    require(isinstance(assessment, dict) and set(assessment) == set(expected),
            "Continued assessment has missing or unexpected top-level fields.")
    require(type(assessment.get("schema_version")) is int and
            assessment.get("schema_version") == expected["schema_version"] and
            type(assessment.get("producer")) is str and
            assessment.get("producer") == expected["producer"],
            "Continued assessment has a changed schema_version or producer.")
    require(isinstance(assessment.get("findings"), list) and isinstance(assessment.get("summary_groups"), list),
            "Continued assessment findings and summary_groups must be lists.")
    require(assessment["identity"] == expected["identity"], "Continued assessment has a stale or changed identity.")
    require(assessment.get("selected_ids") == expected["selected_ids"], "Continued assessment changed selected package rows.")
    rows = {row["id"]: row for row in assessment["rows"]}
    require(len(rows) == len(assessment["rows"]) and list(rows) == expected["selected_ids"],
            "Duplicate, missing or reordered assessment rows.")
    for row in expected["rows"]:
        if row["id"] in ROWS:
            require(rows.get(row["id"]) == row, f"Continued assessment changed deterministic row {row['id']}.")
    require(assessment.get("completion_state") == "incomplete" or all(r.get("status") is not None for r in assessment["rows"]),
            "Continued assessment cannot claim completion with unassigned rows.")
    return {"checked_rows": 11, "unchanged": True, "completion_claim": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--root", required=True)
    run.add_argument("--nupkg", required=True)
    run.add_argument("--source-availability", choices=("unresolved", "public-source", "closed-source"), default="unresolved")
    mode = run.add_mutually_exclusive_group()
    mode.add_argument("--allow-network", action="store_true")
    mode.add_argument("--offline", action="store_true")
    run.add_argument("--source-archive")
    run.add_argument("--dependency-directory")
    run.add_argument("--dependency", action="append", default=[])
    run.add_argument("--row-packets")
    run.add_argument("--npm-archives", help="Caller-designated exact local npm tarballs and SHA-256 pins; no publisher authentication or registry requests.")
    run.add_argument("--release-sbom", help="Designate raw SPDX JSON, or a ZIP with root manifest.spdx.json and optional exact SHA-256 sidecar, for this root as the caller's authoritative release-wide inventory. Structural checks do not prove completeness or publication; no owner attestation or capture is invented.")
    run.add_argument("--release-nupkg", help="Optional SLSA-attested GitHub Release .nupkg for LP-10 build provenance verification.")
    run.add_argument("--provenance-bundle", help="Optional Sigstore SLSA v1 provenance bundle JSON for LP-10 build provenance verification.")
    run.add_argument("--nuget-feed", choices=tuple(NUGET_FEEDS), default="nuget.org")
    check = commands.add_parser("check")
    check.add_argument("--root", required=True)
    check.add_argument("--state", required=True)
    check.add_argument("--assessment", required=True)
    args = parser.parse_args()
    root = regular(args.root, directory=True)
    skill_root = Path(__file__).resolve().parents[1]
    protected = skill_root.parents[1] if (skill_root.parent.name == "skills" and
                                          (skill_root.parents[1] / "plugin.json").is_file()) else skill_root
    require(not root.is_relative_to(protected), "Assessment output must be outside the installed skill or plugin.")
    result = run_command(args, root) if args.command == "run" else continue_command(args, root)
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    try:
        if len(sys.argv) == 5 and sys.argv[1] == "_fetch":
            outcome = fetch_worker(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]))
            print(json.dumps(outcome))
            sys.exit(0)
        sys.exit(main())
    except (ValueError, KeyError, TypeError, ET.ParseError, UnicodeError, zipfile.BadZipFile) as error:
        print(f"Eleven-row admission failure: {error}", file=sys.stderr)
        sys.exit(2)
    except (ToolFailure, OSError) as error:
        print(f"Eleven-row environment/tool failure: {error}", file=sys.stderr)
        sys.exit(3)
