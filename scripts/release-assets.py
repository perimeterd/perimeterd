#!/usr/bin/env python3
"""Stage only checksum-covered release assets with complete SPDX evidence."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import parse_qsl, unquote

CHECKSUMS_NAME = "checksums.txt"
SBOM_SUFFIX = ".spdx.sbom.json"
VERSION_RE = r"[A-Za-z0-9][A-Za-z0-9.+_-]*"
SOURCE_RE = re.compile(rf"perimeterd-source-(?P<version>{VERSION_RE})\.tar\.gz\Z", re.ASCII)
ARCHIVE_TEMPLATE = "perimeterd_{version}_linux_{arch}.tar.gz"
DEB_TEMPLATE = "perimeterd_{version}_{arch}.deb"
RPM_TEMPLATE = "perimeterd-{version}.{arch}.rpm"
ARCHES = {
    "amd64": {"deb": "amd64", "rpm": "x86_64", "elf": 62},
    "arm64": {"deb": "arm64", "rpm": "aarch64", "elf": 183},
}
SPDX_RELATIONSHIPS = {
    "AMENDS", "ANCESTOR_OF", "BUILD_DEPENDENCY_OF", "BUILD_TOOL_OF",
    "CONTAINED_BY", "CONTAINS", "COPY_OF", "DATA_FILE_OF",
    "DEPENDENCY_MANIFEST_OF", "DEPENDENCY_OF", "DESCENDANT_OF",
    "DESCRIBED_BY", "DESCRIBES", "DEV_DEPENDENCY_OF", "DEV_TOOL_OF",
    "DISTRIBUTION_ARTIFACT", "DOCUMENTATION_OF", "DYNAMIC_LINK",
    "EXPANDED_FROM_ARCHIVE", "FILE_ADDED", "FILE_DELETED", "FILE_MODIFIED",
    "GENERATED_FROM", "GENERATES", "HAS_PREREQUISITE", "METAFILE_OF",
    "OPTIONAL_DEPENDENCY_OF", "OTHER", "PACKAGE_OF", "PATCH_APPLIED",
    "PATCH_FOR", "PREREQUISITE_FOR", "PROVIDED_DEPENDENCY_OF",
    "REQUIREMENT_DESCRIPTION_FOR", "RUNTIME_DEPENDENCY_OF", "SPECIFICATION_FOR",
    "STATIC_LINK", "TEST_CASE_OF", "TEST_DEPENDENCY_OF", "TEST_OF",
    "TEST_TOOL_OF", "VARIANT_OF",
}

_SBOM_MODULE = None


def _sbom_module():
    global _SBOM_MODULE
    if _SBOM_MODULE is None:
        path = Path(__file__).resolve().with_name("release_sbom.py")
        spec = importlib.util.spec_from_file_location("release_sbom", path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load SBOM extraction helper: {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            del sys.modules[spec.name]
            raise
        _SBOM_MODULE = module
    return _SBOM_MODULE


def _sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _native_version(release_version):
    """Match GoReleaser's native package version and release suffix."""
    if "-dev." in release_version:
        release_version = release_version.replace("-dev.", "~dev.", 1)
    return f"{release_version}-1"


def _inventory(names):
    sources = [name for name in names if SOURCE_RE.fullmatch(name)]
    if len(sources) != 1:
        raise ValueError("release must contain exactly one perimeterd source archive")
    match = SOURCE_RE.fullmatch(sources[0])
    version = match.group("version")
    native_version = _native_version(version)
    asset_version = native_version.replace("~", "-")

    parents = {name for name in names if not name.endswith(SBOM_SUFFIX)}
    expected = {sources[0]}
    for arch, details in ARCHES.items():
        expected.add(ARCHIVE_TEMPLATE.format(version=version, arch=arch))
        expected.add(DEB_TEMPLATE.format(version=asset_version, arch=details["deb"]))
        expected.add(RPM_TEMPLATE.format(version=asset_version, arch=details["rpm"]))
    missing = sorted(expected - parents)
    extra = sorted(parents - expected)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unexpected {', '.join(extra)}")
        raise ValueError("release artifact inventory mismatch: " + "; ".join(details))

    expected_sboms = {f"{name}{SBOM_SUFFIX}" for name in expected}
    present_sboms = {name for name in names if name.endswith(SBOM_SUFFIX)}
    missing_sboms = sorted(expected_sboms - present_sboms)
    extra_sboms = sorted(present_sboms - expected_sboms)
    if missing_sboms:
        raise ValueError(f"missing required SBOMs: {', '.join(missing_sboms)}")
    if extra_sboms:
        raise ValueError(f"unexpected SBOM companions: {', '.join(extra_sboms)}")
    if len(names) != 14:
        raise ValueError("release checksum inventory must contain exactly 14 artifacts")

    return {
        "version": version,
        "native_version": native_version,
        "source": sources[0],
        "archives": {
            arch: ARCHIVE_TEMPLATE.format(version=version, arch=arch)
            for arch in ARCHES
        },
        "packages": {
            kind: {
                arch: (DEB_TEMPLATE if kind == "deb" else RPM_TEMPLATE).format(
                    version=asset_version,
                    arch=details[kind],
                )
                for arch, details in ARCHES.items()
            }
            for kind in ("deb", "rpm")
        },
        "parents": expected,
    }


def _checksums(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or unsafe checksums.txt")
    names = set()
    checksums = {}
    allowed_name = re.compile(
        r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?\Z", re.ASCII
    )
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]*)", line, re.ASCII)
        if not match or not allowed_name.fullmatch(match.group(2)):
            raise ValueError("invalid release checksum entry")
        checksum, name = match.groups()
        if name in names:
            raise ValueError("duplicate release asset")
        names.add(name)
        artifact = path.parent / name
        if artifact.is_symlink() or not artifact.is_file():
            raise ValueError(f"missing or unsafe release artifact: {name}")
        if _sha256(artifact) != checksum:
            raise ValueError(f"release artifact checksum mismatch: {name}")
        checksums[name] = checksum
    return checksums


def _valid_spdx_id(value):
    return isinstance(value, str) and re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", value) is not None


def _parse_spdx(path, artifact_name):
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{artifact_name}: malformed SPDX document: {error}") from error
    if not isinstance(document, dict):
        raise ValueError(f"{artifact_name}: malformed SPDX document: expected an object")
    if document.get("spdxVersion") != "SPDX-2.3":
        raise ValueError(f"{artifact_name}: unsupported or missing SPDX version")
    if document.get("dataLicense") != "CC0-1.0":
        raise ValueError(f"{artifact_name}: invalid SPDX data license")
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ValueError(f"{artifact_name}: invalid SPDX document identifier")
    if not isinstance(document.get("name"), str) or not document["name"]:
        raise ValueError(f"{artifact_name}: SPDX document name is missing")
    if not isinstance(document.get("documentNamespace"), str) or not document["documentNamespace"]:
        raise ValueError(f"{artifact_name}: SPDX document namespace is missing")
    creation = document.get("creationInfo")
    if not isinstance(creation, dict) or not isinstance(creation.get("creators"), list) or not creation["creators"]:
        raise ValueError(f"{artifact_name}: malformed SPDX creation information")
    if not isinstance(creation.get("created"), str) or not re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)",
        creation["created"],
    ):
        raise ValueError(f"{artifact_name}: malformed SPDX creation timestamp")

    packages = document.get("packages")
    files = document.get("files", [])
    snippets = document.get("snippets", [])
    if not isinstance(packages, list) or not isinstance(files, list) or not isinstance(snippets, list):
        raise ValueError(f"{artifact_name}: malformed SPDX package/file collections")
    identifiers = {"SPDXRef-DOCUMENT"}
    packages_by_id = {}
    for collection, field in ((packages, "package"), (files, "file"), (snippets, "snippet")):
        for entry in collection:
            if not isinstance(entry, dict) or not _valid_spdx_id(entry.get("SPDXID")):
                raise ValueError(f"{artifact_name}: malformed SPDX {field} identifier")
            identifier = entry["SPDXID"]
            if identifier in identifiers:
                raise ValueError(f"{artifact_name}: duplicate SPDX identifier {identifier}")
            identifiers.add(identifier)
            if field == "package":
                if not isinstance(entry.get("name"), str) or not entry["name"]:
                    raise ValueError(f"{artifact_name}: malformed SPDX package name")
                packages_by_id[identifier] = entry
            for key in ("checksums", "externalRefs"):
                if key in entry and not isinstance(entry[key], list):
                    raise ValueError(f"{artifact_name}: malformed SPDX {key}")
            for checksum in entry.get("checksums", []):
                if not isinstance(checksum, dict) or not isinstance(checksum.get("algorithm"), str) or not isinstance(checksum.get("checksumValue"), str):
                    raise ValueError(f"{artifact_name}: malformed SPDX checksum")
            for external_ref in entry.get("externalRefs", []):
                if not isinstance(external_ref, dict) or any(
                    not isinstance(external_ref.get(key), str) or not external_ref[key]
                    for key in ("referenceCategory", "referenceType", "referenceLocator")
                ):
                    raise ValueError(f"{artifact_name}: malformed SPDX external reference")

    relationships = document.get("relationships")
    if not isinstance(relationships, list):
        raise ValueError(f"{artifact_name}: malformed SPDX relationships")
    relationship_set = set()
    for relationship in relationships:
        if not isinstance(relationship, dict):
            raise ValueError(f"{artifact_name}: malformed SPDX relationship")
        source = relationship.get("spdxElementId")
        target = relationship.get("relatedSpdxElement")
        kind = relationship.get("relationshipType")
        if not isinstance(source, str) or not isinstance(target, str) or source not in identifiers or target not in identifiers:
            raise ValueError(f"{artifact_name}: unresolved SPDX relationship")
        if not isinstance(kind, str) or kind not in SPDX_RELATIONSHIPS:
            raise ValueError(f"{artifact_name}: invalid SPDX relationship type")
        relationship_set.add((source, target, kind))
    return document, packages_by_id, relationship_set
 
 
def _checksum_value(package, expected):
    matches = [
        checksum.get("checksumValue")
        for checksum in package.get("checksums", [])
        if checksum.get("algorithm", "").upper() == "SHA256"
    ]
    return matches.count(expected) == 1 and len(matches) == 1
 
 
def _parent_package(document, packages, relationships, artifact_name, digest):
    if document["name"] != artifact_name:
        raise ValueError(f"{artifact_name}: SPDX document name does not identify its parent artifact")
    matches = [package for package in packages.values() if package.get("name") == artifact_name]
    if len(matches) != 1 or not _checksum_value(matches[0], digest):
        raise ValueError(f"{artifact_name}: SPDX parent package filename or SHA256 digest mismatch")
    parent = matches[0]
    if (document["SPDXID"], parent["SPDXID"], "DESCRIBES") not in relationships:
        raise ValueError(f"{artifact_name}: SPDX document does not DESCRIBE its parent package")
    return parent
 
 
def _pct_decode(value, artifact_name):
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError(f"{artifact_name}: malformed package URL encoding")
    return unquote(value, errors="strict")
 
 
def _parse_purl(value, artifact_name):
    if not isinstance(value, str) or not value.startswith("pkg:") or "#" in value:
        raise ValueError(f"{artifact_name}: malformed package URL")
    body = value[4:]
    path, marker, query = body.partition("?")
    if not path or path.count("/") < 1:
        raise ValueError(f"{artifact_name}: malformed package URL")
    package_type, component = path.split("/", 1)
    if not package_type or not component:
        raise ValueError(f"{artifact_name}: malformed package URL")
    package_name, separator, version = component.rpartition("@")
    if not separator or not package_name or not version:
        raise ValueError(f"{artifact_name}: package URL has no version")
    try:
        package_name = _pct_decode(package_name, artifact_name)
        version = _pct_decode(version, artifact_name)
        query_pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True) if marker else []
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(f"{artifact_name}: malformed package URL encoding") from error
    query = {}
    for key, item in query_pairs:
        key = _pct_decode(key, artifact_name)
        item = _pct_decode(item, artifact_name)
        if key in query:
            raise ValueError(f"{artifact_name}: duplicate package URL qualifier")
        query[key] = item
    return package_type, package_name, version, query
 
 
def _package_purls(package, artifact_name):
    references = package.get("externalRefs", [])
    locators = []
    for reference in references:
        if reference.get("referenceCategory") == "PACKAGE-MANAGER" and reference.get("referenceType") == "purl":
            locators.append(reference["referenceLocator"])
    parsed = []
    for locator in locators:
        parsed.append((locator, _parse_purl(locator, artifact_name)))
    return parsed
 
 
def _find_purl(packages, package_type, package_name, version, artifact_name):
    matches = []
    for package in packages.values():
        for locator, parsed in _package_purls(package, artifact_name):
            if parsed[:3] == (package_type, package_name, version):
                matches.append((package, parsed, locator))
    if len(matches) != 1:
        raise ValueError(
            f"{artifact_name}: SPDX is missing or has ambiguous {package_type} component "
            f"{package_name}@{version}"
        )
    return matches[0]
 
 
def _go_escape_module(path):
    return "".join(f"!{character.lower()}" if character.isupper() else character for character in path)
 
 
def _go_build_info(binary, artifact_name):
    go = os.environ.get("GO", "go")
    try:
        result = subprocess.run(
            [go, "version", "-m", str(binary)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"{artifact_name}: cannot inspect Go build metadata: {error}") from error
    if result.returncode:
        detail = result.stderr.strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise ValueError(f"{artifact_name}: go version -m failed{suffix}")
    lines = result.stdout.splitlines()
    if not lines:
        raise ValueError(f"{artifact_name}: go version -m returned no metadata")
    toolchain = re.search(r"\b(go[0-9]+(?:\.[0-9]+)+(?:rc[0-9]+|beta[0-9]+)?)\b", lines[0])
    if not toolchain:
        raise ValueError(f"{artifact_name}: missing versioned Go toolchain")
 
    modules = []
    main_module = None
    current = None
    build = {}
 
    def finish_module():
        nonlocal current, main_module
        if current is None:
            return
        path, version, replacement, is_main = current
        if replacement is not None:
            replacement_path, replacement_version = replacement
            if not replacement_version or replacement_path.startswith((".", "/", "\\")):
                raise ValueError(
                    f"{artifact_name}: unversioned local replacement for Go module {path}"
                )
            path, version = replacement_path, replacement_version
        if not path or not version or version == "(devel)":
            raise ValueError(f"{artifact_name}: Go module {path or '<unknown>'} has no version")
        record = (path, version)
        if is_main:
            if main_module is not None:
                raise ValueError(f"{artifact_name}: multiple Go main modules")
            main_module = record
        else:
            modules.append(record)
        current = None
 
    for line in lines[1:]:
        fields = line.strip().split()
        if not fields:
            continue
        if fields[0] in ("mod", "dep"):
            finish_module()
            if len(fields) < 3:
                raise ValueError(f"{artifact_name}: malformed Go module metadata")
            current = [fields[1], fields[2], None, fields[0] == "mod"]
        elif fields[0] == "=>":
            if current is None or len(fields) < 2:
                raise ValueError(f"{artifact_name}: malformed Go replacement metadata")
            replacement_path = fields[1]
            replacement_version = fields[2] if len(fields) > 2 else ""
            current[2] = (replacement_path, replacement_version)
        elif fields[0] == "build" and len(fields) >= 2 and "=" in fields[1]:
            key, value = fields[1].split("=", 1)
            build[key] = value
    finish_module()
 
    if main_module is None:
        raise ValueError(f"{artifact_name}: missing versioned Go main module")
    if not build.get("GOARCH") or not build.get("GOOS"):
        raise ValueError(f"{artifact_name}: missing Go target architecture metadata")
    deduplicated = set()
    for path, version in modules:
        if (path, version) in deduplicated:
            raise ValueError(f"{artifact_name}: duplicate Go module {path}@{version}")
        deduplicated.add((path, version))
    return {
        "toolchain": toolchain.group(1),
        "stdlib_version": toolchain.group(1)[2:],
        "main": main_module,
        "modules": set(modules) | {main_module},
        "goos": build["GOOS"],
        "goarch": build["GOARCH"],
    }
 
 
def _elf_arch(binary, artifact_name):
    try:
        with binary.open("rb") as stream:
            header = stream.read(20)
    except OSError as error:
        raise ValueError(f"{artifact_name}: cannot read extracted executable: {error}") from error
    if len(header) < 20 or header[:4] != b"\x7fELF" or header[4] != 2 or header[5] not in (1, 2):
        raise ValueError(f"{artifact_name}: embedded perimeterd is not a 64-bit ELF executable")
    byte_order = "little" if header[5] == 1 else "big"
    return int.from_bytes(header[18:20], byte_order)
 
 
def _validate_parent_contains(artifact_name, relationships, parent, child, what):
    if (parent["SPDXID"], child["SPDXID"], "CONTAINS") not in relationships:
        raise ValueError(f"{artifact_name}: SPDX parent is not linked to {what}")
 
 
def _validate_binary_sbom(artifact, sbom, digest, extracted, kind, arch, release_version, native_version, binary_digest):
    artifact_name = artifact.name
    document, packages, relationships = _parse_spdx(sbom, artifact_name)
    parent = _parent_package(document, packages, relationships, artifact_name, digest)
    extracted_hash = _sha256(extracted)
    executable_matches = [
        package for package in packages.values()
        if package.get("name") == "usr/bin/perimeterd" and _checksum_value(package, extracted_hash)
    ]
    if len(executable_matches) != 1:
        raise ValueError(f"{artifact_name}: SPDX does not identify the actual usr/bin/perimeterd executable")
    executable = executable_matches[0]
    _validate_parent_contains(artifact_name, relationships, parent, executable, "embedded executable")
 
    details = ARCHES[arch]
    machine = _elf_arch(extracted, artifact_name)
    if machine != details["elf"]:
        raise ValueError(f"{artifact_name}: embedded executable ELF architecture does not match {arch}")
    go_info = _go_build_info(extracted, artifact_name)
    if go_info["goos"] != "linux" or go_info["goarch"] != arch:
        raise ValueError(f"{artifact_name}: Go build target does not match Linux {arch}")
 
    app, _, _ = _find_purl(packages, "generic", "perimeterd", release_version, artifact_name)
    if app.get("name") != "perimeterd" or app.get("versionInfo") != release_version or app.get("primaryPackagePurpose") != "APPLICATION":
        raise ValueError(f"{artifact_name}: SPDX release application identity/version mismatch")
    _validate_parent_contains(artifact_name, relationships, executable, app, "release application component")
 
    expected_go = {
        (_go_escape_module(path), version)
        for path, version in go_info["modules"]
    } | {("stdlib", go_info["stdlib_version"])}
    linked_go = set()
    for package in packages.values():
        if (executable["SPDXID"], package["SPDXID"], "CONTAINS") not in relationships:
            continue
        for _, parsed in _package_purls(package, artifact_name):
            if parsed[0] != "golang":
                continue
            path, version = parsed[1], parsed[2]
            if package.get("name") not in (path, _go_escape_module(path)):
                raise ValueError(f"{artifact_name}: Go component name and package URL identity disagree")
            pair = (_go_escape_module(path), version)
            if pair in linked_go:
                raise ValueError(f"{artifact_name}: duplicate linked Go component {path}@{version}")
            expected_version_info = (version, f"go{version}") if path == "stdlib" else (version,)
            if package.get("versionInfo") not in expected_version_info:
                raise ValueError(f"{artifact_name}: Go component versionInfo disagrees with its package URL for {path}")
            linked_go.add(pair)
    missing = sorted(expected_go - linked_go)
    unexpected = sorted(linked_go - expected_go)
    if missing:
        path, version = missing[0]
        raise ValueError(f"{artifact_name}: missing linked Go module {path}@{version}")
    if unexpected:
        path, version = unexpected[0]
        raise ValueError(f"{artifact_name}: unexpected linked Go module {path}@{version}")
 
    stdlib, _, _ = _find_purl(packages, "golang", "stdlib", go_info["stdlib_version"], artifact_name)
    stdlib_version = stdlib.get("versionInfo")
    if stdlib.get("name") != "stdlib" or stdlib_version not in (
        go_info["stdlib_version"], go_info["toolchain"]
    ):
        raise ValueError(f"{artifact_name}: Go standard-library version does not match {go_info['toolchain']}")
    if (executable["SPDXID"], stdlib["SPDXID"], "CONTAINS") not in relationships:
        raise ValueError(f"{artifact_name}: Go standard-library component is not linked to executable")
 
    if kind in ("deb", "rpm"):
        package_version = native_version
        wrapper, parsed, _ = _find_purl(packages, kind, "perimeterd", package_version, artifact_name)
        expected_info = package_version if kind == "deb" else f"0:{package_version}"
        expected_arch = details[kind]
        if wrapper.get("name") != "perimeterd" or wrapper.get("versionInfo") != expected_info:
            raise ValueError(f"{artifact_name}: native {kind.upper()} package version metadata mismatch")
        if parsed[3].get("arch") != expected_arch:
            raise ValueError(f"{artifact_name}: native package architecture metadata mismatch")
        if kind == "rpm" and parsed[3].get("epoch") != "0":
            raise ValueError(f"{artifact_name}: RPM epoch metadata mismatch")
        _validate_parent_contains(artifact_name, relationships, parent, wrapper, "native package metadata")
 
    if binary_digest is not None and binary_digest != extracted_hash:
        raise ValueError(f"{artifact_name}: embedded executable differs from the {arch} archive executable")
    return extracted_hash
 
 
def _validate_source_sbom(artifact, sbom, digest):
    document, packages, relationships = _parse_spdx(sbom, artifact.name)
    _parent_package(document, packages, relationships, artifact.name, digest)
 
 
def _extract_and_validate(staging, checksums, inventory):
    module = _sbom_module()
    binary_hashes = {}
    with tempfile.TemporaryDirectory(prefix=".release-assets-inspection-", dir=staging) as temporary:
        temporary = Path(temporary)
        source = staging / inventory["source"]
        _validate_source_sbom(
            source,
            staging / f"{source.name}{SBOM_SUFFIX}",
            checksums[source.name],
        )
        for arch in ARCHES:
            for kind, artifact_name in (
                ("archive", inventory["archives"][arch]),
                ("deb", inventory["packages"]["deb"][arch]),
                ("rpm", inventory["packages"]["rpm"][arch]),
            ):
                artifact = staging / artifact_name
                extract_dir = temporary / f"{kind}-{arch}"
                extract_dir.mkdir()
                try:
                    extracted = Path(module.extract_binary(artifact, kind, extract_dir))
                except Exception as error:
                    raise ValueError(f"{artifact_name}: cannot extract perimeterd executable: {error}") from error
                if extracted.is_symlink() or not extracted.is_file():
                    raise ValueError(f"{artifact_name}: extractor did not return a regular executable file")
                base = extract_dir.resolve()
                actual = extracted.resolve()
                if actual != base and base not in actual.parents:
                    raise ValueError(f"{artifact_name}: extracted executable escaped its temporary directory")
                sbom = staging / f"{artifact_name}{SBOM_SUFFIX}"
                binary_hashes[artifact_name] = _validate_binary_sbom(
                    artifact,
                    sbom,
                    checksums[artifact_name],
                    actual,
                    kind,
                    arch,
                    inventory["version"],
                    inventory["native_version"],
                    binary_hashes.get(inventory["archives"][arch]),
                )
    return binary_hashes
 
 
def stage(source, destination):
    source = Path(source)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    staging = Path(tempfile.mkdtemp(prefix=".release-assets-staging-", dir=destination.parent))
    try:
        checksums = _checksums(source / CHECKSUMS_NAME)
        inventory = _inventory(set(checksums))
        for name in checksums:
            shutil.copyfile(source / name, staging / name)
        _extract_and_validate(staging, checksums, inventory)
        shutil.copyfile(source / CHECKSUMS_NAME, staging / CHECKSUMS_NAME)
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(destination)
        staging.rename(destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
 
 
if __name__ == "__main__":
    stage(Path(sys.argv[1]), Path(sys.argv[2]))
