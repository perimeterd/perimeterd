#!/usr/bin/env python3
"""Generate artifact-bound SPDX SBOMs for release archives and native packages."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import quote


BINARY_MEMBER = "usr/bin/perimeterd"
APPLICATION_MODULE = "github.com/perimeterd/perimeterd"
GO_STDLIB_PURL = "pkg:golang/stdlib@"
GO_MODULE_PURL = f"pkg:golang/{APPLICATION_MODULE}@"
DATA_ARCHIVE = re.compile(r"data\.tar(?:\.(?:gz|xz|bz2|zst|lz4|lzma|lz))?\Z")


class SBOMError(ValueError):
    """An artifact cannot safely produce the required release SBOM."""


def _run_bsdtar(arguments, archive_data=None):
    try:
        result = subprocess.run(
            ["bsdtar", *arguments],
            input=archive_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as error:
        raise SBOMError(
            "bsdtar is required; install libarchive-tools (Ubuntu)"
        ) from error
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise SBOMError(f"bsdtar failed: {detail or result.returncode}")
    return result.stdout


def _safe_member_path(name, allow_absolute):
    if not name or "\\" in name or any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise SBOMError(f"unsafe archive member path: {name!r}")
    if name.startswith("//"):
        raise SBOMError(f"unsafe archive member path: {name!r}")
    if name.startswith("/"):
        if not allow_absolute:
            raise SBOMError(f"absolute archive member path: {name!r}")
        name = name[1:]
    while name.startswith("./"):
        name = name[2:]
    if name in ("", "."):
        return ""
    parts = name.rstrip("/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise SBOMError(f"unsafe archive member path: {name!r}")
    return "/".join(parts)


def _list_members(archive, archive_data=None, allow_absolute=False):
    source = str(archive) if archive_data is None else "-"
    listing = _run_bsdtar(["-tf", source], archive_data)
    verbose = _run_bsdtar(["-tvf", source], archive_data)
    try:
        names = listing.decode("utf-8", errors="strict").splitlines()
        details = verbose.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise SBOMError("archive contains a non-UTF-8 path") from error
    if not names or len(names) != len(details):
        raise SBOMError("archive member listing is malformed or ambiguous")

    members = []
    for raw_name, detail in zip(names, details):
        canonical = _safe_member_path(raw_name, allow_absolute)
        if not detail or detail[0] not in "-d":
            # No links or special files are needed by these release payloads.
            raise SBOMError(f"archive links/special files are not allowed: {raw_name!r}")
        if canonical == "" and detail[0] != "d":
            raise SBOMError(f"archive contains a file without a safe path: {raw_name!r}")
        members.append((raw_name, canonical, detail[0]))
    return members


def _unique_regular_member(members, wanted, description):
    matches = [member for member in members if member[1] == wanted]
    if len(matches) != 1 or matches[0][2] != "-":
        raise SBOMError(
            f"expected exactly one regular {description} member {wanted!r}; "
            f"found {len(matches)}"
        )
    return matches[0][0]


def _extract_member(archive, member, archive_data=None):
    source = str(archive) if archive_data is None else "-"
    data = _run_bsdtar(["-xOf", source, member], archive_data)
    if not data:
        raise SBOMError(f"archive member is empty: {member!r}")
    return data


def _binary_bytes(artifact, kind):
    artifact = Path(artifact)
    if artifact.is_symlink() or not artifact.is_file():
        raise SBOMError(f"artifact must be a regular, non-symlink file: {artifact}")
    artifact = artifact.resolve(strict=True)

    if kind == "archive":
        members = _list_members(artifact, allow_absolute=False)
        member = _unique_regular_member(members, "perimeterd", "binary")
        return _extract_member(artifact, member)

    if kind == "deb":
        outer = _list_members(artifact, allow_absolute=False)
        data_archives = [
            item for item in outer
            if DATA_ARCHIVE.fullmatch(item[1]) and item[2] == "-"
        ]
        if len(data_archives) != 1:
            raise SBOMError(
                f"expected one regular DEB data.tar.* member; found {len(data_archives)}"
            )
        payload = _extract_member(artifact, data_archives[0][0])
        members = _list_members("-", payload, allow_absolute=True)
        member = _unique_regular_member(members, BINARY_MEMBER, "DEB executable")
        return _extract_member("-", member, payload)

    if kind == "rpm":
        members = _list_members(artifact, allow_absolute=True)
        member = _unique_regular_member(members, BINARY_MEMBER, "RPM executable")
        return _extract_member(artifact, member)

    raise SBOMError(f"unsupported artifact kind: {kind!r}")


def extract_binary(artifact: Path, kind: str, destination: Path) -> Path:
    """Safely extract only the executable into a caller-owned temporary directory."""
    data = _binary_bytes(artifact, kind)
    destination = Path(destination)
    if destination.is_symlink():
        raise SBOMError(f"destination must not be a symlink: {destination}")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not destination.is_dir():
        raise SBOMError(f"destination must be a directory: {destination}")
    destination = destination.resolve(strict=True)
    binary = destination / "perimeterd"
    if binary.exists() or binary.is_symlink():
        raise SBOMError(f"refusing to overwrite extracted binary: {binary}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(binary, flags, 0o700)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return binary


def _sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _syft_document(syft, target):
    try:
        result = subprocess.run(
            [syft, str(target), "--output", "spdx-json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as error:
        raise SBOMError(f"Syft executable not found: {syft}") from error
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise SBOMError(f"Syft scan failed for {Path(target).name}: {detail}")
    try:
        document = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SBOMError(f"Syft returned invalid SPDX JSON for {Path(target).name}") from error
    if (
        document.get("spdxVersion") != "SPDX-2.3"
        or document.get("SPDXID") != "SPDXRef-DOCUMENT"
        or not isinstance(document.get("packages"), list)
        or not isinstance(document.get("relationships"), list)
    ):
        raise SBOMError(f"Syft returned an unexpected SPDX document for {Path(target).name}")
    return document


def _root_package(document):
    roots = [
        package for package in document["packages"]
        if package.get("primaryPackagePurpose") == "FILE"
    ]
    if len(roots) != 1:
        raise SBOMError(f"Syft scan must identify exactly one artifact root; found {len(roots)}")
    return roots[0]


def _sha256_checksum(package):
    checksums = package.get("checksums", [])
    if not isinstance(checksums, list):
        raise SBOMError(f"invalid SPDX checksums on {package.get('name', 'package')}")
    return next(
        (item.get("checksumValue") for item in checksums
         if item.get("algorithm", "").upper() == "SHA256"),
        None,
    )


def _wrapper_package(document, kind):
    scheme = "deb" if kind == "deb" else "rpm"
    wrappers = []
    for package in document["packages"]:
        if package.get("name") != "perimeterd":
            continue
        if any(
            reference.get("referenceType") == "purl"
            and reference.get("referenceLocator", "").startswith(f"pkg:{scheme}/perimeterd@")
            for reference in package.get("externalRefs", [])
        ):
            wrappers.append(package)
    if len(wrappers) != 1:
        raise SBOMError(f"Syft must identify exactly one native {scheme} package")
    return wrappers[0]


def _release_version(artifact_name, kind, document):
    if kind == "archive":
        match = re.fullmatch(
            r"perimeterd_(.+)_linux_(?:amd64|arm64)\.tar\.gz", artifact_name
        )
        if not match:
            raise SBOMError(f"cannot infer release version from archive name: {artifact_name}")
        return match.group(1)

    wrapper = _wrapper_package(document, kind)
    native_version = wrapper.get("versionInfo", "")
    if kind == "rpm":
        epoch, separator, native_version = native_version.partition(":")
        if not separator or not epoch.isdigit():
            raise SBOMError(f"RPM wrapper has an invalid versionInfo: {wrapper.get('versionInfo')!r}")
    if kind == "deb":
        match = re.fullmatch(r"perimeterd_(.+)_(?:amd64|arm64)\.deb", artifact_name)
    else:
        match = re.fullmatch(r"perimeterd-(.+)\.(?:x86_64|aarch64)\.rpm", artifact_name)
    expected_name_versions = {native_version, native_version.replace("~", "-")}
    if not match or match.group(1) not in expected_name_versions:
        raise SBOMError(f"native artifact name/version mismatch: {artifact_name}")
    upstream, separator, package_release = native_version.rpartition("-")
    if not separator or package_release != "1" or not upstream:
        raise SBOMError(
            f"cannot infer GoReleaser version from native package version {native_version!r}; "
            "expected configured package release -1"
        )
    return upstream.replace("~", "-")


def _application_package(version):
    return {
        "name": "perimeterd",
        "SPDXID": "SPDXRef-Application-perimeterd-release",
        "versionInfo": version,
        "supplier": "Organization: Perimeterd contributors",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:generic/perimeterd@{quote(version, safe='.-_~')}",
            }
        ],
        "sourceInfo": (
            "Release version inferred from the artifact identity; the Go main-module "
            "source version is represented separately."
        ),
    }


def _binary_package(digest):
    return {
        "name": BINARY_MEMBER,
        "SPDXID": f"SPDXRef-File-perimeterd-executable-{digest[:20]}",
        "versionInfo": f"sha256:{digest}",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "FILE",
    }


def _require_linked_go_inventory(packages):
    purls = {
        reference.get("referenceLocator", "")
        for package in packages
        for reference in package.get("externalRefs", [])
        if reference.get("referenceType") == "purl"
    }
    if not any(purl.startswith(GO_MODULE_PURL) for purl in purls):
        raise SBOMError("Syft did not identify the perimeterd Go main module")
    if not any(purl.startswith(GO_STDLIB_PURL) for purl in purls):
        raise SBOMError("Syft did not identify the Go standard library")


def _validate_relationships(document):
    elements = [document]
    for section in ("packages", "files", "snippets"):
        records = document.get(section, [])
        if not isinstance(records, list):
            raise SBOMError(f"invalid SPDX {section} collection")
        elements.extend(records)
    identifiers = [element.get("SPDXID") for element in elements]
    if any(not identifier for identifier in identifiers):
        raise SBOMError("SPDX element is missing its identifier")
    if len(identifiers) != len(set(identifiers)):
        raise SBOMError("composed SPDX document contains duplicate element identifiers")
    known = set(identifiers)
    for relationship in document.get("relationships", []):
        for field in ("spdxElementId", "relatedSpdxElement"):
            if relationship.get(field) not in known:
                raise SBOMError(
                    f"SPDX relationship references an unknown element: "
                    f"{relationship.get(field)!r}"
                )


def _compose(artifact, kind, document, executable_digest, binary_document=None, binary_path=None):
    artifact_digest = _sha256(artifact)
    root = _root_package(document)
    root_id = root["SPDXID"]
    root["name"] = Path(artifact).name
    root["primaryPackagePurpose"] = "FILE"
    root["versionInfo"] = f"sha256:{artifact_digest}"
    checksums = root.get("checksums", [])
    if not isinstance(checksums, list):
        raise SBOMError("Syft artifact root has invalid checksums")
    root["checksums"] = [
        checksum for checksum in checksums
        if checksum.get("algorithm", "").upper() != "SHA256"
    ] + [{"algorithm": "SHA256", "checksumValue": artifact_digest}]
    document["name"] = Path(artifact).name
    component_files = []


    if kind == "archive":
        root_component_ids = {
            relationship["relatedSpdxElement"]
            for relationship in document["relationships"]
            if relationship.get("spdxElementId") == root_id
            and relationship.get("relationshipType") == "CONTAINS"
        }
        components = [
            package for package in document["packages"]
            if package.get("SPDXID") in root_component_ids
        ]
        if not components:
            raise SBOMError("Syft archive scan has no linked binary components")
        _require_linked_go_inventory(components)
    else:
        wrapper = _wrapper_package(document, kind)
        if not any(
            relationship.get("spdxElementId") == root_id
            and relationship.get("relatedSpdxElement") == wrapper.get("SPDXID")
            and relationship.get("relationshipType") == "CONTAINS"
            for relationship in document["relationships"]
        ):
            raise SBOMError("Syft native SBOM does not link the package wrapper to its artifact root")
        binary_root = _root_package(binary_document)
        if _sha256_checksum(binary_root) != executable_digest:
            raise SBOMError("Syft binary checksum does not match extracted executable bytes")
        binary_root_id = binary_root["SPDXID"]
        components = [
            package for package in binary_document["packages"]
            if package.get("SPDXID") != binary_root_id
        ]
        component_files = binary_document.get("files", [])
        if not isinstance(component_files, list):
            raise SBOMError("Syft binary scan has an invalid files collection")
        for file_record in component_files:
            if _sha256_checksum(file_record) != executable_digest:
                raise SBOMError("Syft binary file checksum does not match extracted executable bytes")
            file_record["fileName"] = BINARY_MEMBER
        document.setdefault("files", []).extend(component_files)

        for package in components:
            source_info = package.get("sourceInfo")
            if isinstance(source_info, str):
                package["sourceInfo"] = source_info.replace(
                    str(binary_path), BINARY_MEMBER
                )
        _require_linked_go_inventory(components)

        binary_relationships = [
            relationship for relationship in binary_document["relationships"]
            if relationship.get("spdxElementId") != binary_root_id
            and relationship.get("relatedSpdxElement") != binary_root_id
        ]
        document["packages"].extend(components)
        document["relationships"].extend(binary_relationships)

    app = _application_package(_release_version(Path(artifact).name, kind, document))
    executable = _binary_package(executable_digest)
    package_ids = [package.get("SPDXID") for package in document["packages"]]
    if len(package_ids) != len(set(package_ids)):
        raise SBOMError("composed SPDX document contains duplicate package identifiers")
    if app["SPDXID"] in package_ids or executable["SPDXID"] in package_ids:
        raise SBOMError("composed SPDX document contains a generated identifier collision")
    document["packages"].extend((executable, app))

    # Archive scans already bind all Go packages directly to the archive root.
    # Move only those component edges under the checksum-bound executable node.
    if kind == "archive":
        document["relationships"] = [
            relationship for relationship in document["relationships"]
            if not (
                relationship.get("spdxElementId") == root_id
                and relationship.get("relatedSpdxElement") in root_component_ids
                and relationship.get("relationshipType") == "CONTAINS"
            )
        ]

    document["relationships"].append(
        {
            "spdxElementId": root_id,
            "relatedSpdxElement": executable["SPDXID"],
            "relationshipType": "CONTAINS",
        }
    )
    document["relationships"].append(
        {
            "spdxElementId": executable["SPDXID"],
            "relatedSpdxElement": app["SPDXID"],
            "relationshipType": "CONTAINS",
        }
    )
    for package in components:
        document["relationships"].append(
            {
                "spdxElementId": executable["SPDXID"],
                "relatedSpdxElement": package["SPDXID"],
                "relationshipType": "CONTAINS",
            }
        )
    for file_record in component_files:
        document["relationships"].append(
            {
                "spdxElementId": executable["SPDXID"],
                "relatedSpdxElement": file_record["SPDXID"],
                "relationshipType": "CONTAINS",
            }
        )
    _validate_relationships(document)

    return document


def _artifact_kind(artifact):
    name = Path(artifact).name
    if name.endswith(".tar.gz"):
        return "archive"
    if name.endswith(".deb"):
        return "deb"
    if name.endswith(".rpm"):
        return "rpm"
    raise SBOMError(f"unsupported release artifact: {name}")


def generate_sbom(artifact: Path, document_path: Path, syft="syft"):
    artifact = Path(artifact)
    document_path = Path(document_path)
    if artifact.is_symlink() or not artifact.is_file():
        raise SBOMError(f"artifact must be a regular, non-symlink file: {artifact}")
    artifact = artifact.resolve(strict=True)
    if document_path.is_symlink() or document_path.resolve() == artifact:
        raise SBOMError(f"unsafe SBOM output path: {document_path}")
    kind = _artifact_kind(artifact)

    with tempfile.TemporaryDirectory(prefix="perimeterd-release-sbom-") as temporary:
        temporary = Path(temporary)
        binary_path = extract_binary(artifact, kind, temporary / "payload")
        binary_digest = _sha256(binary_path)
        document = _syft_document(syft, artifact)
        binary_document = (
            _syft_document(syft, binary_path) if kind != "archive" else None
        )
        composed = _compose(
            artifact, kind, document, binary_digest, binary_document, binary_path
        )

    document_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_output = tempfile.mkstemp(
        prefix=".release-sbom-", suffix=".json", dir=document_path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(composed, stream, ensure_ascii=False, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_output, document_path)
    finally:
        if os.path.exists(temporary_output):
            os.unlink(temporary_output)
    return document_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("document", type=Path)
    parser.add_argument("--syft", default=os.environ.get("SYFT", "syft"))
    args = parser.parse_args(argv)
    try:
        generate_sbom(args.artifact, args.document, args.syft)
    except (OSError, SBOMError) as error:
        print(f"release_sbom.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
