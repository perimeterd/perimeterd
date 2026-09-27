#!/usr/bin/env python3
"""Deterministic SPDX-bound release admission regressions."""
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from urllib.parse import quote
import zipfile

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/release-assets.py"
spec = importlib.util.spec_from_file_location("release_assets", SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

SNAPSHOT_VERSION = "0.0.1-dev.e7152d2"
PRERELEASE_VERSION = "0.0.1-dev.1.g09a3c501a820"
STABLE_VERSION = "1.2.3"
SBOM_SUFFIX = ".spdx.sbom.json"
PSEUDO_VERSION = "v0.0.0-20240614123456-abcdef123456"
ARCHIVES = (
    f"perimeterd_{SNAPSHOT_VERSION}_linux_amd64.tar.gz",
    f"perimeterd_{SNAPSHOT_VERSION}_linux_arm64.tar.gz",
)
PACKAGE_ARTIFACTS = (
    f"perimeterd_0.0.1-dev.e7152d2-1_amd64.deb",
    f"perimeterd_0.0.1-dev.e7152d2-1_arm64.deb",
    f"perimeterd-0.0.1-dev.e7152d2-1.x86_64.rpm",
    f"perimeterd-0.0.1-dev.e7152d2-1.aarch64.rpm",
)
SOURCE_ARCHIVE = f"perimeterd-source-{SNAPSHOT_VERSION}.tar.gz"
REQUIRED_SUBJECTS = (*ARCHIVES, *PACKAGE_ARTIFACTS, SOURCE_ARCHIVE)
REQUIRED_SBOMS = tuple(f"{name}{SBOM_SUFFIX}" for name in REQUIRED_SUBJECTS)
REQUIRED_ARTIFACTS = (*REQUIRED_SUBJECTS, *REQUIRED_SBOMS)


def _native_version(version):
    if "-dev." in version:
        version = version.replace("-dev.", "~dev.", 1)
    return f"{version}-1"


def _asset_names(version):
    native = _native_version(version)
    asset_version = native.replace("~", "-")
    subjects = [
        f"perimeterd_{version}_linux_amd64.tar.gz",
        f"perimeterd_{version}_linux_arm64.tar.gz",
        f"perimeterd_{asset_version}_amd64.deb",
        f"perimeterd_{asset_version}_arm64.deb",
        f"perimeterd-{asset_version}.x86_64.rpm",
        f"perimeterd-{asset_version}.aarch64.rpm",
        f"perimeterd-source-{version}.tar.gz",
    ]
    return subjects, [f"{name}{SBOM_SUFFIX}" for name in subjects]


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


class ReleaseAssetStaging(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_temporary = tempfile.TemporaryDirectory(prefix="release-go-fixture-")
        cls.build_root = Path(cls.build_temporary.name)
        cls.go = os.environ.get("GO", "go")
        cls.proxy = cls.build_root / "proxy"
        module_version = PSEUDO_VERSION
        module_path = "example.test/fork"
        module_files = {
            "go.mod": "module example.test/fork\n\ngo 1.20\n",
            "fork.go": 'package old\n\nfunc Value() string { return "fixture" }\n',
        }
        version_dir = cls.proxy / module_path / "@v"
        version_dir.mkdir(parents=True)
        (version_dir / "list").write_text(f"{module_version}\n", encoding="utf-8")
        (version_dir / f"{module_version}.info").write_text(
            json.dumps({"Version": module_version, "Time": "2024-06-14T12:34:56Z"}),
            encoding="utf-8",
        )
        (version_dir / f"{module_version}.mod").write_text(module_files["go.mod"], encoding="utf-8")
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as module_zip:
            for name, content in module_files.items():
                info = zipfile.ZipInfo(f"{module_path}@{module_version}/{name}", (2024, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                module_zip.writestr(info, content.encode("utf-8"))
        (version_dir / f"{module_version}.zip").write_bytes(archive.getvalue())

        cls.module_root = cls.build_root / "application"
        (cls.module_root / "cmd").mkdir(parents=True)
        (cls.module_root / "go.mod").write_text(
            "module example.test/perimeterd-fixture\n\n"
            "go 1.20\n\n"
            "require example.test/old v1.0.0\n\n"
            f"replace example.test/old v1.0.0 => {module_path} {module_version}\n",
            encoding="utf-8",
        )
        (cls.module_root / "cmd" / "main.go").write_text(
            'package main\n\nimport ("fmt"; "example.test/old")\n\n'
            "func main() { fmt.Print(old.Value()) }\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "--quiet", str(cls.module_root)], check=True)
        subprocess.run(["git", "-C", str(cls.module_root), "config", "user.name", "Fixture Builder"], check=True)
        subprocess.run(["git", "-C", str(cls.module_root), "config", "user.email", "fixture@example.test"], check=True)
        subprocess.run(["git", "-C", str(cls.module_root), "add", "go.mod", "cmd/main.go"], check=True)
        subprocess.run(
            ["git", "-C", str(cls.module_root), "commit", "--quiet", "-m", "deterministic fixture"],
            check=True,
        )
        subprocess.run(["git", "-C", str(cls.module_root), "tag", "v1.0.0"], check=True)

        cls.binaries = {}
        cls.go_info = {}
        for arch in ("amd64", "arm64"):
            output = cls.build_root / f"perimeterd-{arch}"
            env = os.environ.copy()
            env.update(
                {
                    "GOOS": "linux",
                    "GOARCH": arch,
                    "GOAMD64": "v1",
                    "GOARM64": "v8.0",
                    "GOPROXY": cls.proxy.as_uri(),
                    "GOSUMDB": "off",
                    "GOMODCACHE": str(cls.build_root / "gomodcache"),
                    "GOCACHE": str(cls.build_root / "gocache"),
                    "GOTOOLCHAIN": "local",
                    "GOENV": "off",
                    "GOFLAGS": "",
                }
            )
            subprocess.run(
                [
                    cls.go,
                    "build",
                    "-mod=mod",
                    "-trimpath",
                    "-buildvcs=true",
                    "-ldflags=-buildid=",
                    "-o",
                    str(output),
                    "./cmd",
                ],
                cwd=cls.module_root,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            cls.binaries[arch] = output.read_bytes()
            cls.go_info[arch] = release._go_build_info(output, f"fixture-{arch}")
            assert (module_path, module_version) in cls.go_info[arch]["modules"]
            assert ("example.test/old", "v1.0.0") not in cls.go_info[arch]["modules"]

    @classmethod
    def tearDownClass(cls):
        cls.build_temporary.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "dist"
        self.source.mkdir()
        self.destination = self.root / "release-assets"
        self.sbom_module = release._sbom_module()
        self.original_extractor = self.sbom_module.extract_binary
        self.sbom_module.extract_binary = self.fixture_extract_binary
        self.addCleanup(setattr, self.sbom_module, "extract_binary", self.original_extractor)

    @staticmethod
    def _tar_bytes(members):
        result = io.BytesIO()
        with gzip.GzipFile(fileobj=result, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, data in sorted(members.items()):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o755 if name.endswith("perimeterd") else 0o644
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(data))
        return result.getvalue()

    @staticmethod
    def fixture_extract_binary(artifact, kind, destination):
        target = "perimeterd" if kind == "archive" else "usr/bin/perimeterd"
        with tarfile.open(artifact, "r:*") as archive:
            matches = [member for member in archive.getmembers() if member.name == target]
            if len(matches) != 1 or not matches[0].isreg():
                raise ValueError(f"fixture has no unique regular {target}")
            stream = archive.extractfile(matches[0])
            if stream is None:
                raise ValueError(f"fixture cannot read {target}")
            binary = Path(destination) / "perimeterd"
            binary.write_bytes(stream.read())
            binary.chmod(0o755)
        return binary

    @staticmethod
    def _purl_ref(locator):
        return {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": locator,
        }

    @staticmethod
    def _sha256_checksum(digest):
        return [{"algorithm": "SHA256", "checksumValue": digest}]

    def make_spdx(self, artifact_name, artifact_digest, kind=None, arch=None, binary=None, version=SNAPSHOT_VERSION):
        parent = {
            "name": artifact_name,
            "SPDXID": "SPDXRef-Parent",
            "versionInfo": f"sha256:{artifact_digest}",
            "primaryPackagePurpose": "FILE",
            "checksums": self._sha256_checksum(artifact_digest),
        }
        packages = [parent]
        relationships = [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": parent["SPDXID"],
                "relationshipType": "DESCRIBES",
            }
        ]
        native = _native_version(version)
        if binary is not None:
            binary_digest = _sha256(binary)
            executable = {
                "name": "usr/bin/perimeterd",
                "SPDXID": "SPDXRef-Executable",
                "versionInfo": f"sha256:{binary_digest}",
                "primaryPackagePurpose": "FILE",
                "checksums": self._sha256_checksum(binary_digest),
            }
            packages.append(executable)
            relationships.append(
                {
                    "spdxElementId": parent["SPDXID"],
                    "relatedSpdxElement": executable["SPDXID"],
                    "relationshipType": "CONTAINS",
                }
            )
            app = {
                "name": "perimeterd",
                "SPDXID": "SPDXRef-ReleaseApplication",
                "versionInfo": version,
                "primaryPackagePurpose": "APPLICATION",
                "externalRefs": [self._purl_ref(f"pkg:generic/perimeterd@{quote(version, safe='-._~')}")],
            }
            packages.append(app)
            relationships.append(
                {
                    "spdxElementId": executable["SPDXID"],
                    "relatedSpdxElement": app["SPDXID"],
                    "relationshipType": "CONTAINS",
                }
            )
            for index, (module_path, module_version) in enumerate(sorted(self.go_info[arch]["modules"])):
                escaped_path = release._go_escape_module(module_path)
                package = {
                    "name": module_path,
                    "SPDXID": f"SPDXRef-GoModule{index}",
                    "versionInfo": module_version,
                    "externalRefs": [
                        self._purl_ref(
                            "pkg:golang/"
                            + quote(escaped_path, safe="/!._-")
                            + "@"
                            + quote(module_version, safe="-._~")
                        )
                    ],
                }
                packages.append(package)
                relationships.append(
                    {
                        "spdxElementId": executable["SPDXID"],
                        "relatedSpdxElement": package["SPDXID"],
                        "relationshipType": "CONTAINS",
                    }
                )
            stdlib = {
                "name": "stdlib",
                "SPDXID": "SPDXRef-GoStdlib",
                "versionInfo": self.go_info[arch]["toolchain"],
                "externalRefs": [
                    self._purl_ref(
                        f"pkg:golang/stdlib@{quote(self.go_info[arch]['stdlib_version'], safe='-._~')}"
                    )
                ],
            }
            packages.append(stdlib)
            relationships.append(
                {
                    "spdxElementId": executable["SPDXID"],
                    "relatedSpdxElement": stdlib["SPDXID"],
                    "relationshipType": "CONTAINS",
                }
            )
            if kind in ("deb", "rpm"):
                package_arch = ("amd64" if arch == "amd64" else "arm64") if kind == "deb" else ("x86_64" if arch == "amd64" else "aarch64")
                purl = f"pkg:{kind}/perimeterd@{quote(native, safe='-._~')}?arch={package_arch}"
                package_version = native
                if kind == "rpm":
                    purl += "&epoch=0"
                    package_version = f"0:{native}"
                wrapper = {
                    "name": "perimeterd",
                    "SPDXID": "SPDXRef-NativePackage",
                    "versionInfo": package_version,
                    "externalRefs": [self._purl_ref(purl)],
                }
                packages.append(wrapper)
                relationships.append(
                    {
                        "spdxElementId": parent["SPDXID"],
                        "relatedSpdxElement": wrapper["SPDXID"],
                        "relationshipType": "CONTAINS",
                    }
                )

        document = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": artifact_name,
            "documentNamespace": f"https://example.test/spdx/{artifact_name}/{artifact_digest}",
            "creationInfo": {
                "creators": ["Tool: deterministic release fixture"],
                "created": "2024-01-01T00:00:00Z",
            },
            "packages": packages,
            "files": [],
            "relationships": relationships,
        }
        return document

    def create_fixture(self, omit=(), additional=(), version=SNAPSHOT_VERSION):
        omitted = set(omit)
        subjects, sboms = _asset_names(version)
        all_names = [*subjects, *sboms]
        native = _native_version(version)
        asset_version = native.replace("~", "-")
        parents = {}
        for arch in ("amd64", "arm64"):
            for kind, name in (
                ("archive", f"perimeterd_{version}_linux_{arch}.tar.gz"),
                ("deb", f"perimeterd_{asset_version}_{'amd64' if arch == 'amd64' else 'arm64'}.deb"),
                ("rpm", f"perimeterd-{asset_version}.{'x86_64' if arch == 'amd64' else 'aarch64'}.rpm"),
            ):
                member = "perimeterd" if kind == "archive" else "usr/bin/perimeterd"
                payload = self._tar_bytes({member: self.binaries[arch]})
                path = self.source / name
                path.write_bytes(payload)
                parents[name] = (kind, arch, self.binaries[arch])
        source_name = f"perimeterd-source-{version}.tar.gz"
        source_bytes = self._tar_bytes({"perimeterd-source/go.mod": b"module fixture\n"})
        (self.source / source_name).write_bytes(source_bytes)
        parents[source_name] = (None, None, None)

        for name, (kind, arch, binary) in parents.items():
            digest = _sha256((self.source / name).read_bytes())
            document = self.make_spdx(name, digest, kind, arch, binary, version)
            (self.source / f"{name}{SBOM_SUFFIX}").write_text(
                json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
        for name in omitted:
            path = self.source / name
            if path.exists():
                path.unlink()
        for name in additional:
            path = self.source / name
            path.write_bytes(b"deterministic unrelated checksum-covered asset\n")
            if name not in all_names:
                all_names.append(name)
        return [name for name in all_names if name not in omitted]

    def write_manifest(self, names, extra_lines=()):
        lines = [
            f"{_sha256((self.source / name).read_bytes())}  {name}"
            for name in names
        ]
        lines.extend(extra_lines)
        (self.source / "checksums.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def load_sbom(self, artifact_name):
        return json.loads((self.source / f"{artifact_name}{SBOM_SUFFIX}").read_text(encoding="utf-8"))

    def save_sbom(self, artifact_name, document):
        (self.source / f"{artifact_name}{SBOM_SUFFIX}").write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def assert_rejected_by(self, message):
        with self.assertRaisesRegex(ValueError, message):
            release.stage(self.source, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".release-assets-staging-*")), [])

    def test_stages_exact_manifest_assets_and_excludes_build_intermediates(self):
        names = self.create_fixture()
        self.write_manifest(names)
        (self.source / "metadata.json").write_text("build metadata", encoding="utf-8")
        (self.source / "perimeterd").write_bytes(b"unpackaged build intermediate")

        release.stage(self.source, self.destination)

        self.assertEqual(
            {path.name for path in self.destination.iterdir()},
            set(names) | {"checksums.txt"},
        )
        for name in names:
            self.assertEqual((self.destination / name).read_bytes(), (self.source / name).read_bytes())
        self.assertEqual(
            (self.destination / "checksums.txt").read_bytes(),
            (self.source / "checksums.txt").read_bytes(),
        )

    def test_accepts_snapshot_prerelease_and_stable_native_version_names(self):
        for index, version in enumerate((SNAPSHOT_VERSION, PRERELEASE_VERSION, STABLE_VERSION)):
            with self.subTest(version=version):
                names = self.create_fixture(version=version)
                self.write_manifest(names)
                self.destination = self.root / f"release-assets-{index}"
                release.stage(self.source, self.destination)
                self.assertEqual(
                    {path.name for path in self.destination.iterdir()},
                    set(names) | {"checksums.txt"},
                )

    def test_actual_go_build_info_preserves_pseudoversion_replacement_identity(self):
        info = release._go_build_info(
            Path(self.__class__.build_temporary.name) / "perimeterd-amd64",
            "fixture executable",
        )
        self.assertIn(("example.test/fork", PSEUDO_VERSION), info["modules"])
        self.assertNotIn(("example.test/old", "v1.0.0"), info["modules"])

    def test_accepts_unlinked_source_or_tooling_modules_without_counting_them_as_shipped(self):
        names = self.create_fixture()
        artifact = ARCHIVES[0]
        document = self.load_sbom(artifact)
        tool = {
            "name": "example.test/build-tool",
            "SPDXID": "SPDXRef-UnlinkedTool",
            "versionInfo": "v9.0.0",
            "externalRefs": [self._purl_ref("pkg:golang/example.test/build-tool@v9.0.0")],
        }
        document["packages"].append(tool)
        self.save_sbom(artifact, document)
        self.write_manifest(names)

        release.stage(self.source, self.destination)

    def test_wrong_architecture_substitution_is_rejected_from_elf_bytes(self):
        names = self.create_fixture()
        artifact = ARCHIVES[0]
        swapped = self._tar_bytes({"perimeterd": self.binaries["arm64"]})
        (self.source / artifact).write_bytes(swapped)
        document = self.make_spdx(
            artifact,
            _sha256(swapped),
            "archive",
            "arm64",
            self.binaries["arm64"],
        )
        self.save_sbom(artifact, document)
        self.write_manifest(names)

        self.assert_rejected_by("ELF architecture does not match amd64")

    def test_malformed_spdx_document_is_rejected(self):
        names = self.create_fixture()
        artifact = ARCHIVES[0]
        (self.source / f"{artifact}{SBOM_SUFFIX}").write_text("{not json", encoding="utf-8")
        self.write_manifest(names)

        self.assert_rejected_by("malformed SPDX document")

    def test_wrong_parent_checksum_is_rejected_even_after_manifest_refresh(self):
        names = self.create_fixture()
        artifact = ARCHIVES[0]
        document = self.load_sbom(artifact)
        parent = next(package for package in document["packages"] if package["name"] == artifact)
        parent["checksums"] = self._sha256_checksum("0" * 64)
        self.save_sbom(artifact, document)
        self.write_manifest(names)

        self.assert_rejected_by("parent package filename or SHA256 digest mismatch")

    def test_copied_companion_from_other_architecture_is_rejected(self):
        names = self.create_fixture()
        source = self.source / f"{ARCHIVES[0]}{SBOM_SUFFIX}"
        target = self.source / f"{ARCHIVES[1]}{SBOM_SUFFIX}"
        target.write_bytes(source.read_bytes())
        self.write_manifest(names)

        self.assert_rejected_by("SPDX document name does not identify its parent artifact")

    def test_dangling_spdx_relationship_is_rejected(self):
        names = self.create_fixture()
        artifact = ARCHIVES[0]
        document = self.load_sbom(artifact)
        document["relationships"][0]["relatedSpdxElement"] = "SPDXRef-Missing"
        self.save_sbom(artifact, document)
        self.write_manifest(names)

        self.assert_rejected_by("unresolved SPDX relationship")

    def test_missing_parent_describes_relationship_is_rejected(self):
        names = self.create_fixture()
        artifact = SOURCE_ARCHIVE
        document = self.load_sbom(artifact)
        document["relationships"].clear()
        self.save_sbom(artifact, document)
        self.write_manifest(names)

        self.assert_rejected_by("does not DESCRIBE its parent package")

    def test_source_document_requires_its_real_filename_and_digest(self):
        names = self.create_fixture()
        document = self.load_sbom(SOURCE_ARCHIVE)
        document["name"] = "another-source.tar.gz"
        self.save_sbom(SOURCE_ARCHIVE, document)
        self.write_manifest(names)

        self.assert_rejected_by("SPDX document name does not identify its parent artifact")

    def test_wrapper_only_package_sbom_is_rejected(self):
        names = self.create_fixture()
        artifact = PACKAGE_ARTIFACTS[0]
        document = self.load_sbom(artifact)
        document["packages"] = [
            package for package in document["packages"]
            if package["name"] in (artifact, "perimeterd")
        ]
        document["relationships"] = [
            relationship for relationship in document["relationships"]
            if relationship["spdxElementId"] == "SPDXRef-DOCUMENT"
            or relationship["relatedSpdxElement"] == "SPDXRef-NativePackage"
        ]
        self.save_sbom(artifact, document)
        self.write_manifest(names)

        self.assert_rejected_by("does not identify the actual usr/bin/perimeterd executable")

    def test_missing_linked_go_replacement_module_is_rejected(self):
        names = self.create_fixture()
        artifact = ARCHIVES[0]
        document = self.load_sbom(artifact)
        removed = next(
            package for package in document["packages"]
            if package["name"] == "example.test/fork"
        )
        document["packages"].remove(removed)
        document["relationships"] = [
            relationship for relationship in document["relationships"]
            if removed["SPDXID"] not in (
                relationship["spdxElementId"], relationship["relatedSpdxElement"]
            )
        ]
        self.save_sbom(artifact, document)
        self.write_manifest(names)

        self.assert_rejected_by("missing linked Go module example.test/fork@")

    def test_wrong_linked_module_version_is_rejected(self):
        names = self.create_fixture()
        artifact = ARCHIVES[0]
        document = self.load_sbom(artifact)
        module = next(
            package for package in document["packages"]
            if package["name"] == "example.test/fork"
        )
        module["versionInfo"] = "v1.9.9"
        module["externalRefs"][0]["referenceLocator"] = "pkg:golang/example.test/fork@v1.9.9"
        self.save_sbom(artifact, document)
        self.write_manifest(names)

        self.assert_rejected_by("missing linked Go module example.test/fork@")

    def test_missing_or_wrong_stdlib_component_is_rejected(self):
        for wrong in (False, True):
            with self.subTest(wrong_version=wrong):
                names = self.create_fixture()
                artifact = ARCHIVES[0]
                document = self.load_sbom(artifact)
                stdlib = next(package for package in document["packages"] if package["name"] == "stdlib")
                if wrong:
                    stdlib["versionInfo"] = "go0.0.1"
                    stdlib["externalRefs"][0]["referenceLocator"] = "pkg:golang/stdlib@0.0.1"
                else:
                    document["packages"].remove(stdlib)
                    document["relationships"] = [
                        relation for relation in document["relationships"]
                        if stdlib["SPDXID"] not in (relation["spdxElementId"], relation["relatedSpdxElement"])
                    ]
                self.save_sbom(artifact, document)
                self.write_manifest(names)
                self.destination = self.root / f"release-assets-{int(wrong)}"

                self.assert_rejected_by("missing linked Go module stdlib@")

    def test_wrong_native_package_metadata_is_rejected(self):
        names = self.create_fixture()
        artifact = PACKAGE_ARTIFACTS[0]
        document = self.load_sbom(artifact)
        wrapper = next(package for package in document["packages"] if package.get("SPDXID") == "SPDXRef-NativePackage")
        wrapper["versionInfo"] = "0.0.1~dev.e7152d2-2"
        wrapper["externalRefs"][0]["referenceLocator"] = (
            "pkg:deb/perimeterd@0.0.1~dev.e7152d2-2?arch=amd64"
        )
        self.save_sbom(artifact, document)
        self.write_manifest(names)

        self.assert_rejected_by("missing or has ambiguous deb component")

    def test_missing_binary_archive_and_each_required_companion_are_rejected(self):
        names = self.create_fixture(omit=(ARCHIVES[0], f"{ARCHIVES[0]}{SBOM_SUFFIX}"))
        self.write_manifest(names)
        self.assert_rejected_by("release artifact inventory mismatch")

        for index, missing in enumerate(REQUIRED_SBOMS):
            with self.subTest(sbom=missing):
                names = self.create_fixture(omit=(missing,), additional=("unrelated.spdx.sbom.json",))
                self.write_manifest(names)
                self.destination = self.root / f"missing-sbom-{index}"
                self.assert_rejected_by(f"missing required SBOMs: .*{missing}")

    def test_unmanifested_required_sbom_does_not_count(self):
        missing = REQUIRED_SBOMS[0]
        names = self.create_fixture(omit=(missing,))
        (self.source / missing).write_text("present but not checksum-covered", encoding="utf-8")
        self.write_manifest(names)

        self.assert_rejected_by(f"missing required SBOMs: {missing}")

    def test_modified_bytes_with_valid_manifest_reach_checksum_guard(self):
        names = self.create_fixture()
        self.write_manifest(names)
        (self.source / names[0]).write_bytes(b"modified after manifest creation")

        self.assert_rejected_by("release artifact checksum mismatch")

    def test_duplicate_checksum_name_reaches_duplicate_guard(self):
        names = self.create_fixture()
        self.write_manifest([*names, names[0]])

        self.assert_rejected_by("duplicate release asset")

    def test_unsafe_checksum_path_is_rejected_as_invalid_entry(self):
        names = self.create_fixture()
        self.write_manifest(names, [f"{'a' * 64}  ../escape.deb"])

        self.assert_rejected_by("invalid release checksum entry")

    def test_unsafe_checksum_basename_is_rejected_as_invalid_entry(self):
        for forbidden in ("?", "~", "+"):
            with self.subTest(forbidden=forbidden):
                names = self.create_fixture()
                self.write_manifest(names, [f"{'a' * 64}  perimeterd_1.2.3{forbidden}1_amd64.deb"])
                self.assert_rejected_by("invalid release checksum entry")

    def test_existing_destination_is_rejected_without_changes(self):
        names = self.create_fixture()
        self.write_manifest(names)
        self.destination.mkdir()
        existing_file = self.destination / "keep.txt"
        existing_file.write_text("preexisting destination", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            release.stage(self.source, self.destination)

        self.assertEqual({path.name for path in self.destination.iterdir()}, {existing_file.name})
        self.assertEqual(existing_file.read_text(encoding="utf-8"), "preexisting destination")

    def test_symlink_artifact_is_rejected(self):
        names = self.create_fixture()
        self.write_manifest(names)
        artifact = self.source / names[0]
        artifact.unlink()
        target = self.root / "outside-artifact"
        target.write_bytes(b"not a regular release artifact")
        artifact.symlink_to(target)

        self.assert_rejected_by("missing or unsafe release artifact")

    def test_absent_manifest_artifact_is_rejected(self):
        names = self.create_fixture()
        self.write_manifest(names)
        (self.source / names[0]).unlink()

        self.assert_rejected_by("missing or unsafe release artifact")

    def test_non_source_archive_does_not_satisfy_source_requirement(self):
        names = self.create_fixture(
            omit=(SOURCE_ARCHIVE, f"{SOURCE_ARCHIVE}{SBOM_SUFFIX}"),
            additional=("other-source-archive.tar.gz", "other-source-archive.tar.gz.spdx.sbom.json"),
        )
        self.write_manifest(names)

        self.assert_rejected_by("exactly one perimeterd source archive")


if __name__ == "__main__":
    unittest.main()
