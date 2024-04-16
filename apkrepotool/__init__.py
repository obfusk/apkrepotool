#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
apkrepotool - manage APK repos

apkrepotool is a tool for managing APK repositories that can be used with an
F-Droid-compatible client; specifically, it generates v1 & v2 index JSON & JAR
files from a compatible directory structure with the required YAML metadata and
fastlane metadata & image files.
"""

from __future__ import annotations

import binascii
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
import zipfile

from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any, Dict, List, Optional, Set, Tuple

import repro_apk.binres as binres       # FIXME: needs proper release & dependency

from ruamel.yaml import YAML

__version__ = "0.0.0"
NAME = "apkrepotool"

if os.environ.get("APKREPOTOOL_DIR"):
    APKREPOTOOL_DIR = Path(os.environ["APKREPOTOOL_DIR"])
else:
    APKREPOTOOL_DIR = Path.home() / ".apkrepotool"

DEFAULT_LOCALE = "en-US"

CLEAN_LANG_ENV = dict(LC_ALL="C.UTF-8", LANG="", LANGUAGE="")

SDK_ENV = ("ANDROID_HOME", "ANDROID_SDK", "ANDROID_SDK_ROOT")
SDK_JAR = "lib/apksigner.jar"

APKSIGNER_JAR = "/usr/share/java/apksigner.jar"
CERT_JAVA_CODE = r"""
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import com.android.apksig.ApkVerificationIssue;
import com.android.apksig.ApkVerifier;
import com.android.apksig.apk.ApkFormatException;

public class Cert {
  public static void main(String[] args) {
    try {
      ApkVerifier.Builder builder = new ApkVerifier.Builder(new File(args[0]));
      ApkVerifier.Result result = builder.build().verify();
      if (result.isVerified()) {
        List<X509Certificate> signerCerts = result.getSignerCertificates();
        String versions = String.join(",",
          "v1=" + (result.isVerifiedUsingV1Scheme() ? "true" : "false"),
          "v2=" + (result.isVerifiedUsingV2Scheme() ? "true" : "false"),
          "v3=" + (result.isVerifiedUsingV3Scheme() ? "true" : "false"));
        String header = "verified\n" + versions + "\n" + signerCerts.size() + "\n";
        System.out.write(header.getBytes("UTF-8"));
        for (X509Certificate signerCert : signerCerts) {
          byte[] cert = signerCert.getEncoded();
          System.out.write((cert.length + ":").getBytes("UTF-8"));
          System.out.write(cert);
        }
      } else {
        for (ApkVerificationIssue error : result.getErrors()) {
          System.err.println("Error: " + error);
        }
        System.exit(1);
      }
    } catch (IOException | NoSuchAlgorithmException | CertificateEncodingException | ApkFormatException e) {
      System.exit(1);
    }
  }
}
"""[1:]


class Error(Exception):
    """Base class for errors."""


class SigError(Error):
    """Signature (verification) error."""


@dataclass(frozen=True)
class JavaStuff:
    """Java Stuff."""
    java: str
    javac: Optional[str]
    apksigner_jar: str
    apksigner_supported_schemes: List[int]
    cert_java: Path

    @classmethod
    def load(_cls) -> JavaStuff:
        """Create from get_apksigner_jar(), get_java(), get_cert_java()."""
        java, javac = get_java()
        apksigner_jar = get_apksigner_jar()
        schemes = get_apksigner_supported_schemes(apksigner_jar, java)
        cert_java = get_cert_java(apksigner_jar, javac)
        return JavaStuff(java=java, javac=javac, apksigner_jar=apksigner_jar,
                         apksigner_supported_schemes=schemes, cert_java=cert_java)


# FIXME
@dataclass(frozen=True)
class App:
    """App."""
    name: str
    appid: str
    allowed_apk_signing_keys: List[str]
    one_signer_only: bool
    current_version_code: int
    current_version_name: Optional[str]


@dataclass(frozen=True)
class Feature:
    """AndroidManifest.xml uses-feature."""
    name: str


@dataclass(frozen=True)
class Permission:
    """AndroidManifest.xml uses-permission."""
    name: str
    minSdkVersion: Optional[int]
    maxSdkVersion: Optional[int]


@dataclass(frozen=True)
class Manifest:
    """AndroidManifest.xml data."""
    appid: str
    version_code: int
    version_name: str
    min_sdk: int
    target_sdk: int
    features: List[Feature]
    permissions: List[Permission]


@dataclass(frozen=True)
class Apk:
    """APK."""
    filename: str
    size: int
    sha256: str
    signing_keys: List[str]
    fdroid_sig: str
    added: int
    manifest: Manifest


# FIXME
@dataclass(frozen=True)
class Config:
    """Config."""
    repo_url: str
    repo_name: str
    repo_description: str
    repo_keyalias: str
    keystore: str
    keystorepass_cmd: str
    keypass_cmd: str


# FIXME
@dataclass(frozen=True)
class LocalisedConfig:
    """Localised config."""
    repo_name: str
    repo_description: str


@dataclass(frozen=True)
class FileInfo:
    """File info."""
    path: Path
    size: int
    sha256: str

    @classmethod
    def from_path(_cls, path: Path) -> FileInfo:
        """Create from Path."""
        return FileInfo(path, path.stat().st_size, get_sha256(path))


# FIXME
@dataclass(frozen=True)
class Metadata:
    """App metadata."""
    title: Optional[str]
    short_description: Optional[str]
    full_description: Optional[str]
    changelogs: Dict[int, str]
    icon_file: Optional[FileInfo]
    feature_graphic_file: Optional[FileInfo]
    phone_screenshots_files: List[FileInfo]


# FIXME
def parse_recipe_yaml(recipe_file: Path, latest_version_code: int) -> App:
    r"""
    Parse recipe YAML.

    >>> parse_recipe_yaml(Path("test/metadata/android.appsecurity.cts.tinyapp.yml"), 10)
    App(name='TestApp', appid='android.appsecurity.cts.tinyapp', allowed_apk_signing_keys=['fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8'], one_signer_only=True, current_version_code=10, current_version_name=None)

    """
    appid = recipe_file.stem
    with recipe_file.open(encoding="utf-8") as fh:
        yaml = YAML(typ="safe")
        data = yaml.load(fh)
        name = data["Name"]
        if "AllowedAPKSigningKeys" in data:
            if isinstance(data["AllowedAPKSigningKeys"], str):
                allowed_apk_signing_keys = [data["AllowedAPKSigningKeys"]]
            else:
                allowed_apk_signing_keys = data["AllowedAPKSigningKeys"]
        else:
            allowed_apk_signing_keys = []
        oso = data.get("OneSignerOnly", True)
        cvc = data.get("CurrentVersionCode", latest_version_code)
        cvn = data.get("CurrentVersion")
        return App(name=name, appid=appid, allowed_apk_signing_keys=allowed_apk_signing_keys,
                   one_signer_only=oso, current_version_code=cvc, current_version_name=cvn)


# FIXME
def parse_config_yaml(config_file: Path) -> Config:
    r"""
    Parse config YAML.

    >>> parse_config_yaml(Path("test/config.yml"))
    Config(repo_url='https://example.com/fdroid/repo', repo_name='My Repo', repo_description='This is a repository of apps to be used with an F-Droid-compatible client. Applications in this repository are official binaries built by the original application developers.', repo_keyalias='myrepo', keystore='keystore.jks', keystorepass_cmd='cat .keystorepass', keypass_cmd='cat .keypass')

    """
    with config_file.open(encoding="utf-8") as fh:
        yaml = YAML(typ="safe")
        data = yaml.load(fh)
        return Config(repo_url=data["repo_url"], repo_name=data["repo_name"],
                      repo_description=data["repo_description"],
                      repo_keyalias=data["repo_keyalias"], keystore=data["keystore"],
                      keystorepass_cmd=data["keystorepass_cmd"], keypass_cmd=data["keypass_cmd"])


# FIXME
def parse_localised_config_yaml(config_dir: Path) -> Dict[str, LocalisedConfig]:
    r"""
    Parse localised config YAML.

    >>> for kv in parse_localised_config_yaml(Path("test/config")).items():
    ...     kv
    ('de', LocalisedConfig(repo_name='Mein Repository', repo_description='Dies ist ein Repository mit Android Apps zur Nutzung mit einem F-Droid Client. Apps in diesem Repository sind offizielle Binaries, die von den jeweiligen Entwicklern der App bereitgestellt werden.'))
    ('en-US', LocalisedConfig(repo_name='My Repo', repo_description='This is a repository of apps to be used with an F-Droid-compatible client. Applications in this repository are official binaries built by the original application developers.'))

    """
    configs = {}
    for locale_dir in sorted(config_dir.iterdir()):
        if locale_dir.is_dir():
            config_file = locale_dir / "config.yml"
            with open(config_file, encoding="utf-8") as fh:
                yaml = YAML(typ="safe")
                data = yaml.load(fh)
                configs[locale_dir.name] = LocalisedConfig(
                    repo_name=data["repo"]["name"],
                    repo_description=data["repo"]["description"])
    return configs


# FIXME
def parse_app_metadata(app_dir: Path, repo_dir: Path, version_codes: List[int]) -> Dict[str, Metadata]:
    r"""
    Parse (fastlane) metadata (from app_dir) and images (from repo_dir).

    >>> import dataclasses
    >>> app_dir = Path("test/metadata/android.appsecurity.cts.tinyapp")
    >>> meta = parse_app_metadata(app_dir, Path("test/repo"), [10])
    >>> sorted(meta.keys())
    ['en-US']
    >>> for field in dataclasses.fields(meta["en-US"]):
    ...     x = getattr(meta["en-US"], field.name)
    ...     if isinstance(x, list):
    ...         print(f"{field.name}:")
    ...         for y in x:
    ...             print(f"  {y!r}")
    ...     else:
    ...         print(f"{field.name}={x!r}")
    title='title'
    short_description='short description'
    full_description='full description\n'
    changelogs={10: 'changelog for version code 10\n'}
    icon_file=FileInfo(path=PosixPath('test/repo/android.appsecurity.cts.tinyapp/en-US/icon.png'), size=0, sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    feature_graphic_file=FileInfo(path=PosixPath('test/repo/android.appsecurity.cts.tinyapp/en-US/featureGraphic.png'), size=0, sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    phone_screenshots_files:
      FileInfo(path=PosixPath('test/repo/android.appsecurity.cts.tinyapp/en-US/phoneScreenshots/01.png'), size=0, sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
      FileInfo(path=PosixPath('test/repo/android.appsecurity.cts.tinyapp/en-US/phoneScreenshots/02.png'), size=0, sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    """
    metadata = {}
    for locale_dir in sorted(app_dir.iterdir()):
        title_path = locale_dir / "title.txt"
        short_desc_path = locale_dir / "short_description.txt"
        full_desc_path = locale_dir / "full_description.txt"
        changelog_dir = locale_dir / "changelogs"
        title = title_path.read_text().strip() if title_path.exists() else None
        short_desc = short_desc_path.read_text().strip() if short_desc_path.exists() else None
        full_desc = full_desc_path.read_text() if full_desc_path.exists() else None
        changelogs = {}
        if changelog_dir.exists():
            for changelog in sorted(changelog_dir.glob("*.txt")):
                if changelog.stem.isdigit():
                    version_code = int(changelog.stem)
                    if version_code in version_codes:
                        changelogs[version_code] = changelog.read_text()
        images_dir = repo_dir / app_dir.name / locale_dir.name
        if images_dir.exists():
            icon_path = images_dir / "icon.png"
            fg_path = images_dir / "featureGraphic.png"
            ps_dir = images_dir / "phoneScreenshots"
            icon_file = FileInfo.from_path(icon_path) if icon_path.exists() else None
            fg_file = FileInfo.from_path(fg_path) if fg_path.exists() else None
            if ps_dir.exists():
                ps_files = [FileInfo.from_path(p) for p in sorted(ps_dir.glob("*.png"))]
            else:
                ps_files = []
        else:
            icon_file, fg_file, ps_files = None, None, []
        metadata[locale_dir.name] = Metadata(
            title=title, short_description=short_desc, full_description=full_desc,
            changelogs=changelogs, icon_file=icon_file, feature_graphic_file=fg_file,
            phone_screenshots_files=ps_files)
    return metadata


# FIXME
def get_apk_info(apkfile: Path, added: int = 0, *, java_stuff: Optional[JavaStuff] = None) -> Apk:
    r"""
    Get APK info.

    >>> import dataclasses
    >>> apk = get_apk_info(Path("test/repo/golden-aligned-v1v2v3-out.apk"))
    >>> for field in dataclasses.fields(apk):
    ...     if field.name != "manifest":
    ...         print(f"{field.name}={getattr(apk, field.name)!r}")
    filename='test/repo/golden-aligned-v1v2v3-out.apk'
    size=12865
    sha256='ba7828ba42a3b68bd3acff78773e41d6a62aabe6317538671441c568748d9cd7'
    signing_keys=['fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8']
    fdroid_sig='506ceb2a3116981827a3990f3446d3af'
    added=0

    """
    size = apkfile.stat().st_size
    certs, _ = get_signing_certs(apkfile, java_stuff=java_stuff)
    fingerprints = [hashlib.sha256(cert).hexdigest() for cert in certs]
    sig = hashlib.md5(binascii.hexlify(certs[0])).hexdigest()
    return Apk(filename=str(apkfile), size=size, sha256=get_sha256(apkfile),
               signing_keys=fingerprints, fdroid_sig=sig, added=added,
               manifest=get_manifest(apkfile))


# FIXME
def get_manifest(apkfile: Path) -> Manifest:
    r"""
    Parse AndroidManifest.xml.

    >>> import dataclasses
    >>> manifest = get_manifest(Path("test/repo/golden-aligned-v1v2v3-out.apk"))
    >>> for field in dataclasses.fields(manifest):
    ...     print(f"{field.name}={getattr(manifest, field.name)!r}")
    appid='android.appsecurity.cts.tinyapp'
    version_code=10
    version_name='1.0'
    min_sdk=23
    target_sdk=23
    features=[]
    permissions=[]

    """
    def get(elem: ET.Element, attr: str, android: bool = True) -> Optional[str]:
        if android:
            attr = "{" + binres.SCHEMA_ANDROID + "}" + attr
        return elem.get(attr)

    def get_str(elem: ET.Element, attr: str, android: bool = True) -> str:
        value = get(elem, attr, android=android)
        if not isinstance(value, str):
            raise TypeError("AndroidManifest.xml element type mismatch")
        return value

    chunk = binres.read_chunk(binres.quick_load(str(apkfile), binres.MANIFEST))[0]
    if not isinstance(chunk, binres.XMLChunk):
        raise Error("Expected XMLChunk")
    root = binres.xmlchunk_to_etree(chunk).getroot()
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is None:
        raise TypeError("AndroidManifest.xml missing uses-sdk")
    features = []
    for elem in root.iterfind("uses-feature"):
        if get_str(elem, "required") == "true":
            features.append(Feature(get_str(elem, "name")))
    permissions = []
    for k in ("uses-permission", "uses-permission-sdk-23"):
        for elem in root.iterfind(k):
            minSdkVersion = 23 if k == "uses-permission-sdk-23" else None
            maxsv = get(elem, "maxSdkVersion")
            maxSdkVersion = int(maxsv) if maxsv is not None else None
            permissions.append(Permission(
                name=get_str(elem, "name"), minSdkVersion=minSdkVersion,
                maxSdkVersion=maxSdkVersion))
    return Manifest(
        appid=get_str(root, "package", android=False),
        version_code=int(get_str(root, "versionCode")),
        version_name=get_str(root, "versionName"),
        min_sdk=int(get_str(uses_sdk, "minSdkVersion")),
        target_sdk=int(get_str(uses_sdk, "targetSdkVersion")),
        features=sorted(features, key=lambda f: f.name),
        permissions=sorted(permissions, key=lambda f: f.name))


def get_sha256(file: Path) -> str:
    r"""
    Get SHA-256 digest of file.

    >>> get_sha256(Path("LICENSE.AGPLv3"))
    '8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef'

    """
    sha = hashlib.sha256()
    with file.open("rb") as fh:
        while data := fh.read(4096):
            sha.update(data)
    return sha.hexdigest()


def get_signing_certs(apkfile: Path, *, java_stuff: Optional[JavaStuff] = None) \
        -> Tuple[List[bytes], Dict[str, bool]]:
    r"""
    Get APK signing key certificates using apksigner JAR.

    NB: this validates the signature(s)!

    >>> certs, vsns = get_signing_certs(Path("test/repo/golden-aligned-v1v2v3-out.apk"))
    >>> for cert in certs:
    ...     hashlib.sha256(cert).hexdigest()
    'fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8'
    >>> vsns
    {'v1': True, 'v2': True, 'v3': True}

    """
    if not java_stuff:
        java_stuff = JavaStuff.load()
    if java_stuff.cert_java.suffix == ".java":
        cert_arg = str(java_stuff.cert_java)
        classpath = java_stuff.apksigner_jar
    else:
        cert_arg = java_stuff.cert_java.stem
        classpath = f"{java_stuff.cert_java.parent}:{java_stuff.apksigner_jar}"
    args = (java_stuff.java, "-classpath", classpath, cert_arg, str(apkfile))
    try:
        out = subprocess.run(args, check=True, stdout=subprocess.PIPE).stdout
    except subprocess.CalledProcessError as e:
        raise SigError(f"Verification with apksigner failed: {e}") from e
    except FileNotFoundError as e:
        raise Error(f"Could not run apksigner: {e}") from e
    try:
        verified, versions, num_certs_str, certs_data = out.split(b"\n", 3)
        num_certs = int(num_certs_str)
        if verified != b"verified" or num_certs < 1:
            raise SigError("Verification output mismatch")
        vsns = {k: v == "true" for kv in versions.decode().split(",") for k, v in [kv.split("=")]}
        if sorted(vsns.keys()) != ["v1", "v2", "v3"] or not any(vsns.values()):
            raise SigError("Verification output mismatch")
        certs = []
        for i in range(num_certs):
            cert_size_str, certs_data = certs_data.split(b":", 1)
            cert_size = int(cert_size_str)
            cert, certs_data = certs_data[:cert_size], certs_data[cert_size:]
            if len(cert) != cert_size:
                raise SigError("Verification output mismatch")
            certs.append(cert)
        if certs_data:
            raise SigError("Verification output mismatch")
    except ValueError:
        raise SigError("Verification output mismatch")      # pylint: disable=W0707
    return certs, vsns


# FIXME
def get_cert_java(apksigner_jar: str, javac: Optional[str]) -> Path:
    r"""
    Get path to Cert.java or Cert.class.

    Cert.java is saved in $APKREPOTOOL_DIR (~/.apkrepotool) and compiled to
    Cert.class with javac if available.

    >>> str(APKREPOTOOL_DIR)
    '.tmp'
    >>> str(get_cert_java(get_apksigner_jar(), get_java()[1]))
    '.tmp/Cert.class'

    """
    cert_java = APKREPOTOOL_DIR / "Cert.java"
    cert_class = cert_java.with_suffix(".class")
    javac_failed = cert_class.with_suffix(".javac_failed")
    if cert_class.exists():
        return cert_class
    if not cert_java.exists():
        APKREPOTOOL_DIR.mkdir(mode=0o700, exist_ok=True)
        with cert_java.open("w", encoding="utf-8") as fh:
            fh.write(CERT_JAVA_CODE)
    if javac and not javac_failed.exists():
        args = (javac, "-classpath", f"{cert_java.parent}:{apksigner_jar}", str(cert_java))
        subprocess.run(args, check=False)
        if cert_class.exists():
            return cert_class
        javac_failed.touch()
    return cert_java


def get_apksigner_jar() -> str:
    r"""
    Find apksigner JAR using $ANDROID_HOME etc.

    >>> get_apksigner_jar()
    '/usr/share/java/apksigner.jar'
    >>> os.environ["ANDROID_HOME"] = "test/fake-sdk"
    >>> os.environ["APKSIGNER_JAR"] = "/nonexistent"
    >>> get_apksigner_jar()
    'test/fake-sdk/build-tools/35.0.0-rc1/lib/apksigner.jar'
    >>> os.environ["APKSIGNER_JAR"] = "test/fake-sdk/build-tools/31.0.0/lib/apksigner.jar"
    >>> get_apksigner_jar()
    'test/fake-sdk/build-tools/31.0.0/lib/apksigner.jar'
    >>> del os.environ["ANDROID_HOME"], os.environ["APKSIGNER_JAR"]

    """
    if (jar := os.environ.get("APKSIGNER_JAR") or APKSIGNER_JAR) and os.path.exists(jar):
        return jar
    for k in SDK_ENV:
        if home := os.environ.get(k):
            tools = os.path.join(home, "build-tools")
            if os.path.exists(tools):
                for vsn in sorted(os.listdir(tools), key=_vsn, reverse=True):
                    jar = os.path.join(tools, vsn, *SDK_JAR.split("/"))
                    if os.path.exists(jar):
                        return jar
    raise Error("Could not locate apksigner JAR")


def get_java() -> Tuple[str, Optional[str]]:
    r"""
    Find java (and possibly javac) using $JAVA_HOME/$PATH.

    >>> get_java()
    ('/usr/bin/java', '/usr/bin/javac')
    >>> os.environ["JAVA_HOME"] = "/usr/lib/jvm/java-11-openjdk-amd64"
    >>> get_java()
    ('/usr/lib/jvm/java-11-openjdk-amd64/bin/java', '/usr/lib/jvm/java-11-openjdk-amd64/bin/javac')
    >>> del os.environ["JAVA_HOME"]

    """
    java = javac = None
    if home := os.environ.get("JAVA_HOME"):
        java = os.path.join(home, "bin/java")
        javac = os.path.join(home, "bin/javac")
    if not (java and os.path.exists(java)):
        java = shutil.which("java")
        javac = shutil.which("javac")
        if not (java and os.path.exists(java)):
            raise Error("Could not locate java")
    return java, (javac if javac and os.path.exists(javac) else None)


def _vsn(v: str) -> Tuple[int, ...]:
    r"""
    >>> vs = "31.0.0 32.1.0-rc1 34.0.0-rc3 34.0.0 35.0.0-rc1".split()
    >>> for v in sorted(vs, key=_vsn, reverse=True):
    ...     (_vsn(v), v)
    ((35, 0, 0, 0, 1), '35.0.0-rc1')
    ((34, 0, 0, 1, 0), '34.0.0')
    ((34, 0, 0, 0, 3), '34.0.0-rc3')
    ((32, 1, 0, 0, 1), '32.1.0-rc1')
    ((31, 0, 0, 1, 0), '31.0.0')
    """
    if "-rc" in v:
        v = v.replace("-rc", ".0.", 1)
    else:
        v = v + ".1.0"
    return tuple(int(x) if x.isdigit() else -1 for x in v.split("."))


# FIXME
# FIXME: signed .jar, diff/*.json
# FIXME: --pretty?
def make_index(*, repo_dir: Path, apps: List[App], apks: Dict[str, Dict[int, Apk]],
               meta: Dict[str, Dict[str, Metadata]], cfg: Config,
               localised_cfgs: Dict[str, LocalisedConfig], added: Dict[str, int],
               updated: Dict[str, int], ts: int, pretty: bool = False, verbose: int = 0) -> None:
    """Create & write v1 & v2 index."""
    v1_data = v1_index(apps=apps, apks=apks, meta=meta, ts=ts, cfg=cfg,
                       added=added, updated=updated)
    v2_data = v2_index(apps=apps, apks=apks, meta=meta, ts=ts, cfg=cfg, localised_cfgs=localised_cfgs,
                       added=added, updated=updated)
    if verbose:
        print("Writing index-v1.json...")
    with (repo_dir / "index-v1.json").open("w", encoding="utf-8") as fh:
        if pretty:
            json.dump(v1_data, fh, indent=2)
            fh.write("\n")
        else:
            json.dump(v1_data, fh)
    if verbose:
        print("Writing index-v2.json...")
    with (repo_dir / "index-v2.json").open("w", encoding="utf-8") as fh:
        if pretty:
            json.dump(v2_data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        else:
            json.dump(v2_data, fh, ensure_ascii=False)
    diffs: Dict[int, Tuple[FileInfo, int]] = {}     # FIXME
    entry = v2_entry(ts, len(apps), FileInfo.from_path(repo_dir / "index-v2.json"), diffs)
    if verbose:
        print("Writing entry.json...")
    with (repo_dir / "entry.json").open("w", encoding="utf-8") as fh:
        if pretty:
            json.dump(entry, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        else:
            json.dump(entry, fh, ensure_ascii=False)


# FIXME
# FIXME: use localised config if it exists; ensure identical if both do
def v1_index(*, apps: List[App], apks: Dict[str, Dict[int, Apk]],
             meta: Dict[str, Dict[str, Metadata]], ts: int, cfg: Config,
             added: Dict[str, int], updated: Dict[str, int]) -> Dict[str, Any]:
    """Create v1 index data."""
    return {
        "repo": {
            "timestamp": ts,
            "version": 20002,
            "name": cfg.repo_name,
            "icon": "icon.png",                     # FIXME
            "address": cfg.repo_url,
            "description": cfg.repo_description,
        },
        "requests": {"install": [], "uninstall": []},
        "apps": v1_apps(apps, meta, added, updated),
        "packages": v1_packages(apks),
    }


# FIXME
def v1_apps(apps: List[App], meta: Dict[str, Dict[str, Metadata]],
            added: Dict[str, int], updated: Dict[str, int]) -> List[Dict[str, Any]]:
    """Create v1 index apps data."""
    data = []
    # index is historically sorted by name
    for app in sorted(apps, key=lambda app: app.name.upper()):
        entry = {
            "allowedAPKSigningKeys": app.allowed_apk_signing_keys or None,
            "suggestedVersionName": app.current_version_name,
            "suggestedVersionCode": str(app.current_version_code),
            "license": "Unknown",                   # FIXME
            "name": app.name,
            "added": added[app.appid],
            "packageName": app.appid,
            "lastUpdated": updated[app.appid],
            "localized": v1_localised(meta[app.appid], app.current_version_code),
        }
        data.append({k: v for k, v in entry.items() if v is not None})
    return data


# FIXME
# FIXME: hashed graphics files
def v1_localised(app_meta: Dict[str, Metadata], current_version_code: int) -> Dict[str, Any]:
    """Create v1 index app localised data."""
    data = {}
    for locale, meta in app_meta.items():
        entry = {
            "description": meta.full_description,
            "featureGraphic": meta.feature_graphic_file.path.name if meta.feature_graphic_file else None,
            "icon": meta.icon_file.path.name if meta.icon_file else None,
            "name": meta.title,
            "phoneScreenshots": [
                file.path.name for file in meta.phone_screenshots_files
            ] if meta.phone_screenshots_files else None,
            "summary": meta.short_description,
            "whatsNew": meta.changelogs.get(current_version_code),
        }
        data[locale] = {k: v for k, v in entry.items() if v is not None}
    return data


# FIXME
# FIXME: sort by appid, group, signer, version_code
def v1_packages(apks: Dict[str, Dict[int, Apk]]) -> Dict[str, List[Any]]:
    """Create v1 index packages data."""
    data: Dict[str, List[Any]] = {}
    for appid, versions in sorted(apks.items(), key=lambda kv: kv[0]):
        for apk in versions.values():
            man = apk.manifest
            if appid not in data:
                data[appid] = []
            entry = {
                "added": apk.added,
                "apkName": PurePath(apk.filename).name,
                "features": [f.name for f in man.features] or None,
                "hash": apk.sha256,
                "hashType": "sha256",
                "minSdkVersion": man.min_sdk,
                "packageName": man.appid,
                "sig": apk.fdroid_sig,
                "signer": apk.signing_keys[0],
                "size": apk.size,
                "targetSdkVersion": man.target_sdk,
                "uses-permission": [
                    [p.name, p.maxSdkVersion] for p in man.permissions
                ] or None,
                "versionCode": man.version_code,
                "versionName": man.version_name,
            }
            data[appid].append({k: v for k, v in entry.items() if v is not None})
    return data


# FIXME
# FIXME: mirrors etc.
# FIXME: ensure localised config and regular one are identical if both exist
def v2_index(*, apps: List[App], apks: Dict[str, Dict[int, Apk]],
             meta: Dict[str, Dict[str, Metadata]], ts: int, cfg: Config,
             localised_cfgs: Dict[str, LocalisedConfig], added: Dict[str, int],
             updated: Dict[str, int]) -> Dict[str, Any]:
    """Create v2 index data."""
    if DEFAULT_LOCALE not in localised_cfgs:
        localised_cfgs = localised_cfgs.copy()
        localised_cfgs[DEFAULT_LOCALE] = LocalisedConfig(
            repo_name=cfg.repo_name, repo_description=cfg.repo_description)
    return {
        "repo": {
            "name": {k: v.repo_name for k, v in localised_cfgs.items()},
            "description": {k: v.repo_description for k, v in localised_cfgs.items()},
            "icon": {
                k: {
                    "name": "/icons/icon.png",      # FIXME
                    "sha256": "FIXME",              # FIXME
                    "size": 0,                      # FIXME
                } for k, v in localised_cfgs.items()
            },
            "address": cfg.repo_url,
            "timestamp": ts,
        },
        "packages": v2_packages(apps, apks, meta, added, updated),
    }


# FIXME
# FIXME: hashed graphics files, sha256 & size
def v2_packages(apps: List[App], apks: Dict[str, Dict[int, Apk]],
                meta: Dict[str, Dict[str, Metadata]], added: Dict[str, int],
                updated: Dict[str, int]) -> Dict[str, Any]:
    """Create v2 index packages data."""
    data = {}
    for app in apps:
        loc = meta[app.appid]
        mv = max(apks[app.appid].keys())
        signer = apks[app.appid][mv].signing_keys[0]    # FIXME: sort by ...
        data[app.appid] = {
            "metadata": {
                "added": added[app.appid],
                "lastUpdated": updated[app.appid],
                "featureGraphic": {
                    locale: {
                        "name": f"/{app.appid}/{locale}/{m.feature_graphic_file.path.name}",
                        "sha256": m.feature_graphic_file.sha256,
                        "size": m.feature_graphic_file.size,
                    } for locale, m in loc.items() if m.feature_graphic_file
                },
                "screenshots": {
                    "phone": {
                        locale: [
                            {
                                "name": f"/{app.appid}/{locale}/phoneScreenshots/{file.path.name}",
                                "sha256": file.sha256,
                                "size": file.size,
                            } for file in m.phone_screenshots_files
                        ] for locale, m in loc.items() if m.phone_screenshots_files
                    },
                },
                "name": {
                    DEFAULT_LOCALE: app.name,       # FIXME
                },
                "summary": {
                    locale: m.short_description
                    for locale, m in loc.items() if m.short_description is not None
                },
                "description": {
                    locale: m.full_description
                    for locale, m in loc.items() if m.full_description is not None
                },
                "icon": {
                    locale: {
                        "name": f"/{app.appid}/{locale}/{m.icon_file.path.name}",
                        "sha256": m.icon_file.sha256,
                        "size": m.icon_file.size,
                    } for locale, m in loc.items() if m.icon_file
                },
                "preferredSigner": signer,
            },
            "versions": v2_versions(apks[app.appid]),
        }
    return data


# FIXME
# FIXME: sort by group, signer, version_code
def v2_versions(apks: Dict[int, Apk]) -> Dict[str, Any]:
    """Create v2 index app versions data."""
    data = {}
    for apk in apks.values():
        man = apk.manifest
        features = [{"name": f.name} for f in man.features]
        permissions = [
            {"name": p.name, "maxSdkVersion": p.maxSdkVersion}
            if p.maxSdkVersion is not None else {"name": p.name}
            for p in man.permissions
        ]
        manifest = {
            "versionName": man.version_name,
            "versionCode": man.version_code,
            "features": features,
            "usesSdk": {
                "minSdkVersion": man.min_sdk,
                "targetSdkVersion": man.target_sdk,
            },
            "signer": {"sha256": apk.signing_keys},
            "usesPermission": permissions,
        }
        if not manifest["features"]:
            del manifest["features"]
        if not manifest["usesPermission"]:
            del manifest["usesPermission"]
        data[apk.sha256] = {
            "added": apk.added,
            "file": {
                "name": f"/{PurePath(apk.filename).name}",
                "sha256": apk.sha256,
                "size": apk.size,
            },
            "manifest": manifest,
        }
    return data


# FIXME: diffs
def v2_entry(ts: int, packages: int, index_info: FileInfo,
             diffs: Dict[int, Tuple[FileInfo, int]]) -> Dict[str, Any]:
    """Create v2 entry data."""
    return {
        "timestamp": ts,
        "version": 20002,
        "index": {
            "name": f"/{index_info.path.name}",
            "sha256": index_info.sha256,
            "size": index_info.size,
            "numPackages": packages,
        },
        "diffs": {
            str(t): {
                "name": f"/diff/{i.path.name}",
                "sha256": i.sha256,
                "size": i.size,
                "numPackages": n,
            } for t, (i, n) in diffs.items()
        },
    }


def load_timestamps(parent_dir: Path) -> Dict[str, int]:
    """Load timestamps.json."""
    try:
        with (parent_dir / "timestamps.json").open(encoding="utf-8") as fh:
            return json.load(fh)    # type: ignore[no-any-return]
    except FileNotFoundError:
        return {}


def save_timestamps(parent_dir: Path, timestamps: Dict[str, int]) -> None:
    """Save timestamps.json."""
    with (parent_dir / "timestamps.json").open("w", encoding="utf-8") as fh:
        json.dump(timestamps, fh, indent=2)
        fh.write("\n")


def sign_index(repo_dir: Path, cfg: Config, *, verbose: int = 0,
               java_stuff: Optional[JavaStuff] = None) -> None:
    """Sign index."""
    index_v1 = repo_dir / "index-v1.json"
    entry = repo_dir / "entry.json"
    if verbose:
        print("Signing index-v1.jar...")
    create_and_sign_jar(cfg, index_v1, index_v1.with_suffix(".jar"), java_stuff=java_stuff)
    if verbose:
        print("Signing entry.jar...")
    create_and_sign_jar(cfg, entry, entry.with_suffix(".jar"), java_stuff=java_stuff)


def create_and_sign_jar(cfg: Config, json_file: Path, jar_file: Path, *,
                        java_stuff: Optional[JavaStuff] = None) -> None:
    """Create & sign JAR."""
    with json_file.open("rb") as fhi:
        with zipfile.ZipFile(str(jar_file), "w", compression=zipfile.ZIP_DEFLATED) as zf:
            with zf.open(json_file.name, "w") as fho:
                while data := fhi.read(4096):
                    fho.write(data)
    sign_jar(cfg, jar_file, java_stuff=java_stuff)


def sign_jar(cfg: Config, jar_file: Path, *, java_stuff: Optional[JavaStuff] = None) -> None:
    """Sign JAR w/ apksigner."""
    if not java_stuff:
        java_stuff = JavaStuff.load()
    args = [java_stuff.java, "-jar", java_stuff.apksigner_jar, "sign",
            "--ks", cfg.keystore, "--ks-key-alias", cfg.repo_keyalias,
            "--ks-pass", "env:APKREPOTOOL_KS_PASS", "--key-pass", "env:APKREPOTOOL_KEY_PASS",
            "--min-sdk-version=23", "--max-sdk-version=24", "--v1-signing-enabled=true",
            "--v2-signing-enabled=false", "--v3-signing-enabled=false"]
    if 4 in java_stuff.apksigner_supported_schemes:
        args.append("--v4-signing-enabled=false")
    args.append(str(jar_file))
    ks_pass, key_pass = get_passwords(cfg.keystorepass_cmd, cfg.keypass_cmd)
    env = dict(APKREPOTOOL_KS_PASS=ks_pass, APKREPOTOOL_KEY_PASS=key_pass)
    try:
        out, err = run_command(*args, env=env)
    except subprocess.CalledProcessError as e:
        raise Error(f"Signing with apksigner failed: {e}") from e
    except FileNotFoundError as e:
        raise Error(f"Could not run apksigner: {e}") from e


def get_passwords(keystorepass_cmd: str, keypass_cmd: str) -> Tuple[str, str]:
    r"""
    Get passwords by running keystorepass_cmd & keypass_cmd.

    >>> get_passwords("echo foo", "echo bar")
    ('foo', 'bar')

    """
    try:
        keystorepass_out = subprocess.run(keystorepass_cmd, check=True, shell=True,
                                          stdout=subprocess.PIPE).stdout
        keypass_out = subprocess.run(keypass_cmd, check=True, shell=True,
                                     stdout=subprocess.PIPE).stdout
    except subprocess.CalledProcessError as e:
        raise Error(f"Password command failed: {e}") from e
    except FileNotFoundError as e:
        raise Error(f"Could not run password command: {e}") from e
    return keystorepass_out.decode().strip("\r\n"), keypass_out.decode().strip("\r\n")


def get_apksigner_supported_schemes(apksigner_jar: str, java: str) -> List[int]:
    r"""
    Check what signature schemes apksigner supports.

    >>> get_apksigner_supported_schemes(get_apksigner_jar(), get_java()[0])
    [1, 2, 3, 4]

    """
    args = (java, "-jar", apksigner_jar, "sign", "--help")
    try:
        out = subprocess.run(args, check=True, stdout=subprocess.PIPE).stdout
    except subprocess.CalledProcessError as e:
        raise Error(f"Getting apksigner help failed: {e}") from e
    except FileNotFoundError as e:
        raise Error(f"Could not run apksigner: {e}") from e
    versions = []
    for v in (1, 2, 3, 4):
        if f"--v{v}-signing-enabled".encode() in out:
            versions.append(v)
    return versions


def run_command(*args: str, env: Optional[Dict[str, str]] = None, keepenv: bool = True,
                merged: bool = False, verbose: bool = False) -> Tuple[str, str]:
    r"""
    Run command and capture stdout + stderr.

    >>> run_command("echo", "OK")
    ('OK\n', '')
    >>> run_command("bash", "-c", "echo OK >&2")
    ('', 'OK\n')
    >>> run_command("bash", "-c", "echo OK >&2", merged=True)
    ('OK\n', None)
    >>> run_command("bash", "-c", "echo out; echo err >&2")
    ('out\n', 'err\n')
    >>> os.environ["_TEST"] = "foo"
    >>> run_command("env", env=dict(TEST="bar"), keepenv=False)
    ('TEST=bar\n', '')
    >>> lines = run_command("env", env=dict(TEST="bar"))[0].splitlines()
    >>> "TEST=bar" in lines
    True
    >>> "_TEST=foo" in lines
    True
    >>> try:
    ...     run_command("false")
    ... except subprocess.CalledProcessError as e:
    ...     print(e)
    Command '('false',)' returned non-zero exit status 1.

    """
    if verbose:
        print(f"Running {' '.join(args)!r}...", file=sys.stderr)
    stderr = subprocess.STDOUT if merged else subprocess.PIPE
    kwargs: Dict[str, Any] = {}
    if env is not None:
        kwargs["env"] = {**os.environ, **env} if keepenv else env
    cmd = subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=stderr, **kwargs)
    out = cmd.stdout.decode()
    err = cmd.stderr.decode() if not merged else None
    return out, err


# FIXME
# def do_init() -> None:
#     """Create a new repo."""
#     raise NotImplementedError("FIXME")


# FIXME
# FIXME: --pretty, --no-sign
def do_update(verbose: int = 0) -> None:
    """Update index."""
    java_stuff = JavaStuff.load()
    cur_dir = Path(".")
    meta_dir = Path("metadata")
    repo_dir = Path("repo")
    config_file = Path("config.yml")
    config_dir = Path("config")
    timestamp = int(time.time()) * 1000
    cfg = parse_config_yaml(config_file)
    localised_cfgs = parse_localised_config_yaml(config_dir) if config_dir.exists() else {}
    apks: Dict[str, Dict[int, Apk]] = {}
    apps, meta, aask, one_signer_only = [], {}, {}, {}
    times: Dict[str, Set[int]] = {}
    recipes = sorted(meta_dir.glob("*.yml"))
    appids = set(recipe.stem for recipe in recipes)
    timestamps = load_timestamps(cur_dir)
    if verbose > 1:
        print(f"Config locales: {list(localised_cfgs.keys())}.")
    for apkfile in sorted(repo_dir.glob("*.apk")):
        if verbose:
            print(f"Processing {str(apkfile)!r}...")
        if apkfile.name not in timestamps:
            timestamps[apkfile.name] = timestamp
        apk = get_apk_info(apkfile, timestamps[apkfile.name], java_stuff=java_stuff)
        man = apk.manifest
        if verbose:
            print(f"  {man.appid!r}:{man.version_code} ({man.version_name!r})")
        if man.appid not in appids:
            raise Error(f"APK without recipe: {str(apkfile)!r} ({man.appid!r})")
        if man.appid not in apks:
            apks[man.appid] = {}
        if man.version_code in apks[man.appid]:
            raise Error(f"Duplicate version code: {man.appid!r}:{man.version_code}")
        apks[man.appid][man.version_code] = apk
        if man.appid not in times:
            times[man.appid] = set()
        times[man.appid].add(timestamps[apkfile.name])
    save_timestamps(cur_dir, timestamps)
    for recipe in recipes:
        if verbose:
            print(f"Processing {str(recipe)!r}...")
        appid = recipe.stem
        if appid not in apks:
            raise Error(f"recipe without APKs: {appid!r}")
        version_codes = sorted(apks[appid].keys())
        app = parse_recipe_yaml(recipe, version_codes[-1])
        app_dir = recipe.with_suffix("")
        if app_dir.exists():
            meta[appid] = parse_app_metadata(app_dir, repo_dir, version_codes)
            if verbose > 1:
                print(f"  Metadata locales: {list(meta[appid].keys())}.")
        if not app.allowed_apk_signing_keys:
            print(f"Warning: no allowed signing keys specified for {appid!r}", file=sys.stderr)
        aask[appid] = app.allowed_apk_signing_keys
        one_signer_only[appid] = app.one_signer_only
        apps.append(app)
    for appid, versions in apks.items():
        for apk in versions.values():
            if len(apk.signing_keys) > 1:
                if one_signer_only[appid]:
                    raise Error(f"Multiple signers for {appid!r}: {apk.signing_keys}")
                print(f"Warning: multiple signers for {appid!r}: {apk.signing_keys}", file=sys.stderr)
            if signers := aask[appid]:
                if apk.signing_keys[0] not in signers:
                    raise Error(f"Unallowed signer for {appid!r}: {apk.signing_keys[0]}")
    added = {k: min(v) for k, v in times.items()}
    updated = {k: max(v) for k, v in times.items()}
    make_index(repo_dir=repo_dir, apps=apps, apks=apks, meta=meta, cfg=cfg,
               localised_cfgs=localised_cfgs, added=added, updated=updated,
               ts=timestamp, verbose=verbose)
    sign_index(repo_dir, cfg, verbose=verbose, java_stuff=java_stuff)


# FIXME
def main() -> None:
    """CLI; requires click."""

    import click

    @click.group(help="""
        apkrepotool - manage APK repos
    """)
    @click.version_option(__version__)
    def cli() -> None:
        pass

    # @cli.command(help="""
    #     create a new repo
    # """)
    # def init(*args: Any, **kwargs: Any) -> None:
    #     do_init(*args, **kwargs)

    @cli.command(help="""
        generate/update index
    """)
    @click.option("-v", "--verbose", count=True, help="Increase verbosity.")
    def update(*args: Any, **kwargs: Any) -> None:
        do_update(*args, **kwargs)

    try:
        cli(prog_name=NAME)
    except (Error, binres.Error) as e:
        print(f"Error: {e}.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
