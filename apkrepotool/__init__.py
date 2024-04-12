#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
apkrepotool - manage APK repos

FIXME
"""

import binascii
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any, Dict, List, Optional, Tuple

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

import com.android.apksig.ApkVerificationIssue;
import com.android.apksig.ApkVerifier;
import com.android.apksig.apk.ApkFormatException;

public class Cert {
  public static void main(String[] args) {
    try {
      ApkVerifier.Builder builder = new ApkVerifier.Builder(new File(args[0]));
      ApkVerifier.Result result = builder.build().verify();
      if (result.isVerified()) {
        byte[] cert = result.getSignerCertificates().get(0).getEncoded();
        String versions = String.join(",",
          "v1=" + (result.isVerifiedUsingV1Scheme() ? "true" : "false"),
          "v2=" + (result.isVerifiedUsingV2Scheme() ? "true" : "false"),
          "v3=" + (result.isVerifiedUsingV3Scheme() ? "true" : "false"));
        System.out.write(("verified\n" + versions + "\n" + cert.length + "\n").getBytes("UTF-8"));
        System.out.write(cert);
      } else {
        for (ApkVerificationIssue error : result.getErrors()) {
          System.err.println("ERROR: " + error);
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


# FIXME
@dataclass(frozen=True)
class App:
    """App."""
    name: str
    appid: str
    allowed_apk_signing_keys: List[str]
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
    signing_key: str
    fdroid_sig: str
    manifest: Manifest


# FIXME
@dataclass(frozen=True)
class Config:
    """Config."""
    repo_url: str
    repo_name: str
    repo_description: str
    # repo_keyalias: str
    # keystore: str
    # keystorepass: str
    # keypass: str
    # keydname: str


# FIXME
@dataclass(frozen=True)
class LocalisedConfig:
    """Localised config."""
    repo_name: str
    repo_description: str


# FIXME
@dataclass(frozen=True)
class Metadata:
    """App metadata."""
    title: Optional[str]
    short_description: Optional[str]
    full_description: Optional[str]
    changelogs: Dict[int, str]
    icon_file: Optional[Path]
    feature_graphic_file: Optional[Path]
    phone_screenshots_files: List[Path]


# FIXME
def parse_recipe_yaml(recipe_file: Path, latest_version_code: int) -> App:
    r"""
    Parse recipe YAML.

    >>> parse_recipe_yaml(Path("test/metadata/android.appsecurity.cts.tinyapp.yml"), 10)
    App(name='TestApp', appid='android.appsecurity.cts.tinyapp', allowed_apk_signing_keys=['fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8'], current_version_code=10, current_version_name=None)

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
        cvc = data.get("CurrentVersionCode", latest_version_code)
        cvn = data.get("CurrentVersion")
        return App(name=name, appid=appid, allowed_apk_signing_keys=allowed_apk_signing_keys,
                   current_version_code=cvc, current_version_name=cvn)


# FIXME
def parse_config_yaml(config_file: Path) -> Config:
    r"""
    Parse config YAML.

    >>> parse_config_yaml(Path("test/config.yml"))
    Config(repo_url='https://example.com/fdroid/repo', repo_name='My Repo', repo_description='This is a repository of apps to be used with an F-Droid-compatible client. Applications in this repository are official binaries built by the original application developers.')

    """
    with config_file.open(encoding="utf-8") as fh:
        yaml = YAML(typ="safe")
        data = yaml.load(fh)
        return Config(repo_url=data["repo_url"], repo_name=data["repo_name"],
                      repo_description=data["repo_description"])


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
# FIXME: metadata/<app>/<locale>/images/ vs repo/<app>/<locale>/ (& hashes)
def parse_app_metadata(app_dir: Path, version_codes: List[int]) -> Dict[str, Metadata]:
    r"""
    Parse (fastlane) metadata.

    >>> app_dir = Path("test/metadata/android.appsecurity.cts.tinyapp")
    >>> meta = parse_app_metadata(app_dir, [10])
    >>> sorted(meta.keys())
    ['en-US']
    >>> meta["en-US"]
    Metadata(title='title', short_description='short description', full_description='full description\n', changelogs={10: 'changelog for version code 10\n'}, icon_file=PosixPath('test/metadata/android.appsecurity.cts.tinyapp/en-US/images/icon.png'), feature_graphic_file=PosixPath('test/metadata/android.appsecurity.cts.tinyapp/en-US/images/featureGraphic.png'), phone_screenshots_files=[PosixPath('test/metadata/android.appsecurity.cts.tinyapp/en-US/images/phoneScreenshots/01.png'), PosixPath('test/metadata/android.appsecurity.cts.tinyapp/en-US/images/phoneScreenshots/02.png')])

    """
    metadata = {}
    for locale_dir in sorted(app_dir.iterdir()):
        title_path = locale_dir / "title.txt"
        short_desc_path = locale_dir / "short_description.txt"
        full_desc_path = locale_dir / "full_description.txt"
        changelog_dir = locale_dir / "changelogs"
        images_dir = locale_dir / "images"
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
        if images_dir.exists():
            icon_path = images_dir / "icon.png"
            fg_path = images_dir / "featureGraphic.png"
            ps_dir = images_dir / "phoneScreenshots"
            icon_file = icon_path if icon_path.exists() else None
            fg_file = fg_path if fg_path.exists() else None
            ps_files = sorted(ps_dir.glob("*.png")) if ps_dir.exists() else []
        else:
            icon_file, fg_file, ps_files = None, None, []
        metadata[locale_dir.name] = Metadata(
            title=title, short_description=short_desc, full_description=full_desc,
            changelogs=changelogs, icon_file=icon_file, feature_graphic_file=fg_file,
            phone_screenshots_files=ps_files)
    return metadata


# FIXME
def get_apk_info(apkfile: Path) -> Apk:
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
    signing_key='fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8'
    fdroid_sig='506ceb2a3116981827a3990f3446d3af'

    """
    size = apkfile.stat().st_size
    cert, _ = get_signing_cert(apkfile)
    fingerprint = hashlib.sha256(cert).hexdigest()
    sig = hashlib.md5(binascii.hexlify(cert)).hexdigest()
    return Apk(filename=str(apkfile), size=size, sha256=get_sha256(apkfile),
               signing_key=fingerprint, fdroid_sig=sig, manifest=get_manifest(apkfile))


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


def get_signing_cert(apkfile: Path) -> Tuple[bytes, Dict[str, bool]]:
    r"""
    Get APK signing key certificate using apksigner JAR.

    NB: this validates the signature(s)!

    >>> cert, vsns = get_signing_cert(Path("test/repo/golden-aligned-v1v2v3-out.apk"))
    >>> len(cert)
    765
    >>> vsns
    {'v1': True, 'v2': True, 'v3': True}

    """
    java, javac = get_java()
    apksigner_jar = get_apksigner_jar()
    cert_java = get_cert_java(apksigner_jar, javac)
    if cert_java.suffix == ".java":
        cert_arg = str(cert_java)
        classpath = apksigner_jar
    else:
        cert_arg = cert_java.stem
        classpath = f"{cert_java.parent}:{apksigner_jar}"
    args = (java, "-classpath", classpath, cert_arg, str(apkfile))
    try:
        out = subprocess.run(args, check=True, stdout=subprocess.PIPE).stdout
    except subprocess.CalledProcessError as e:
        raise SigError(f"Verification with apksigner failed: {e}") from e
    except FileNotFoundError as e:
        raise Error(f"Could not run apksigner: {e}") from e
    try:
        verified, versions, size, cert = out.split(b"\n", 3)
    except ValueError:
        raise SigError("Verification output mismatch")      # pylint: disable=W0707
    if verified != b"verified" or int(size) != len(cert):
        raise SigError("Verification output mismatch")
    vsns = {k: v == "true" for kv in versions.decode().split(",") for k, v in [kv.split("=")]}
    return cert, vsns


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
# FIXME: entry.json, signed .jar, diff/*.json
def make_index(repo_dir: Path, apps: List[App], apks: Dict[str, Dict[int, Apk]],
               meta: Dict[str, Dict[str, Metadata]], cfg: Config,
               localised_cfgs: Dict[str, LocalisedConfig]) -> None:
    """Create & write v1 & v2 index."""
    ts = int(time.time()) * 1000
    v1_data = v1_index(apps, apks, meta, ts, cfg)
    v2_data = v2_index(apps, apks, meta, ts, cfg, localised_cfgs)
    with (repo_dir / "index-v1.json").open("w", encoding="utf-8") as fh:
        json.dump(v1_data, fh, indent=2)
        fh.write("\n")
    with (repo_dir / "index-v2.json").open("w", encoding="utf-8") as fh:
        json.dump(v2_data, fh, indent=2)
        fh.write("\n")


# FIXME
# FIXME: use localised config if it exists; ensure identical if both do
def v1_index(apps: List[App], apks: Dict[str, Dict[int, Apk]],
             meta: Dict[str, Dict[str, Metadata]], ts: int, cfg: Config) -> Dict[str, Any]:
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
        "apps": v1_apps(apps, meta),
        "packages": v1_packages(apks),
    }


# FIXME
def v1_apps(apps: List[App], meta: Dict[str, Dict[str, Metadata]]) -> List[Dict[str, Any]]:
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
            "added": 0,                             # FIXME
            "packageName": app.appid,
            "lastUpdated": 0,                       # FIXME
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
            "featureGraphic": meta.feature_graphic_file.name if meta.feature_graphic_file else None,
            "icon": meta.icon_file.name if meta.icon_file else None,
            "name": meta.title,
            "phoneScreenshots": [
                file.name for file in meta.phone_screenshots_files
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
                "added": 0,                         # FIXME
                "apkName": PurePath(apk.filename).name,
                "features": [f.name for f in man.features] or None,
                "hash": apk.sha256,
                "hashType": "sha256",
                "minSdkVersion": man.min_sdk,
                "packageName": man.appid,
                "sig": apk.fdroid_sig,
                "signer": apk.signing_key,
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
def v2_index(apps: List[App], apks: Dict[str, Dict[int, Apk]],
             meta: Dict[str, Dict[str, Metadata]], ts: int, cfg: Config,
             localised_cfgs: Dict[str, LocalisedConfig]) -> Dict[str, Any]:
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
        "packages": v2_packages(apps, apks, meta),
    }


# FIXME
# FIXME: hashed graphics files, sha256 & size
def v2_packages(apps: List[App], apks: Dict[str, Dict[int, Apk]],
                meta: Dict[str, Dict[str, Metadata]]) -> Dict[str, Any]:
    """Create v2 index packages data."""
    data = {}
    for app in apps:
        loc = meta[app.appid]
        mv = max(apks[app.appid].keys())
        signer = apks[app.appid][mv].signing_key    # FIXME: sort by ...
        data[app.appid] = {
            "metadata": {
                "added": 0,                         # FIXME
                "lastUpdated": 0,                   # FIXME
                "featureGraphic": {
                    locale: {
                        "name": f"/{app.appid}/{locale}/{m.feature_graphic_file.name}",
                        "sha256": "FIXME",          # FIXME
                        "size": 0,                  # FIXME
                    } for locale, m in loc.items() if m.feature_graphic_file
                },
                "screenshots": {
                    "phone": {
                        locale: [
                            {
                                "name": f"/{app.appid}/{locale}/phoneScreenshots/{file.name}",
                                "sha256": "FIXME",  # FIXME
                                "size": 0,          # FIXME
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
                        "name": f"/{app.appid}/{locale}/{m.icon_file.name}",
                        "sha256": "FIXME",          # FIXME
                        "size": 0,                  # FIXME
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
            "signer": {"sha256": [apk.signing_key]},
            "usesPermission": permissions,
        }
        if not manifest["features"]:
            del manifest["features"]
        if not manifest["usesPermission"]:
            del manifest["usesPermission"]
        data[apk.sha256] = {
            "added": 0,                             # FIXME
            "file": {
                "name": f"/{PurePath(apk.filename).name}",
                "sha256": apk.sha256,
                "size": apk.size,
            },
            "manifest": manifest,
        }
    return data


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
def do_init() -> None:
    """Create a new repo."""
    raise NotImplementedError("FIXME")


# FIXME
def do_update(verbose: bool = False) -> None:
    """Update index."""
    meta_dir = Path("metadata")
    repo_dir = Path("repo")
    config_file = Path("config.yml")
    config_dir = Path("config")
    cfg = parse_config_yaml(config_file)
    localised_cfgs = parse_localised_config_yaml(config_dir) if config_dir.exists() else {}
    apks: Dict[str, Dict[int, Apk]] = {}
    apps, meta, aask = [], {}, {}
    recipes = sorted(meta_dir.glob("*.yml"))
    appids = set(recipe.stem for recipe in recipes)
    for apkfile in sorted(repo_dir.glob("*.apk")):
        if verbose:
            print(f"Processing {str(apkfile)!r}...")
        apk = get_apk_info(apkfile)
        man = apk.manifest
        if verbose:
            print(f"  {man.appid!r}:{man.version_code} ({man.version_name!r})")
        if man.appid not in appids:
            raise Error(f"APK without recipe: {man.appid}")
        if man.appid not in apks:
            apks[man.appid] = {}
        if man.version_code in apks[man.appid]:
            raise Error(f"Duplicate: {man.appid}:{man.version_code}")
        apks[man.appid][man.version_code] = apk
    for recipe in recipes:
        if verbose:
            print(f"Processing {str(recipe)!r}...")
        appid = recipe.stem
        if appid not in apks:
            raise Error(f"recipe without APKs: {appid}")
        version_codes = sorted(apks[appid].keys())
        app = parse_recipe_yaml(recipe, version_codes[-1])
        app_dir = recipe.with_suffix("")
        if app_dir.exists():
            meta[appid] = parse_app_metadata(app_dir, version_codes)
        if not app.allowed_apk_signing_keys:
            print(f"Warning: no allowed signing keys specified for {appid}", file=sys.stderr)
        aask[appid] = app.allowed_apk_signing_keys
        apps.append(app)
    for appid, versions in apks.items():
        for apk in versions.values():
            if signers := aask[apk.manifest.appid]:
                if apk.signing_key not in signers:
                    raise Error(f"Unallowed signer for {apk.manifest.appid}: {apk.signing_key}")
    make_index(repo_dir, apps, apks, meta, cfg, localised_cfgs)


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

    @cli.command(help="""
        create a new repo
    """)
    def init(*args: Any, **kwargs: Any) -> None:
        do_init(*args, **kwargs)

    @cli.command(help="""
        update index
    """)
    @click.option("-v", "--verbose", is_flag=True, help="Be verbose.")
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
