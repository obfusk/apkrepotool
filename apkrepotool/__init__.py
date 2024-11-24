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

import base64
import binascii
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile

from dataclasses import field
from pathlib import Path, PurePath
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import repro_apk.binres as binres

from ruamel.yaml import YAML

try:
    from pydantic.dataclasses import dataclass
except ImportError:
    print("Warning: pydantic not available, validation disabled.", file=sys.stderr)
    from dataclasses import dataclass   # type: ignore[no-redef]

__version__ = "0.0.1"
NAME = "apkrepotool"

if os.environ.get("APKREPOTOOL_DIR"):
    APKREPOTOOL_DIR = Path(os.environ["APKREPOTOOL_DIR"])
else:
    APKREPOTOOL_DIR = Path.home() / ".apkrepotool"

DEFAULT_LOCALE = "en-US"

CLEAN_LANG_ENV = dict(LC_ALL="C.UTF-8", LANG="", LANGUAGE="")

SDK_ENV = ("ANDROID_HOME", "ANDROID_SDK", "ANDROID_SDK_ROOT")
SDK_JAR = "lib/apksigner.jar"

APKSIGNER_JARS = ("/usr/share/java/apksigner.jar", "/usr/lib/android-sdk/build-tools/debian/apksigner.jar")
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
CERT_JAVA_SHA256 = hashlib.sha256(CERT_JAVA_CODE.encode()).hexdigest()


class Error(Exception):
    """Base class for errors."""


class SigError(Error):
    """Signature (verification) error."""


@dataclass(frozen=True)
class JavaStuff:
    """Java Stuff."""
    java: str
    javac: Optional[str]
    keytool: str
    apksigner_jar: str
    apksigner_supported_schemes: List[int]
    cert_java: Path

    @classmethod
    def load(_cls, cfg: Optional[Config] = None, verbose: int = 0) -> JavaStuff:
        """Create from get_apksigner_jar(), get_java(), get_cert_java()."""
        art_dir = Path(cfg.apkrepotool_dir) if cfg and cfg.apkrepotool_dir else None
        jars = [cfg.apksigner_jar] if cfg and cfg.apksigner_jar else None
        java_home = cfg.java_home if cfg else None
        java, javac, keytool = get_java(java_home=java_home)
        apksigner_jar = get_apksigner_jar(jars=jars)
        schemes = get_apksigner_supported_schemes(apksigner_jar, java)
        cert_java = get_cert_java(apksigner_jar, javac, apkrepotool_dir=art_dir, verbose=verbose)
        if verbose > 1:
            print(f"Using apksigner JAR {apksigner_jar!r}.")
        return JavaStuff(java=java, javac=javac, keytool=keytool, apksigner_jar=apksigner_jar,
                         apksigner_supported_schemes=schemes, cert_java=cert_java)


# FIXME
@dataclass(frozen=True)
class App:
    """App."""
    appid: str
    name: str
    current_version_code: int
    current_version_name: Optional[str] = None
    allowed_apk_signing_keys: List[str] = field(default_factory=list)
    anti_features: Dict[str, Dict[str, str]] = field(default_factory=dict)
    categories: List[str] = field(default_factory=list)
    one_signer_only: bool = True
    author_email: Optional[str] = None
    author_name: Optional[str] = None
    author_website_url: Optional[str] = None
    changelog_url: Optional[str] = None
    donate_url: Optional[str] = None
    issue_tracker_url: Optional[str] = None
    license: Optional[str] = None
    source_code_url: Optional[str] = None
    translation_url: Optional[str] = None
    website_url: Optional[str] = None


@dataclass(frozen=True)
class Feature:
    """AndroidManifest.xml uses-feature."""
    name: str


@dataclass(frozen=True)
class Permission:
    """AndroidManifest.xml uses-permission."""
    name: str
    min_sdk_version: Optional[int]
    max_sdk_version: Optional[int]


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
    abis: List[str]


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
    apkrepotool_dir: Optional[str] = None
    apksigner_jar: Optional[str] = None
    java_home: Optional[str] = None


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
    title: Optional[str] = None
    short_description: Optional[str] = None
    full_description: Optional[str] = None
    changelogs: Dict[int, str] = field(default_factory=dict)
    icon_file: Optional[FileInfo] = None
    feature_graphic_file: Optional[FileInfo] = None
    phone_screenshots_files: List[FileInfo] = field(default_factory=list)


# FIXME
def parse_recipe_yaml(recipe_file: Path, latest_version_code: int) -> App:
    r"""
    Parse recipe YAML.

    >>> import dataclasses
    >>> app = parse_recipe_yaml(Path("test/metadata/android.appsecurity.cts.tinyapp.yml"), 10)
    >>> for field in dataclasses.fields(app):
    ...     print(f"{field.name}={getattr(app, field.name)!r}")
    appid='android.appsecurity.cts.tinyapp'
    name='TestApp'
    current_version_code=10
    current_version_name='1.0'
    allowed_apk_signing_keys=['fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8']
    anti_features={}
    categories=['Development']
    one_signer_only=True
    author_email='google@example.com'
    author_name='Google'
    author_website_url='https://authorwebsite.example.com/'
    changelog_url='https://git.example.com/test/app/blob/HEAD/CHANGELOG.md'
    donate_url='https://donate.example.com/'
    issue_tracker_url='https://git.example.com/test/app/issues'
    license='Apache-2.0'
    source_code_url='https://git.example.com/test/app'
    translation_url='https://weblate.example.com/projects/test/app'
    website_url='https://website.example.com/'

    """
    appid = recipe_file.stem
    with recipe_file.open(encoding="utf-8") as fh:
        yaml = YAML(typ="safe")
        data = yaml.load(fh)
        aask = []
        anti_features: Dict[str, Dict[str, str]] = {}
        if "AllowedAPKSigningKeys" in data:
            if isinstance(data["AllowedAPKSigningKeys"], str):
                aask = [data["AllowedAPKSigningKeys"]]
            else:
                aask = data["AllowedAPKSigningKeys"]
        if "AntiFeatures" in data:
            if isinstance(data["AntiFeatures"], list):
                anti_features = {k: {} for k in data["AntiFeatures"]}
            else:
                anti_features = data["AntiFeatures"]
        if "Name" in data:
            name = data["Name"]
        elif "AutoName" in data:
            name = data["AutoName"]
        else:
            raise NotImplementedError("FIXME: cannot get name from APK yet")
        return App(
            appid=appid, name=name,
            current_version_code=data.get("CurrentVersionCode", latest_version_code),
            current_version_name=data.get("CurrentVersion"),
            allowed_apk_signing_keys=aask, anti_features=anti_features,
            categories=data.get("Categories", []), one_signer_only=data.get("OneSignerOnly", True),
            author_email=data.get("AuthorEmail"), author_name=data.get("AuthorName"),
            author_website_url=data.get("AuthorWebSite"), changelog_url=data.get("Changelog"),
            donate_url=data.get("Donate"), issue_tracker_url=data.get("IssueTracker"),
            license=data.get("License"), source_code_url=data.get("SourceCode"),
            translation_url=data.get("Translation"), website_url=data.get("WebSite"))


# FIXME
def parse_config_yaml(config_file: Path) -> Config:
    r"""
    Parse config YAML.

    >>> import dataclasses
    >>> cfg = parse_config_yaml(Path("test/config.yml"))
    >>> for field in dataclasses.fields(cfg):
    ...     print(f"{field.name}={getattr(cfg, field.name)!r}")
    repo_url='https://example.com/fdroid/repo/'
    repo_name='My Repo'
    repo_description='This is a repository of apps to be used with an F-Droid-compatible client. Applications in this repository are official binaries built by the original application developers.'
    repo_keyalias='myrepo'
    keystore='/path/to/keystore.jks'
    keystorepass_cmd='cat /path/to/.keystorepass'
    keypass_cmd='cat /path/to/.keypass'
    apkrepotool_dir='/path/to/apkrepotool_dir'
    apksigner_jar='/path/to/apksigner.jar'
    java_home='/usr/lib/jvm/java-11-openjdk-amd64'

    """
    with config_file.open(encoding="utf-8") as fh:
        yaml = YAML(typ="safe")
        data = yaml.load(fh)
        return Config(
            repo_url=data["repo_url"], repo_name=data["repo_name"],
            repo_description=data["repo_description"], repo_keyalias=data["repo_keyalias"],
            keystore=data["keystore"], keystorepass_cmd=data["keystorepass_cmd"],
            keypass_cmd=data["keypass_cmd"], apkrepotool_dir=data.get("apkrepotool_dir"),
            apksigner_jar=data.get("apksigner_jar"), java_home=data.get("java_home"))


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
    icon_file=FileInfo(path=PosixPath('test/repo/android.appsecurity.cts.tinyapp/en-US/icon_47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=.png'), size=0, sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    feature_graphic_file=FileInfo(path=PosixPath('test/repo/android.appsecurity.cts.tinyapp/en-US/featureGraphic_47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=.png'), size=0, sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
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
            icon_file = hashed_image(icon_path) if icon_path.exists() else None
            fg_file = hashed_image(fg_path) if fg_path.exists() else None
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
    abis=['armeabi']

    """
    m = binres.get_manifest_info_apk(str(apkfile))
    assert m.abis is not None
    features = [Feature(f.name) for f in m.features if f.required]
    permissions = [Permission(p.name, p.min_sdk_version, p.max_sdk_version) for p in m.permissions]
    return Manifest(appid=m.appid, version_code=m.version_code, version_name=m.version_name,
                    min_sdk=m.min_sdk, target_sdk=m.target_sdk,
                    features=sorted(features, key=lambda f: f.name),
                    permissions=sorted(permissions, key=lambda p: p.name), abis=m.abis)


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
def get_cert_java(apksigner_jar: str, javac: Optional[str], *,
                  apkrepotool_dir: Optional[Path] = None, verbose: int = 0) -> Path:
    r"""
    Get path to Cert.java or Cert.class.

    Cert.java is saved in $APKREPOTOOL_DIR (~/.apkrepotool) and compiled to
    Cert.class with javac if available.

    >>> str(APKREPOTOOL_DIR)
    '.tmp'
    >>> p1 = get_cert_java(get_apksigner_jar(), get_java()[1])
    >>> str(p1)
    '.tmp/Cert.class'
    >>> subdir = Path(".tmp/subdir")
    >>> p2 = get_cert_java(get_apksigner_jar(), get_java()[1], apkrepotool_dir=subdir)
    >>> str(p2)
    '.tmp/subdir/Cert.class'
    >>> get_sha256(p1.with_suffix(".java"))
    'bebfc0ffb1668995fdb5ef40df59ac939b61441790c4686efae03905eeb951e4'
    >>> get_sha256(p2.with_suffix(".java"))
    'bebfc0ffb1668995fdb5ef40df59ac939b61441790c4686efae03905eeb951e4'
    >>> CERT_JAVA_SHA256
    'bebfc0ffb1668995fdb5ef40df59ac939b61441790c4686efae03905eeb951e4'

    """
    if apkrepotool_dir is None:
        apkrepotool_dir = APKREPOTOOL_DIR
    cert_java = apkrepotool_dir / "Cert.java"
    cert_class = cert_java.with_suffix(".class")
    if not (cert_java.exists() and get_sha256(cert_java) == CERT_JAVA_SHA256):
        apkrepotool_dir.mkdir(mode=0o700, exist_ok=True)
        if verbose:
            print(f"Writing {str(cert_java)!r}...")
        cert_java.write_text(CERT_JAVA_CODE, encoding="utf-8")
        if cert_class.exists():
            cert_class.unlink()
        if javac:
            if verbose:
                print(f"Compiling {str(cert_class)!r}...")
            args = (javac, "-classpath", f"{cert_java.parent}:{apksigner_jar}", str(cert_java))
            subprocess.run(args, check=False)
            if verbose:
                print("  OK" if cert_class.exists() else "  failed")
    return cert_class if cert_class.exists() else cert_java


def get_apksigner_jar(*, jars: Optional[List[str]] = None,
                      env: Optional[Dict[str, str]] = None) -> str:
    r"""
    Find apksigner JAR using $ANDROID_HOME etc.

    >>> get_apksigner_jar()
    '/usr/share/java/apksigner.jar'
    >>> get_apksigner_jar(jars=[], env=dict(ANDROID_HOME="test/fake-sdk"))
    'test/fake-sdk/build-tools/35.0.0-rc1/lib/apksigner.jar'
    >>> get_apksigner_jar(jars=["test/fake-sdk/build-tools/31.0.0/lib/apksigner.jar"])
    'test/fake-sdk/build-tools/31.0.0/lib/apksigner.jar'

    """
    env_get = os.environ.get if env is None else env.get
    if jars is None:
        jars = [env_get("APKSIGNER_JAR") or "", *APKSIGNER_JARS]
    for jar in jars:
        if jar and os.path.exists(jar):
            return jar
    for k in SDK_ENV:
        if home := env_get(k):
            tools = os.path.join(home, "build-tools")
            if os.path.exists(tools):
                for vsn in sorted(os.listdir(tools), key=_vsn, reverse=True):
                    jar = os.path.join(tools, vsn, *SDK_JAR.split("/"))
                    if os.path.exists(jar):
                        return jar
    raise Error("Could not locate apksigner JAR")


def get_java(*, java_home: Optional[str] = None) -> Tuple[str, Optional[str], str]:
    r"""
    Find java, (possibly) javac, and keytool using $JAVA_HOME/$PATH.

    >>> get_java()
    ('/usr/bin/java', '/usr/bin/javac', '/usr/bin/keytool')
    >>> get_java(java_home="/usr/lib/jvm/java-11-openjdk-amd64")
    ('/usr/lib/jvm/java-11-openjdk-amd64/bin/java', '/usr/lib/jvm/java-11-openjdk-amd64/bin/javac', '/usr/lib/jvm/java-11-openjdk-amd64/bin/keytool')

    """
    java = javac = keytool = None
    if not java_home:
        java_home = os.environ.get("JAVA_HOME")
    if java_home:
        java = os.path.join(java_home, "bin/java")
        javac = os.path.join(java_home, "bin/javac")
        keytool = os.path.join(java_home, "bin/keytool")
    if not (java and os.path.exists(java)):
        java = shutil.which("java")
        javac = shutil.which("javac")
        keytool = shutil.which("keytool")
        if not (java and os.path.exists(java)):
            raise Error("Could not locate java")
    if not (keytool and os.path.exists(keytool)):
        raise Error("Could not locate keytool")
    return java, (javac if javac and os.path.exists(javac) else None), keytool


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
# FIXME: --pretty?
def make_index(*, repo_dir: Path, cache_dir: Path, apps: List[App], apks: Dict[str, Dict[int, Apk]],
               meta: Dict[str, Dict[str, Metadata]], cfg: Config,
               localised_cfgs: Dict[str, LocalisedConfig], added: Dict[str, int],
               updated: Dict[str, int], ts: int, pretty: bool = False, verbose: int = 0) -> None:
    """Create & write v1 & v2 index."""
    for p in (repo_dir / "diff", cache_dir / "repo"):
        p.mkdir(parents=True, exist_ok=True)
    icon_path = repo_dir / "icons" / "icon.png"
    if not icon_path.exists():
        raise Error(f"Missing icon file: {str(icon_path)!r}")
    icon = FileInfo.from_path(icon_path)
    v1_data = v1_index(apps=apps, apks=apks, meta=meta, ts=ts, cfg=cfg,
                       added=added, updated=updated)
    v2_data = v2_index(apps=apps, apks=apks, meta=meta, ts=ts, cfg=cfg, localised_cfgs=localised_cfgs,
                       added=added, updated=updated, icon=icon)
    save_json(repo_dir / "index-v1.json", v1_data, ensure_ascii=True, pretty=pretty, verbose=verbose)
    save_json(repo_dir / "index-v2.json", v2_data, pretty=pretty, verbose=verbose)
    diffs = make_diffs(repo_dir, cache_dir, v2_data, pretty=pretty, verbose=verbose)
    entry = v2_entry(ts, len(apps), FileInfo.from_path(repo_dir / "index-v2.json"), diffs)
    save_json(repo_dir / "entry.json", entry, verbose=verbose, pretty=pretty)
    update_cache(cache_dir, v2_data, ts, pretty=pretty, verbose=verbose)


def make_diffs(repo_dir: Path, cache_dir: Path, v2_data: Dict[str, Any], *,
               pretty: bool = False, verbose: int = 0) -> Dict[int, Tuple[FileInfo, int]]:
    """Make v2 diffs."""
    for p in sorted((repo_dir / "diff").glob("*.json")):
        p.unlink()
    diffs = {}
    for p in sorted((cache_dir / "repo").glob("*.json"), key=lambda p: int(p.stem))[-10:]:
        t = int(p.stem)
        d = repo_dir / "diff" / f"{t}.json"
        diff = index_diff(load_json(p), v2_data)
        save_json(d, diff, name=f"diff/{t}.json", pretty=pretty, verbose=verbose)
        diffs[t] = (FileInfo.from_path(d), len(diff.get("packages", [])))
    return diffs


# FIXME: APK cache
def update_cache(cache_dir: Path, v2_data: Dict[str, Any], ts: int, *,
                 pretty: bool = False, verbose: int = 0) -> None:
    """Update cache."""
    save_json(cache_dir / "repo" / f"{ts}.json", v2_data,
              name=f"{cache_dir.name}/repo/{ts}.json", pretty=pretty, verbose=verbose)
    for p in sorted((cache_dir / "repo").glob("*.json"), key=lambda p: int(p.stem))[:-10]:
        p.unlink()


def index_diff(source: Any, target: Any) -> Any:
    """Create diff of index data."""
    if not (isinstance(source, dict) and isinstance(target, dict)):
        return target
    deleted = {k: None for k in source if k not in target}
    added = {k: v for k, v in target.items() if k not in source}
    updated = {k: index_diff(source[k], v) for k, v in target.items()
               if k in source and source[k] != v}
    return {**deleted, **added, **updated}


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
            "allowedAPKSigningKeys": app.allowed_apk_signing_keys,
            "antiFeatures": list(app.anti_features.keys()),
            "authorEmail": app.author_email,
            "authorName": app.author_name,
            "authorWebSite": app.author_website_url,
            "categories": app.categories,
            "changelog": app.changelog_url,
            "suggestedVersionName": app.current_version_name,
            "suggestedVersionCode": str(app.current_version_code),
            "donate": app.donate_url,
            "issueTracker": app.issue_tracker_url,
            "license": app.license or "Unknown",
            "name": app.name,
            "sourceCode": app.source_code_url,
            "translation": app.translation_url,
            "webSite": app.website_url,
            "added": added[app.appid],
            "packageName": app.appid,
            "lastUpdated": updated[app.appid],
            "localized": v1_localised(meta[app.appid], app.current_version_code),
        }
        data.append({k: v for k, v in entry.items() if v})
    return data


# FIXME
def v1_localised(loc: Dict[str, Metadata], current_version_code: int) -> Dict[str, Any]:
    """Create v1 index app localised data."""
    data = {}
    for locale, meta in loc.items():
        entry = {
            "description": meta.full_description,
            "featureGraphic": meta.feature_graphic_file.path.name if meta.feature_graphic_file else None,
            "icon": meta.icon_file.path.name if meta.icon_file else None,
            "name": meta.title,
            "phoneScreenshots": [
                file.path.name for file in meta.phone_screenshots_files
            ],
            "summary": meta.short_description,
            "whatsNew": meta.changelogs.get(current_version_code),
        }
        data[locale] = {k: v for k, v in entry.items() if v}
    return data


# FIXME
# FIXME: sort by appid, group, signer, version_code
def v1_packages(apks: Dict[str, Dict[int, Apk]]) -> Dict[str, List[Any]]:
    """Create v1 index packages data."""
    data: Dict[str, List[Any]] = {}
    for appid, versions in sorted(apks.items(), key=lambda kv: kv[0]):
        for apk in sorted(versions.values(), key=lambda apk: apk.manifest.version_code,
                          reverse=True):
            man = apk.manifest
            if appid not in data:
                data[appid] = []
            entry = {
                "added": apk.added,
                "apkName": PurePath(apk.filename).name,
                "features": [f.name for f in man.features],
                "hash": apk.sha256,
                "hashType": "sha256",
                "minSdkVersion": man.min_sdk,
                "nativecode": man.abis,
                "packageName": man.appid,
                "sig": apk.fdroid_sig,
                "signer": apk.signing_keys[0],
                "size": apk.size,
                "targetSdkVersion": man.target_sdk,
                "uses-permission": [
                    [p.name, p.max_sdk_version] for p in man.permissions
                    if not p.min_sdk_version
                ],
                "uses-permission-sdk-23": [
                    [p.name, p.max_sdk_version] for p in man.permissions
                    if p.min_sdk_version
                ],
                "versionCode": man.version_code,
                "versionName": man.version_name,
            }
            data[appid].append({k: v for k, v in entry.items() if v})
    return data


# FIXME
# FIXME: categories
# FIXME: mirrors etc.
# FIXME: ensure localised config and regular one are identical if both exist
def v2_index(*, apps: List[App], apks: Dict[str, Dict[int, Apk]],
             meta: Dict[str, Dict[str, Metadata]], ts: int, cfg: Config,
             localised_cfgs: Dict[str, LocalisedConfig], added: Dict[str, int],
             updated: Dict[str, int], icon: FileInfo) -> Dict[str, Any]:
    """Create v2 index data."""
    if DEFAULT_LOCALE not in localised_cfgs:
        localised_cfgs = localised_cfgs.copy()
        localised_cfgs[DEFAULT_LOCALE] = LocalisedConfig(
            repo_name=cfg.repo_name, repo_description=cfg.repo_description)
    categories = sorted(set().union(*(set(app.categories) for app in apps)))
    return {
        "repo": {
            "name": {k: v.repo_name for k, v in localised_cfgs.items()},
            "description": {k: v.repo_description for k, v in localised_cfgs.items()},
            "icon": {
                k: {
                    "name": "/icons/icon.png",
                    "sha256": icon.sha256,
                    "size": icon.size,
                } for k, v in localised_cfgs.items()
            },
            "address": cfg.repo_url,
            "timestamp": ts,
            "categories": {c: {"name": {DEFAULT_LOCALE: c}} for c in categories},
        },
        "packages": v2_packages(apps, apks, meta, added, updated),
    }


# FIXME
def v2_packages(apps: List[App], apks: Dict[str, Dict[int, Apk]],
                meta: Dict[str, Dict[str, Metadata]], added: Dict[str, int],
                updated: Dict[str, int]) -> Dict[str, Any]:
    """Create v2 index packages data."""
    data = {}
    for app in apps:
        loc = meta[app.appid]
        mv = max(apks[app.appid].keys())
        signer = apks[app.appid][mv].signing_keys[0]    # FIXME: sort by ...
        metadata = {
            "added": added[app.appid],
            "categories": app.categories,
            "changelog": app.changelog_url,
            "issueTracker": app.issue_tracker_url,
            "lastUpdated": updated[app.appid],
            "license": app.license,
            "sourceCode": app.source_code_url,
            "translation": app.translation_url,
            "webSite": app.website_url,
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
            "authorEmail": app.author_email,
            "authorName": app.author_name,
            "authorWebSite": app.author_website_url,
            "name": {
                DEFAULT_LOCALE: app.name,                               # FIXME
            },
            "summary": {
                locale: m.short_description
                for locale, m in loc.items() if m.short_description
            },
            "description": {
                locale: m.full_description
                for locale, m in loc.items() if m.full_description
            },
            "donate": [app.donate_url] if app.donate_url else None,     # FIXME
            "icon": {
                locale: {
                    "name": f"/{app.appid}/{locale}/{m.icon_file.path.name}",
                    "sha256": m.icon_file.sha256,
                    "size": m.icon_file.size,
                } for locale, m in loc.items() if m.icon_file
            },
            "preferredSigner": signer,
        }
        data[app.appid] = {
            "metadata": {k: v for k, v in metadata.items() if v},
            "versions": v2_versions(app, apks[app.appid], loc),
        }
    return data


# FIXME
# FIXME: sort by group, signer, version_code
def v2_versions(app: App, apks: Dict[int, Apk], loc: Dict[str, Metadata]) -> Dict[str, Any]:
    """Create v2 index app versions data."""
    data = {}
    for apk in sorted(apks.values(), key=lambda apk: apk.manifest.version_code, reverse=True):
        man = apk.manifest
        features = [{"name": f.name} for f in man.features]
        permissions = [
            {"name": p.name, "maxSdkVersion": p.max_sdk_version}
            if p.max_sdk_version is not None else {"name": p.name}
            for p in man.permissions if not p.min_sdk_version
        ]
        permissions_sdk23 = [
            {"name": p.name, "maxSdkVersion": p.max_sdk_version}
            if p.max_sdk_version is not None else {"name": p.name}
            for p in man.permissions if p.min_sdk_version
        ]
        manifest = {
            "nativecode": man.abis,
            "versionName": man.version_name,
            "versionCode": man.version_code,
            "features": features,
            "usesSdk": {
                "minSdkVersion": man.min_sdk,
                "targetSdkVersion": man.target_sdk,
            },
            "signer": {"sha256": apk.signing_keys},
            "usesPermission": permissions,
            "usesPermissionSdk23": permissions_sdk23,
        }
        entry = {
            "added": apk.added,
            "file": {
                "name": f"/{PurePath(apk.filename).name}",
                "sha256": apk.sha256,
                "size": apk.size,
            },
            "manifest": {k: v for k, v in manifest.items() if v},
            "antiFeatures": app.anti_features,
            "whatsNew": {
                locale: m.changelogs[man.version_code]
                for locale, m in loc.items() if man.version_code in m.changelogs
            },
        }
        for k in ("antiFeatures", "whatsNew"):
            if not entry[k]:
                del entry[k]
        data[apk.sha256] = entry
    return data


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
        return load_json(parent_dir / "timestamps.json")
    except FileNotFoundError:
        return {}


def save_timestamps(parent_dir: Path, timestamps: Dict[str, int]) -> None:
    """Save timestamps.json."""
    save_json(parent_dir / "timestamps.json", timestamps, pretty=True)


def load_json(path: Path) -> Dict[str, Any]:
    """Load JSON data."""
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)            # type: ignore[no-any-return]


def save_json(path: Path, data: Dict[str, Any], *, ensure_ascii: bool = False,
              name: Optional[str] = None, pretty: bool = False, verbose: int = 0) -> None:
    """Save JSON data."""
    if verbose:
        print(f"Writing {name or path.name}...")
    with path.open("w", encoding="utf-8") as fh:
        if pretty:
            json.dump(data, fh, ensure_ascii=ensure_ascii, indent=2)
            fh.write("\n")
        else:
            json.dump(data, fh, ensure_ascii=ensure_ascii)


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
    assert key_pass is not None
    env = dict(APKREPOTOOL_KS_PASS=ks_pass, APKREPOTOOL_KEY_PASS=key_pass)
    try:
        run_command(*args, env=env)
    except subprocess.CalledProcessError as e:
        raise Error(f"Signing with apksigner failed: {e}") from e
    except FileNotFoundError as e:
        raise Error(f"Could not run apksigner: {e}") from e


def get_keystore_cert_fingerprint(cfg: Config, java_stuff: JavaStuff) -> str:
    """Get keystore certificate fingerprint."""
    args = [java_stuff.keytool, "-exportcert", "-keystore", cfg.keystore,
            "-alias", cfg.repo_keyalias, "-storepass:env", "APKREPOTOOL_KS_PASS"]
    ks_pass, _ = get_passwords(cfg.keystorepass_cmd, None)
    env = {**os.environ, **dict(APKREPOTOOL_KS_PASS=ks_pass)}
    try:
        out = subprocess.run(args, check=True, env=env, stdout=subprocess.PIPE).stdout
        return hashlib.sha256(out).hexdigest()
    except subprocess.CalledProcessError as e:
        raise Error(f"Exporting certificate with keytool failed: {e}") from e
    except FileNotFoundError as e:
        raise Error(f"Could not run keytool: {e}") from e


def get_passwords(keystorepass_cmd: str, keypass_cmd: Optional[str]) -> Tuple[str, Optional[str]]:
    r"""
    Get passwords by running keystorepass_cmd & keypass_cmd.

    >>> get_passwords("echo foo", "echo bar")
    ('foo', 'bar')
    >>> get_passwords("echo foo", None)
    ('foo', None)

    """
    try:
        keystorepass_out = subprocess.run(keystorepass_cmd, check=True, shell=True,
                                          stdout=subprocess.PIPE).stdout
        keystorepass = keystorepass_out.decode().strip("\r\n")
        if keypass_cmd is not None:
            keypass_out = subprocess.run(keypass_cmd, check=True, shell=True,
                                         stdout=subprocess.PIPE).stdout
            keypass = keypass_out.decode().strip("\r\n")
            return keystorepass, keypass
        return keystorepass, None
    except subprocess.CalledProcessError as e:
        raise Error(f"Password command failed: {e}") from e
    except FileNotFoundError as e:
        raise Error(f"Could not run password command: {e}") from e


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


def hashed_image(path: Path) -> FileInfo:
    """
    Copy to path with base64-encoded SHA-256 hash; e.g. icon.png to
    icon_47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=.png.
    """
    info = FileInfo.from_path(path)
    b64hash = base64.b64encode(binascii.unhexlify(info.sha256), b"-_").decode()
    hashed_path = path.with_name(f"{path.stem}_{b64hash}{path.suffix}")
    if not hashed_path.exists():
        shutil.copy2(path, hashed_path)
    return FileInfo(hashed_path, info.size, info.sha256)


def run_command(*args: str, env: Optional[Dict[str, str]] = None, keepenv: bool = True,
                merged: bool = False, verbose: bool = False) -> Tuple[str, Optional[str]]:
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


def do_link() -> None:
    """Print repo link."""
    cfg = parse_config_yaml(Path("config.yml"))
    java_stuff = JavaStuff.load(cfg=cfg)
    fpr = get_keystore_cert_fingerprint(cfg, java_stuff).upper()
    url = urlparse(cfg.repo_url)
    if not url.path.endswith("/"):
        url = url._replace(path=f"{url.path}/")
    url = url._replace(query=f"fingerprint={fpr}")
    print(url.geturl())


# FIXME
# FIXME: --pretty, --no-sign
def do_update(verbose: int = 0) -> None:
    """Update index."""
    paths = (".", "metadata", "repo", "cache", "config.yml", "config")
    cur_dir, meta_dir, repo_dir, cache_dir, config_file, config_dir = [Path(p) for p in paths]
    timestamp = int(time.time()) * 1000
    cfg = parse_config_yaml(config_file)
    localised_cfgs = parse_localised_config_yaml(config_dir) if config_dir.exists() else {}
    java_stuff = JavaStuff.load(cfg=cfg, verbose=verbose)
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
            raise Error(f"No allowed signing keys specified for {appid!r} "
                        "(use 'any' to allow any signing key)")
        if app.allowed_apk_signing_keys == ["any"]:
            print(f"Warning: any signing key allowed for {appid!r}.", file=sys.stderr)
        aask[appid] = app.allowed_apk_signing_keys
        one_signer_only[appid] = app.one_signer_only
        apps.append(app)
    for appid, versions in apks.items():
        for apk in versions.values():
            filename, signers = apk.filename, aask[appid]
            if len(apk.signing_keys) > 1:
                if one_signer_only[appid]:
                    raise Error(f"Multiple signers for {filename!r}: {apk.signing_keys}")
                print(f"Warning: multiple signers for {filename!r}: {apk.signing_keys}.", file=sys.stderr)
            missing = [k for k in apk.signing_keys if k not in signers]
            if missing and signers != ["any"]:
                raise Error(f"Unallowed signer(s) for {filename!r}: {missing}")
    added = {k: min(v) for k, v in times.items()}
    updated = {k: max(v) for k, v in times.items()}
    make_index(repo_dir=repo_dir, cache_dir=cache_dir, apps=apps, apks=apks, meta=meta,
               cfg=cfg, localised_cfgs=localised_cfgs, added=added, updated=updated,
               ts=timestamp, verbose=verbose)
    sign_index(repo_dir, cfg, verbose=verbose, java_stuff=java_stuff)
    save_timestamps(cur_dir, timestamps)


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
        print repo link
    """)
    def link(*args: Any, **kwargs: Any) -> None:
        do_link(*args, **kwargs)

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
