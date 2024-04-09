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
import struct
import subprocess
import sys
import time

from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any, Dict, Iterator, List, Optional, Tuple

import apksigcopier
import repro_apk.binres as binres       # FIXME: needs proper release & dependency

from ruamel.yaml import YAML

__version__ = "0.0.0"
NAME = "apkrepotool"

CLEAN_LANG_ENV = dict(LC_ALL="C.UTF-8", LANG="", LANGUAGE="")

APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a
APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0
APK_SIGNATURE_SCHEME_V31_BLOCK_ID = 0x1b93ad61
VERITY_PADDING_BLOCK_ID = 0x42726577


class Error(Exception):
    """Base class for errors."""


class SigError(Error):
    """Signature (verification) error."""


@dataclass(frozen=True)
class Block:
    """Block from APK Signing Block."""
    data: bytes


@dataclass(frozen=True)
class APKSignatureSchemeBlock(Block):
    """APK Signature Scheme v2/v3 Block."""
    version: int
    certificates: List[bytes]


@dataclass(frozen=True)
class Pair:
    """Pair from APK Signing Block."""
    id: int
    value: Block


# FIXME
@dataclass(frozen=True)
class App:
    """App."""
    name: str
    appid: str
    allowed_apk_signing_keys: List[str]
    current_version: Optional[int]


# FIXME
@dataclass(frozen=True)
class Apk:
    """APK."""
    filename: str
    size: int
    sha256: str
    appid: str
    version_code: int
    version_name: str
    signing_key: str
    fdroid_sig: str


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
def parse_recipe_yaml(recipe_file: str) -> App:
    r"""
    Parse recipe YAML.

    >>> parse_recipe_yaml("test/metadata/android.appsecurity.cts.tinyapp.yml")
    App(name='TestApp', appid='android.appsecurity.cts.tinyapp', allowed_apk_signing_keys=['fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8'], current_version=None)

    """
    appid = PurePath(recipe_file).stem
    with open(recipe_file, encoding="utf-8") as fh:
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
        return App(name=name, appid=appid, allowed_apk_signing_keys=allowed_apk_signing_keys,
                   current_version=None)


# FIXME
def parse_config_yaml(config_file: str) -> Config:
    r"""
    Parse config YAML.

    >>> parse_config_yaml("test/config.yml")
    Config(repo_url='https://example.com/fdroid/repo', repo_name='My Repo', repo_description='This is a repository of apps to be used with an F-Droid-compatible client. Applications in this repository are official binaries built by the original application developers.')

    """
    with open(config_file, encoding="utf-8") as fh:
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
def get_apk_info(apkfile: str) -> Apk:
    r"""
    Get APK info.

    >>> get_apk_info("test/repo/golden-aligned-v1v2v3-out.apk")
    Apk(filename='test/repo/golden-aligned-v1v2v3-out.apk', size=12865, sha256='ba7828ba42a3b68bd3acff78773e41d6a62aabe6317538671441c568748d9cd7', appid='android.appsecurity.cts.tinyapp', version_code=10, version_name='1.0', signing_key='fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8', fdroid_sig='506ceb2a3116981827a3990f3446d3af')

    """
    size = Path(apkfile).stat().st_size
    sha256 = get_sha256(apkfile)
    appid, vercode, vername = binres.quick_get_idver(apkfile)
    fingerprint = get_signing_cert_fingerprint(apkfile)     # verify w/ apksigner first!
    extracted_v2_sig = apksigcopier.extract_v2_sig(apkfile)
    assert extracted_v2_sig is not None
    _, sig_block = extracted_v2_sig
    certs = get_signing_certs(sig_block)
    if fingerprint not in certs:
        raise SigError("SHA-256 fingerprint mismatch")
    sig = get_fdroid_sig(certs[fingerprint])
    return Apk(filename=apkfile, size=size, sha256=sha256, appid=appid, version_code=vercode,
               version_name=vername, signing_key=fingerprint, fdroid_sig=sig)


def get_sha256(file: str) -> str:
    r"""
    Get SHA-256 digest of file.

    >>> get_sha256("LICENSE.AGPLv3")
    '8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef'

    """
    sha = hashlib.sha256()
    with open(file, "rb") as fh:
        while data := fh.read(4096):
            sha.update(data)
    return sha.hexdigest()


def get_signing_cert_fingerprint(apkfile: str) -> str:
    """
    Get APK signing key certificate SHA-256 fingerprint using apksigner.

    NB: this validates the signature(s)!
    """
    prefix = "Signer #1 certificate SHA-256 digest: "
    hexdigit = "01234567890abcdef"
    try:
        out, err = run_command("apksigner", "verify", "--print-certs", "--",
                               apkfile, env=CLEAN_LANG_ENV)
    except subprocess.CalledProcessError as e:
        raise SigError(f"Verification with apksigner failed: {e}") from e
    except FileNotFoundError as e:
        raise Error(f"Could not run apksigner: {e}") from e
    for line in out.splitlines():
        if line.startswith(prefix):
            fingerprint = line[len(prefix):]
            if len(fingerprint) == 64 and all(c in hexdigit for c in fingerprint):
                return fingerprint
            raise SigError(f"Malformed fingerprint: {fingerprint!r}")
    raise SigError("No signer found")


def get_fdroid_sig(cert: bytes) -> str:
    """
    Get F-Droid APK sig (MD5 of hexdump of certificate).

    NB: this does not validate anything; use after get_signing_cert_fingerprint()!
    """
    return hashlib.md5(binascii.hexlify(cert)).hexdigest()


def get_signing_certs(sig_block: bytes) -> Dict[str, bytes]:
    """
    Get APK signing key certificates by partially parsing the APK Signing Block.

    NB: this does not validate anything; use after get_signing_cert_fingerprint()!
    """
    certs = {}
    for p in parse_apk_signing_block(sig_block):
        if isinstance(p.value, APKSignatureSchemeBlock):
            cert = p.value.certificates[0]
            fingerprint = hashlib.sha256(cert).hexdigest()
            if fingerprint not in certs:
                certs[fingerprint] = cert
    return certs


# FIXME: also use to detect "unwanted" blocks
def parse_apk_signing_block(data: bytes) -> Iterator[Pair]:
    """
    Partially parse APK Signing Block (a sequence of pairs).

    NB: this is not a full parser!  Just enough to get the certificates.
    """
    magic = data[-16:]
    sb_size1 = int.from_bytes(data[:8], "little")
    sb_size2 = int.from_bytes(data[-24:-16], "little")
    if magic != b"APK Sig Block 42":
        raise SigError("APK Sig Block magic mismatch")
    if not (sb_size1 == sb_size2 == len(data) - 8):
        raise SigError("APK Sig Block size mismatch")
    data = data[8:-24]
    while data:
        value: Block
        pair_len, pair_id = struct.unpack("<QL", data[:12])
        pair_val, data = data[12:8 + pair_len], data[8 + pair_len:]
        if pair_id == APK_SIGNATURE_SCHEME_V2_BLOCK_ID:
            value = parse_apk_signature_scheme_block(pair_val, 2)
        elif pair_id == APK_SIGNATURE_SCHEME_V3_BLOCK_ID:
            value = parse_apk_signature_scheme_block(pair_val, 3)
        elif pair_id == APK_SIGNATURE_SCHEME_V31_BLOCK_ID:
            value = parse_apk_signature_scheme_block(pair_val, 31)
        elif pair_id == VERITY_PADDING_BLOCK_ID:
            if not all(b == 0 for b in pair_val):
                raise SigError("Verity zero padding mismatch")
            value = Block(pair_val)
        else:
            value = Block(pair_val)
        yield Pair(pair_id, value)


def parse_apk_signature_scheme_block(data: bytes, version: int) -> APKSignatureSchemeBlock:
    """
    Partially parse APK Signature Scheme v2/v3 Block.

    NB: this is not a full parser!  Just enough to get the certificates.
    """
    certificates = []
    seq_len, data = int.from_bytes(data[:4], "little"), data[4:]
    if seq_len != len(data):
        raise SigError("APK Signature Scheme Block size mismatch")
    while data:
        d_signer, data = _split_len_prefixed_field(data)
        signed_data, _ = _split_len_prefixed_field(d_signer)
        d_digests, signed_data = _split_len_prefixed_field(signed_data)
        d_certs, _ = _split_len_prefixed_field(signed_data)
        while d_certs:
            cert, d_certs = _split_len_prefixed_field(d_certs)
            certificates.append(cert)
    return APKSignatureSchemeBlock(data, version, certificates)


def _split_len_prefixed_field(data: bytes) -> Tuple[bytes, bytes]:
    """
    Parse length-prefixed field (length is little-endian, uint32) at beginning
    of data.

    Returns (field data, remaining data).
    """
    if len(data) < 4:
        raise SigError("Prefixed field must be at least 4 bytes")
    field_len = int.from_bytes(data[:4], "little")
    if len(data) < 4 + field_len:
        raise SigError("Prefixed field size mismatch")
    return data[4:4 + field_len], data[4 + field_len:]


# FIXME
def make_index(apps: List[App], apks: Dict[str, Apk], meta: Dict[str, Dict[str, Metadata]],
               repo_dir: Path, cfg: Config, localised_cfgs: Dict[str, LocalisedConfig]) -> None:
    """Create & write v1 & v2 index."""
    ts = int(time.time())
    v1_data = v1_index(apps, apks, meta, ts, cfg)
    v2_data = v2_index(apps, apks, meta, ts, cfg, localised_cfgs)
    with (repo_dir / "index-v1.json").open("w") as fh:
        json.dump(v1_data, fh, indent=2)
        fh.write("\n")
    with (repo_dir / "index-v2.json").open("w") as fh:
        json.dump(v2_data, fh, indent=2)
        fh.write("\n")


# FIXME
def v1_index(apps: List[App], apks: Dict[str, Apk], meta: Dict[str, Dict[str, Metadata]],
             ts: int, cfg: Config) -> Any:
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
def v1_apps(apps: List[App], meta: Dict[str, Dict[str, Metadata]]) -> Any:
    """Create v1 index apps data."""
    data = []
    for app in apps:
        entry = {
            "allowedAPKSigningKeys": app.allowed_apk_signing_keys or None,
            "suggestedVersionName": None,           # FIXME
            "suggestedVersionCode": str(1),         # FIXME
            "license": "Unknown",                   # FIXME
            "name": app.name,
            "added": 0,                             # FIXME
            "packageName": app.appid,
            "lastUpdated": 0,                       # FIXME
            "localized": v1_localised(meta[app.appid], app.current_version),
        }
        data.append({k: v for k, v in entry.items() if v is not None})
    return data


# FIXME
def v1_localised(app_meta: Dict[str, Metadata], current_version: Optional[int]) -> Any:
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
            "whatsNew": meta.changelogs.get(current_version) if current_version else None,
        }
        data[locale] = {k: v for k, v in entry.items() if v is not None}
    return data


# FIXME
def v1_packages(apks: Dict[str, Apk]) -> Any:
    """Create v1 index packages data."""
    data: Dict[str, Any] = {}
    for appid, apk in apks.items():
        if appid not in data:
            data[appid] = []
        data[appid].append({
            "added": 0,                             # FIXME
            "apkName": PurePath(apk.filename).name,
            "features": [],                         # FIXME
            "hash": apk.sha256,
            "hashType": "sha256",
            "minSdkVersion": 1,                     # FIXME
            "packageName": apk.appid,
            "sig": apk.fdroid_sig,
            "signer": apk.signing_key,
            "size": apk.size,
            "targetSdkVersion": 1,                  # FIXME
            "uses-permission": [],                  # FIXME
            "versionCode": apk.version_code,
            "versionName": apk.version_name,
        })
    return data


# FIXME
def v2_index(apps: List[App], apks: Dict[str, Apk], meta: Dict[str, Dict[str, Metadata]],
             ts: int, cfg: Config, localised_cfgs: Dict[str, LocalisedConfig]) -> Any:
    """Create v2 index data."""
    apps, apks, meta, ts, cfg, localised_cfgs
    return {}


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


# FIXME
def do_update() -> None:
    """Update index."""


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
