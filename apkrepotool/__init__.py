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
import os
import struct
import subprocess
import sys

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import apksigcopier
import repro_apk.binres as binres       # FIXME: needs proper release & dependency

from ruamel.yaml import YAML

__version__ = "0.0.0"
NAME = "apkrepotool"

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
    allowed_apk_signing_keys: List[str]


# FIXME
@dataclass(frozen=True)
class Apk:
    """APK."""
    filename: str
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

    >>> app = parse_recipe_yaml("test/metadata/android.appsecurity.cts.tinyapp.yml")
    >>> app
    App(name='TestApp', allowed_apk_signing_keys=['fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8'])

    """
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
        return App(name=name, allowed_apk_signing_keys=allowed_apk_signing_keys)


# FIXME
def parse_config_yaml(config_file: str) -> Config:
    r"""
    Parse config YAML.

    >>> cfg = parse_config_yaml("test/config.yml")
    >>> cfg
    Config(repo_url='https://example.com/fdroid/repo', repo_name='My Repo', repo_description='This is a repository of apps to be used with an F-Droid-compatible client. Applications in this repository are official binaries built by the original application developers.')

    """
    with open(config_file, encoding="utf-8") as fh:
        yaml = YAML(typ="safe")
        data = yaml.load(fh)
        return Config(repo_url=data["repo_url"], repo_name=data["repo_name"],
                      repo_description=data["repo_description"])


# FIXME
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

    >>> apk = get_apk_info("test/repo/golden-aligned-v1v2v3-out.apk")
    >>> apk
    Apk(filename='test/repo/golden-aligned-v1v2v3-out.apk', appid='android.appsecurity.cts.tinyapp', version_code=10, version_name='1.0', signing_key='fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8', fdroid_sig='506ceb2a3116981827a3990f3446d3af')

    """
    appid, vercode, vername = binres.quick_get_idver(apkfile)
    fingerprint = get_signing_cert_fingerprint(apkfile)     # verify w/ apksigner first!
    extracted_v2_sig = apksigcopier.extract_v2_sig(apkfile)
    assert extracted_v2_sig is not None
    _, sig_block = extracted_v2_sig
    certs = get_signing_certs(sig_block)
    if fingerprint not in certs:
        raise SigError("SHA-256 fingerprint mismatch")
    sig = get_fdroid_sig(certs[fingerprint])
    return Apk(filename=apkfile, appid=appid, version_code=vercode, version_name=vername,
               signing_key=fingerprint, fdroid_sig=sig)


def get_signing_cert_fingerprint(apkfile: str) -> str:
    """
    Get APK signing key certificate SHA-256 fingerprint using apksigner.

    NB: this validates the signature(s)!
    """
    prefix = "Signer #1 certificate SHA-256 digest: "
    hexdigit = "01234567890abcdef"
    try:
        out, err = run_command("apksigner", "verify", "--print-certs", "--", apkfile)
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
def make_index_v1(apps: List[App], apks: List[Apk]) -> None:
    """Make v1 index."""
    apps, apks


# FIXME
def make_index_v2(apps: List[App], apks: List[Apk]) -> None:
    """Make v2 index."""
    apps, apks


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
