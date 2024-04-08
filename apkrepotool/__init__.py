#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
apkrepotool - manage APK repos

FIXME
"""

import subprocess
import sys

from dataclasses import dataclass
from typing import Any, List

# FIXME: needs proper release & dependency
import repro_apk.binres as binres

from ruamel.yaml import YAML

__version__ = "0.0.0"
NAME = "apkrepotool"


class Error(Exception):
    """Base class for errors."""


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
def get_apk_info(apkfile: str) -> Apk:
    r"""
    Get APK info.

    >>> apk = get_apk_info("test/repo/golden-aligned-v1v2v3-out.apk")
    >>> apk
    Apk(filename='test/repo/golden-aligned-v1v2v3-out.apk', appid='android.appsecurity.cts.tinyapp', version_code=10, version_name='1.0', signing_key='fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8')

    """
    appid, vercode, vername = binres.quick_get_idver(apkfile)
    return Apk(filename=apkfile, appid=appid, version_code=vercode,
               version_name=vername, signing_key=get_signing_key(apkfile))


def get_signing_key(apkfile: str) -> str:
    """Get APK signing key SHA-256 fingerprint using apksigner."""
    prefix = "Signer #1 certificate SHA-256 digest: "
    hexdigit = "01234567890abcdef"
    args = ("apksigner", "verify", "--print-certs", "--", apkfile)
    for line in run_command(*args).splitlines():
        if line.startswith(prefix):
            fingerprint = line[len(prefix):]
            if len(fingerprint) == 64 and all(c in hexdigit for c in fingerprint):
                return fingerprint
            raise Error(f"Malformed fingerprint: {fingerprint!r}")
    raise Error("No signer found")


# FIXME
def make_index_v1(repo_dir: str, apps: List[App], apks: List[Apk]) -> None:
    """Make v1 index."""
    repo_dir, apps, apks


# FIXME
def make_index_v2(repo_dir: str, apps: List[App], apks: List[Apk]) -> None:
    """Make v2 index."""
    repo_dir, apps, apks


def run_command(*args: str, verbose: bool = False) -> str:
    r"""
    Run command and capture stdout + stderr.

    >>> run_command("echo", "OK")
    'OK\n'
    >>> run_command("bash", "-c", "echo OK >&2")
    'OK\n'
    >>> try:
    ...     run_command("false")
    ... except subprocess.CalledProcessError as e:
    ...     print(e)
    Command '('false',)' returned non-zero exit status 1.

    """
    if verbose:
        print(f"Running {' '.join(args)!r}...", file=sys.stderr)
    return subprocess.run(args, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT).stdout.decode()


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
    except (Error, subprocess.CalledProcessError, binres.Error) as e:
        print(f"Error: {e}.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
