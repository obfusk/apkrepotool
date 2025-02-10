#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2025 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import argparse
import sys
import zipfile

from pathlib import Path
from typing import Dict, Tuple

import apkrepotool


def process_apks(tc: apkrepotool.ToolConfig, *,
                 apks: Dict[str, Dict[int, Tuple[Path, apkrepotool.Manifest]]]) -> None:
    """Process APKs."""
    for apkfile in tc.apk_paths():
        man = apkrepotool.get_manifest(apkfile)
        apks.setdefault(man.appid, {})
        if man.version_code in apks[man.appid]:
            raise apkrepotool.Error(f"Duplicate version code: {man.appid!r}:{man.version_code}")
        apks[man.appid][man.version_code] = (apkfile, man)


def process_recipes(tc: apkrepotool.ToolConfig, *, verbose: bool,
                    apks: Dict[str, Dict[int, Tuple[Path, apkrepotool.Manifest]]]) -> None:
    """Process recipes."""
    for recipe in tc.recipe_paths:
        if verbose:
            print(f"Processing {str(recipe)!r}...")
        appid, done = recipe.stem, False
        icon_path = tc.repo_dir / appid / apkrepotool.DEFAULT_LOCALE / "icon.png"
        if icon_path.exists():
            continue
        for _, (apkfile, man) in sorted(apks.get(appid, {}).items(), reverse=True):
            if not man.png_icons:
                continue
            with zipfile.ZipFile(apkfile) as zf:
                infos = {i.orig_filename: i for i in zf.infolist()}
                for png_icon in man.png_icons:
                    if png_icon not in infos:
                        print(f"Warning: Missing {png_icon!r} from {str(apkfile)!r}.", file=sys.stderr)
                        continue
                    data = zf.read(infos[png_icon])
                    if data[:8] != b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a":
                        print(f"Warning: PNG header missing for {png_icon!r} from {str(apkfile)!r}.", file=sys.stderr)
                        continue
                    if verbose:
                        print(f"Copying {png_icon!r} from {str(apkfile)!r} to {str(icon_path)!r}.")
                    with icon_path.open("wb") as fh:
                        fh.write(data)
                    done = True
                    break
            if done:
                break
        if not done:
            print(f"Warning: Unable to extract icon for {appid!r}.", file=sys.stderr)


# FIXME: how to properly handle errors?
# FIXME: what if older APK has better quality icon?
def run(tc: apkrepotool.ToolConfig, *args: str) -> None:
    """Extract PNG icons from APKs with missing icons."""
    parser = argparse.ArgumentParser(prog="apkrepotool extract-icons")
    parser.add_argument("-v", "--verbose", action="store_true")
    opts = parser.parse_args(args)
    apks: Dict[str, Dict[int, Tuple[Path, apkrepotool.Manifest]]] = {}
    process_apks(tc, apks=apks)
    process_recipes(tc, apks=apks, verbose=opts.verbose)


# vim: set tw=80 sw=4 sts=4 et fdm=marker :
