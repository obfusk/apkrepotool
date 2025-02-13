#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2025 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import argparse
import logging
import zipfile

from pathlib import Path
from typing import Dict, Optional, Tuple

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


def process_recipes(tc: apkrepotool.ToolConfig, *, no_webp: bool, verbose: bool,
                    apks: Dict[str, Dict[int, Tuple[Path, apkrepotool.Manifest]]]) -> None:
    """Process recipes."""
    for recipe in tc.recipe_paths:
        if verbose:
            print(f"Processing {str(recipe)!r}...")
        appid = recipe.stem
        icon_path = tc.repo_dir / appid / apkrepotool.DEFAULT_LOCALE / "icon.png"
        if icon_path.exists():
            continue
        for _, (apkfile, manifest) in sorted(apks.get(appid, {}).items(), reverse=True):
            if icon_file := extract_icon(apkfile, manifest, icon_path, no_webp=no_webp):
                if verbose:
                    print(f"Saved {str(icon_path)!r} using {icon_file!r} from {str(apkfile)!r}.")
                break
        else:
            log = logging.getLogger(__name__)
            log.warning(f"Unable to extract icon for {appid!r}.")


def extract_icon(apkfile: Path, manifest: apkrepotool.Manifest, icon_path: Path, *,
                 no_webp: bool = False) -> Optional[str]:
    """Extract best .png (or .webp) icon from APK."""
    log = logging.getLogger(__name__)
    with zipfile.ZipFile(apkfile) as zf:
        infos = {i.orig_filename: i for i in zf.infolist()}
        for png_icon in (manifest.png_icons or []):
            if png_icon not in infos:
                log.warning(f"Missing {png_icon!r} from {str(apkfile)!r}.")
                continue
            if extract_png_from_apk(apkfile, zf, infos[png_icon], icon_path):
                return png_icon
        if no_webp:
            return None
        for webp_icon in (manifest.webp_icons or []):
            if webp_icon not in infos:
                log.warning(f"Missing {webp_icon!r} from {str(apkfile)!r}.")
                continue
            if result := convert_webp_from_apk(apkfile, zf, infos[webp_icon], icon_path):
                return webp_icon
            if result is None:  # webp support unavailable
                break
    return None


def extract_png_from_apk(apkfile: Path, zf: zipfile.ZipFile, info: zipfile.ZipInfo,
                         icon_path: Path) -> bool:
    """
    Extract .png from APK.

    NB: only checks for a PNG header.
    """
    data = zf.read(info)
    if data[:8] != b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a":
        log = logging.getLogger(__name__)
        log.warning(f"PNG header missing for {info.orig_filename!r} from {str(apkfile)!r}.")
        return False
    icon_path.parent.mkdir(parents=True, exist_ok=True)
    with icon_path.open("wb") as fh:
        fh.write(data)
    return True


def convert_webp_from_apk(apkfile: Path, zf: zipfile.ZipFile, info: zipfile.ZipInfo,
                          icon_path: Path) -> Optional[bool]:
    """
    Convert .webp from APK.

    Requires Pillow with WebP support.
    """
    log = logging.getLogger(__name__)
    try:
        import PIL
        import PIL.features
        from PIL import Image
    except ImportError:
        log.warning("Unable to import Pillow.")
        return None
    if not PIL.features.check_module("webp"):
        log.warning("Pillow does not support WebP.")
        return None
    try:
        with zf.open(info) as fh, Image.open(fh, formats=["WEBP"]) as im:
            icon_path.parent.mkdir(parents=True, exist_ok=True)
            im.save(icon_path, "PNG")
    except PIL.UnidentifiedImageError as e:
        log.warning(f"Unable to open {info.orig_filename!r} from {str(apkfile)!r}: {e}.")
        return False
    return True


# FIXME: how to properly handle errors?
# FIXME: what if older APK has better quality icon?
# FIXME: XML icons?!
def run(tc: apkrepotool.ToolConfig, *args: str) -> None:
    """Extract PNG (or convert WebP) icons from APKs with missing icons."""
    parser = argparse.ArgumentParser(prog="apkrepotool extract-icons")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-webp", action="store_true")
    opts = parser.parse_args(args)
    apks: Dict[str, Dict[int, Tuple[Path, apkrepotool.Manifest]]] = {}
    process_apks(tc, apks=apks)
    process_recipes(tc, apks=apks, no_webp=opts.no_webp, verbose=opts.verbose)


# vim: set tw=80 sw=4 sts=4 et fdm=marker :
