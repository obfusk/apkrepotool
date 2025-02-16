#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2025 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import argparse
import functools
import logging
import zipfile

from pathlib import Path
from typing import Dict, Optional, Tuple

import apkrepotool


@functools.lru_cache(maxsize=None)
def have_webp_support() -> bool:
    r"""
    Memoised check for WebP dependencies (Pillow with WebP support).

    >>> import sys
    >>> "__pypy__" in sys.builtin_module_names or have_webp_support()
    True

    """
    log = logging.getLogger(__name__)
    try:
        import PIL.Image
        import PIL.features
        PIL.Image.Image
    except (ImportError, AttributeError):
        log.warning("Unable to import Pillow.")
        return False
    try:
        if PIL.features.check_module("webp"):
            return True
    except ValueError:
        pass
    log.warning("Pillow does not support WebP.")
    return False


@functools.lru_cache(maxsize=None)
def have_xml_support() -> bool:
    r"""
    Memoised check for XML icon dependencies (Pillow and CairoSVG).

    >>> have_xml_support()
    True

    """
    log = logging.getLogger(__name__)
    try:
        import cairosvg         # type: ignore[import-untyped]
        cairosvg.svg2png
    except (ImportError, AttributeError):
        log.warning("Unable to import CairoSVG.")
        return False
    try:
        import PIL.Image
        PIL.Image.Image
    except (ImportError, AttributeError):
        log.warning("Unable to import Pillow.")
        return False
    return True


def process_apks(tc: apkrepotool.ToolConfig, *,
                 apks: Dict[str, Dict[int, Tuple[Path, apkrepotool.Manifest]]]) -> None:
    """Process APKs."""
    for apkfile in tc.apk_paths():
        man = apkrepotool.get_manifest(apkfile)
        apks.setdefault(man.appid, {})
        if man.version_code in apks[man.appid]:
            raise apkrepotool.Error(f"Duplicate version code: {man.appid!r}:{man.version_code}")
        apks[man.appid][man.version_code] = (apkfile, man)


def process_recipes(tc: apkrepotool.ToolConfig, *, skip_png: bool, try_webp: bool, try_xml: bool,
                    verbose: bool, apks: Dict[str, Dict[int, Tuple[Path, apkrepotool.Manifest]]]) -> None:
    """Process recipes."""
    for recipe in tc.recipe_paths:
        if verbose:
            print(f"Processing {str(recipe)!r}...")
        appid = recipe.stem
        icon_path = tc.repo_dir / appid / apkrepotool.DEFAULT_LOCALE / "icon.png"
        if icon_path.exists():
            continue
        for _, (apkfile, manifest) in sorted(apks.get(appid, {}).items(), reverse=True):
            if icon_file := extract_icon(apkfile, manifest, icon_path, skip_png=skip_png,
                                         try_webp=try_webp, try_xml=try_xml):
                if verbose:
                    print(f"Saved {str(icon_path)!r} using {icon_file!r} from {str(apkfile)!r}.")
                break
        else:
            log = logging.getLogger(__name__)
            log.warning(f"Unable to extract icon for {appid!r}.")


def extract_icon(apkfile: Path, manifest: apkrepotool.Manifest, icon_path: Path, *,
                 skip_png: bool = False, try_webp: bool = False, try_xml: bool = False) -> Optional[str]:
    """Extract best .png (or converted .webp or .xml) icon from APK."""
    log = logging.getLogger(__name__)
    with zipfile.ZipFile(apkfile) as zf:
        infos = {i.orig_filename: i for i in zf.infolist()}
        if not skip_png:
            for png_icon in (manifest.png_icons or []):
                if png_icon not in infos:
                    log.warning(f"Missing {png_icon!r} from {str(apkfile)!r}.")
                    continue
                if extract_png_from_apk(apkfile, zf, infos[png_icon], icon_path):
                    return png_icon
        if try_webp and have_webp_support():
            for webp_icon in (manifest.webp_icons or []):
                if webp_icon not in infos:
                    log.warning(f"Missing {webp_icon!r} from {str(apkfile)!r}.")
                    continue
                if convert_webp_from_apk(apkfile, zf, infos[webp_icon], icon_path):
                    return webp_icon
        if try_xml and have_xml_support():
            for xml_icon in (manifest.xml_icons or []):
                if xml_icon not in infos:
                    log.warning(f"Missing {xml_icon!r} from {str(apkfile)!r}.")
                    continue
                if convert_xml_from_apk(apkfile, zf, infos[xml_icon], icon_path):
                    return xml_icon
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


# FIXME: delete on error?
def convert_webp_from_apk(apkfile: Path, zf: zipfile.ZipFile, info: zipfile.ZipInfo,
                          icon_path: Path) -> bool:
    """
    Convert .webp from APK.

    Requires Pillow with WebP support.
    """
    import PIL
    import PIL.Image
    try:
        with zf.open(info) as fh, PIL.Image.open(fh, formats=["WEBP"]) as im:
            icon_path.parent.mkdir(parents=True, exist_ok=True)
            im.save(icon_path, "PNG")
    except PIL.UnidentifiedImageError as e:
        log = logging.getLogger(__name__)
        log.warning(f"Unable to open {info.orig_filename!r} from {str(apkfile)!r}: {e}.")
        return False
    return True


def convert_xml_from_apk(apkfile: Path, zf: zipfile.ZipFile, info: zipfile.ZipInfo,
                         icon_path: Path) -> Optional[bool]:
    """
    Convert .xml from APK.

    Requires Pillow and CairoSVG.
    """
    import apkrepotool.xml_icons as xml_icons
    import repro_apk.binres as binres
    try:
        data = xml_icons.extract_icon(zf, info.orig_filename)
    except (xml_icons.Error, binres.Error) as e:
        log = logging.getLogger(__name__)
        log.warning(f"Unable to convert {info.orig_filename!r} from {str(apkfile)!r}: {e}.")
        return False
    icon_path.parent.mkdir(parents=True, exist_ok=True)
    with icon_path.open("wb") as fh:
        fh.write(data)
    return True


# FIXME: how to properly handle errors?
# FIXME: what if older APK has better quality icon?
def run(tc: apkrepotool.ToolConfig, *args: str) -> None:
    """Extract PNG (or convert WebP or XML) icons from APKs with missing icons."""
    parser = argparse.ArgumentParser(prog="apkrepotool extract-icons")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--skip-png", action="store_true")
    parser.add_argument("--try-webp", action="store_true")
    parser.add_argument("--try-xml", action="store_true")
    opts = parser.parse_args(args)
    apks: Dict[str, Dict[int, Tuple[Path, apkrepotool.Manifest]]] = {}
    process_apks(tc, apks=apks)
    process_recipes(tc, apks=apks, skip_png=opts.skip_png, try_webp=opts.try_webp,
                    try_xml=opts.try_xml, verbose=opts.verbose)


# vim: set tw=80 sw=4 sts=4 et fdm=marker :
