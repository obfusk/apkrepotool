#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2025 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import argparse
import io
import logging
import re
import xml.etree.ElementTree as ET
import zipfile

from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import apkrepotool
import repro_apk.binres as binres


def process_apks(tc: apkrepotool.ToolConfig, *,
                 apks: Dict[str, Dict[int, Tuple[Path, apkrepotool.Manifest]]]) -> None:
    """Process APKs."""
    for apkfile in tc.apk_paths():
        man = apkrepotool.get_manifest(apkfile)
        apks.setdefault(man.appid, {})
        if man.version_code in apks[man.appid]:
            raise apkrepotool.Error(f"Duplicate version code: {man.appid!r}:{man.version_code}")
        apks[man.appid][man.version_code] = (apkfile, man)


def process_recipes(tc: apkrepotool.ToolConfig, *, try_webp: bool, try_xml: bool, verbose: bool,
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
            if icon_file := extract_icon(apkfile, manifest, icon_path, try_webp=try_webp, try_xml=try_xml):
                if verbose:
                    print(f"Saved {str(icon_path)!r} using {icon_file!r} from {str(apkfile)!r}.")
                break
        else:
            log = logging.getLogger(__name__)
            log.warning(f"Unable to extract icon for {appid!r}.")


def extract_icon(apkfile: Path, manifest: apkrepotool.Manifest, icon_path: Path, *,
                 try_webp: bool = False, try_xml: bool = False) -> Optional[str]:
    """Extract best .png (or .webp) icon from APK."""
    log = logging.getLogger(__name__)
    with zipfile.ZipFile(apkfile) as zf:
        infos = {i.orig_filename: i for i in zf.infolist()}
        # for png_icon in (manifest.png_icons or []):
        #     if png_icon not in infos:
        #         log.warning(f"Missing {png_icon!r} from {str(apkfile)!r}.")
        #         continue
        #     if extract_png_from_apk(apkfile, zf, infos[png_icon], icon_path):
        #         return png_icon
        if try_webp:
            for webp_icon in (manifest.webp_icons or []):
                if webp_icon not in infos:
                    log.warning(f"Missing {webp_icon!r} from {str(apkfile)!r}.")
                    continue
                if result := convert_webp_from_apk(apkfile, zf, infos[webp_icon], icon_path):
                    return webp_icon
                if result is None:  # webp support unavailable
                    break
        if try_xml:
            for xml_icon in (manifest.xml_icons or []):
                if xml_icon not in infos:
                    log.warning(f"Missing {xml_icon!r} from {str(apkfile)!r}.")
                    continue
                if result := convert_xml_from_apk(apkfile, zf, infos[xml_icon], icon_path):
                    return xml_icon
                if result is None:  # dependencies unavailable
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
        import PIL.Image
    except ImportError:
        log.warning("Unable to import Pillow.")
        return None
    if not PIL.features.check_module("webp"):
        log.warning("Pillow does not support WebP.")
        return None
    try:
        with zf.open(info) as fh, PIL.Image.open(fh, formats=["WEBP"]) as im:
            icon_path.parent.mkdir(parents=True, exist_ok=True)
            im.save(icon_path, "PNG")
    except PIL.UnidentifiedImageError as e:
        log.warning(f"Unable to open {info.orig_filename!r} from {str(apkfile)!r}: {e}.")
        return False
    return True


def convert_xml_from_apk(apkfile: Path, zf: zipfile.ZipFile, info: zipfile.ZipInfo,
                         icon_path: Path) -> Optional[bool]:
    """
    Convert .xml from APK.

    Requires Pillow and CairoSVG.
    """
    assert apkfile
    if data := parse_xml_icon(zf, info):
        icon_path.parent.mkdir(parents=True, exist_ok=True)
        with icon_path.open("wb") as fh:
            fh.write(data)
        return True
    return None if data is None else False


# FIXME
def parse_xml_icon(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> Optional[bytes]:
    log = logging.getLogger(__name__)
    try:
        import PIL.Image        # noqa: F401
    except ImportError:
        log.warning("Unable to import Pillow.")
        return None
    try:
        import cairosvg         # type: ignore[import-untyped]  # noqa: F401
    except ImportError:
        log.warning("Unable to import CairoSVG.")
        return None
    infos = {i.orig_filename: i for i in zf.infolist()}     # FIXME
    resources = binres.read_chunk(zf.read(infos[binres.ARSC_FILE]))[0] if binres.ARSC_FILE in infos else None
    if resources is not None and not isinstance(resources, binres.ResourceTableChunk):
        log.warning("Unable to parse AXML.")
        return b""
    return _parse_xml_icon(zf, info, resources) or b""


# FIXME
def _parse_xml_icon(zf: zipfile.ZipFile, info: zipfile.ZipInfo,
                    resources: Optional[binres.ResourceTableChunk]) -> Optional[bytes]:
    import cairosvg
    log = logging.getLogger(__name__)
    axml_chunk = binres.read_chunk(zf.read(info))[0]
    if not isinstance(axml_chunk, binres.XMLChunk):
        log.warning("Unable to parse AXML.")
        return None
    xml_root = binres.xmlchunk_to_etree(axml_chunk, resources=resources).getroot()
    if xml_root.tag == "adaptive-icon":
        bg, fg = xml_root.find("background"), xml_root.find("foreground")
        if bg is None or fg is None:
            return None
        bg_d, fg_d = bg.get(_android("drawable")), fg.get(_android("drawable"))
        if bg_d is None or fg_d is None:
            return None
        bg_img = _load_drawable(zf, bg_d, resources)
        fg_img = _load_drawable(zf, fg_d, resources)
        if bg_img is None or fg_img is None:
            return None
        if bg_img.size > fg_img.size:
            bg_img = bg_img.resize(fg_img.size)
        elif fg_img.size > bg_img.size:
            fg_img = fg_img.resize(bg_img.size)
        bg_img.alpha_composite(fg_img)
        bg_img.show()
        return b""
        # bio = io.BytesIO()
        # bg_img.save(bio, "PNG")
        # return bio.getvalue()
    if xml_root.tag == "vector":
        if tree := _vector_to_svg(xml_root):
            bio = io.BytesIO()
            tree.write(bio)
            print(bio.getvalue())
            data = cairosvg.svg2png(bytestring=bio.getvalue(), output_width=512, output_height=512)
            assert isinstance(data, bytes)
            return data
        return b""
    log.warning(f"Unsupported tag: {xml_root.tag!r}.")
    return None


# FIXME
def _load_drawable(zf: zipfile.ZipFile, drawable: str,
                   resources: Optional[binres.ResourceTableChunk]) -> Optional[Any]:
    import PIL.Image
    infos = {i.orig_filename: i for i in zf.infolist()}     # FIXME
    if re.fullmatch("#[0-9a-f]{8}", drawable):
        return PIL.Image.new("RGBA", (512, 512), _rgba(drawable))
    if drawable.endswith(".xml"):
        if data := _parse_xml_icon(zf, infos[drawable], resources):
            bio = io.BytesIO(data)
        else:
            return None
    elif drawable.endswith(".png"):
        bio = io.BytesIO(zf.read(infos[drawable]))
    else:
        return None
    # FIXME: handle errors
    with PIL.Image.open(bio, formats=["PNG"]) as im:
        im.load()
        return im
    return None


# FIXME
def _vector_to_svg(xml_root: ET.Element) -> Optional[ET.ElementTree]:
    attrs = xml_root.attrib.copy()
    _ = attrs.pop(_android("width"), None)      # FIXME
    _ = attrs.pop(_android("height"), None)     # FIXME
    vp_width = attrs.pop(_android("viewportWidth"), None)
    vp_height = attrs.pop(_android("viewportHeight"), None)
    if vp_width is None or vp_height is None or attrs:
        return None
    viewbox = f"0 0 {vp_width} {vp_height}"
    svg = ET.Element("svg", {"xmlns": "http://www.w3.org/2000/svg", "viewBox": viewbox})
    for xml_elem in xml_root:
        if not _process_vector_elem(svg, xml_elem):
            return None
    return ET.ElementTree(svg)


# FIXME
def _process_vector_elem(svg_elem: ET.Element, xml_elem: ET.Element) -> bool:
    attrs = xml_elem.attrib.copy()
    if xml_elem.tag == "group":
        # FIXME: rotate, ...
        scale_x = attrs.pop(_android("scaleX"), "1")
        scale_y = attrs.pop(_android("scaleY"), "1")
        trans_x = attrs.pop(_android("translateX"), "0")
        trans_y = attrs.pop(_android("translateY"), "0")
        # FIXME: why reversed?
        transform = f"translate({trans_x}, {trans_y}) scale({scale_x}, {scale_y})"
        svg_subelem = ET.SubElement(svg_elem, "g", {"transform": transform})
        for xml_subelem in xml_elem:
            if not _process_vector_elem(svg_subelem, xml_subelem):
                return False
    elif xml_elem.tag == "path":
        # FIXME: check colours
        cap = dict(enumerate(("butt", "round", "square")))
        join = dict(enumerate(("miter", "round", "bevel")))
        data = attrs.pop(_android("pathData"), "")
        fill = _rgba(attrs.pop(_android("fillColor"), "none"))
        stroke = _rgba(attrs.pop(_android("strokeColor"), "none"))
        stroke_w = attrs.pop(_android("strokeWidth"), "0")
        stroke_a = attrs.pop(_android("strokeAlpha"), "1")
        fill_a = attrs.pop(_android("fillAlpha"), "1")
        stroke_lc = attrs.pop(_android("strokeLineCap"), "0")
        stroke_lj = attrs.pop(_android("strokeLineJoin"), "0")
        fill_t = attrs.pop(_android("fillType"), "nonZero")
        fill = "none" if fill == "#00000000" else fill
        svg_subelem = ET.SubElement(svg_elem, "path", {
            "d": data, "fill": fill, "stroke": stroke, "stroke-width": stroke_w,
            "stroke-opacity": stroke_a, "fill-opacity": fill_a,
            "stroke-linecap": cap[int(stroke_lc)],
            "stroke-linejoin": join[int(stroke_lj)],
            "fill-rule": fill_t.lower(),
        })
    else:
        return False
    if attrs:
        return False
    return True


# FIXME
def _rgba(colour: str) -> str:
    if re.fullmatch("#[0-9a-f]{8}", colour):
        return f"#{colour[3:]}{colour[1:3]}"
    return colour


def _android(attr: str) -> str:
    return f"{{{binres.SCHEMA_ANDROID}}}{attr}"


# FIXME: how to properly handle errors?
# FIXME: what if older APK has better quality icon?
# FIXME: XML icons?!
def run(tc: apkrepotool.ToolConfig, *args: str) -> None:
    """Extract PNG (or convert WebP) icons from APKs with missing icons."""
    parser = argparse.ArgumentParser(prog="apkrepotool extract-icons")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--try-webp", action="store_true")
    parser.add_argument("--try-xml", action="store_true")
    opts = parser.parse_args(args)
    apks: Dict[str, Dict[int, Tuple[Path, apkrepotool.Manifest]]] = {}
    process_apks(tc, apks=apks)
    process_recipes(tc, apks=apks, try_webp=opts.try_webp, try_xml=opts.try_xml, verbose=opts.verbose)


# vim: set tw=80 sw=4 sts=4 et fdm=marker :
