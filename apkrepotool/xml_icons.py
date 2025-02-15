#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2025 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
import zipfile

from typing import Dict, List, Optional, Tuple

import cairosvg                 # type: ignore[import-untyped]
import PIL.Image

import repro_apk.binres as binres

SCHEMA_SVG = "http://www.w3.org/2000/svg"
DRAWABLE = f"{{{binres.SCHEMA_ANDROID}}}drawable"
ARGB = re.compile(r"\A#[0-9a-f]{8}\Z")
CAP = dict(enumerate(("butt", "round", "square")))
JOIN = dict(enumerate(("miter", "round", "bevel")))
FILL = dict(enumerate(("evenodd", "nonzero")))
GRADIENT = dict(enumerate(("linear", "radial", "sweep")))
TAGMAP = {"vector": "svg", "group": "g", "path": "path"}


class Error(Exception):
    """Base class for errors."""


def extract_icon(zf: zipfile.ZipFile, filename: str, *, size: int = 512) -> bytes:
    """Extract XML icon by converting to SVG and then to PNG data."""
    infos = {i.orig_filename: i for i in zf.infolist()}
    resources = binres.read_chunk(zf.read(infos[binres.ARSC_FILE]))[0] if binres.ARSC_FILE in infos else None
    if resources is not None and not isinstance(resources, binres.ResourceTableChunk):
        raise Error("Unable to parse AXML")
    return _extract_icon(zf, infos, filename, resources=resources, size=size)


# FIXME: check end tags?
def _extract_icon(zf: zipfile.ZipFile, infos: Dict[str, zipfile.ZipInfo], filename: str, *,
                  resources: Optional[binres.ResourceTableChunk], size: int) -> bytes:
    if filename not in infos:
        raise Error(f"Entry not found: {filename!r}")
    axml_chunk = binres.read_chunk(zf.read(infos[filename]))[0]
    if not isinstance(axml_chunk, binres.XMLChunk):
        raise Error("Unable to parse AXML")
    adaptive_icon = background = foreground = bg_drawable = fg_drawable = None
    for i, c in enumerate(axml_chunk.children):
        if isinstance(c, binres.XMLElemStartChunk):
            if c.name == "vector":
                return _extract_vector(zf, infos, axml_chunk.children[i:], resources=resources, size=size)
            if c.name == "adaptive-icon":
                if adaptive_icon:
                    raise Error("Duplicate <adaptive-icon>")
                adaptive_icon = c
            elif not adaptive_icon:
                raise Error("Expected <adaptive-icon> or <vector>")
            elif c.name == "background":
                if background:
                    raise Error("Duplicate <background>")
                background = c
                if not (a := c.attrs_as_dict.get(DRAWABLE)):
                    raise Error("Missing drawable attr for <background>")
                bg_drawable = binres.brv_str_deref(a.typed_value, a.raw_value, resources=resources)
            elif c.name == "foreground":
                if foreground:
                    raise Error("Duplicate <foreground>")
                foreground = c
                if not (a := c.attrs_as_dict.get(DRAWABLE)):
                    raise Error("Missing drawable attr for <foreground>")
                fg_drawable = binres.brv_str_deref(a.typed_value, a.raw_value, resources=resources)
            elif c.name == "monochrome":
                pass
            else:
                raise Error(f"Unsupported tag: {c.name!r}")
            if background and foreground:
                break
    if not (bg_drawable and fg_drawable):
        raise Error("Missing <background> and/or <foreground>")
    return _combine_images(
        _extract_drawable(zf, infos, bg_drawable, resources=resources, size=size),
        _extract_drawable(zf, infos, fg_drawable, resources=resources, size=size))


def _combine_images(bg: PIL.Image.Image, fg: PIL.Image.Image) -> bytes:
    if bg.mode != "RGBA":
        bg = bg.convert("RGBA")
    if fg.mode != "RGBA":
        fg = fg.convert("RGBA")
    if bg.size > fg.size:
        bg = bg.resize(fg.size)
    elif fg.size > bg.size:
        fg = fg.resize(bg.size)
    bg.alpha_composite(fg)
    bio = io.BytesIO()
    bg.save(bio, "PNG")
    return bio.getvalue()


def _extract_drawable(zf: zipfile.ZipFile, infos: Dict[str, zipfile.ZipInfo], drawable: str, *,
                      resources: Optional[binres.ResourceTableChunk], size: int) -> PIL.Image.Image:
    if ARGB.fullmatch(drawable):
        return PIL.Image.new("RGBA", (size, size), _rgba(drawable))
    if drawable.endswith(".xml"):
        bio = io.BytesIO(_extract_icon(zf, infos, drawable, resources=resources, size=size))
    elif drawable.endswith(".png"):
        if drawable not in infos:
            raise Error(f"Entry not found: {drawable!r}")
        bio = io.BytesIO(zf.read(infos[drawable]))
    else:
        raise Error(f"Unsupported drawable: {drawable!r}")
    try:
        with PIL.Image.open(bio, formats=["PNG"]) as im:
            im.load()
            assert isinstance(im, PIL.Image.Image)
            return im
    except PIL.UnidentifiedImageError as e:
        raise Error(f"Unable to load PNG: {e}") from e


# FIXME: <shape>? <inset>?
def _extract_vector(zf: zipfile.ZipFile, infos: Dict[str, zipfile.ZipInfo], children: Tuple[binres.Chunk, ...],
                    *, resources: Optional[binres.ResourceTableChunk], size: int) -> bytes:
    tb, defs, vector = ET.TreeBuilder(), ET.Element("defs"), None
    tag_stack: List[binres.XMLElemStartChunk] = []
    for c in children:
        if isinstance(c, binres.XMLElemStartChunk):
            tag_stack.append(c)
            if c.name == "vector":
                if vector:
                    raise Error("Duplicate <vector>")
                vector = c
                _convert_vector(tb, c)
            elif not vector:
                raise Error("Expected <vector>")
            elif c.name == "group":
                _convert_group(tb, c)
            elif c.name == "path":
                _convert_path(zf, infos, tb, c, defs=defs, resources=resources)
            else:
                raise Error(f"Unsupported tag: {c.name!r}")
        elif isinstance(c, binres.XMLElemEndChunk):
            if not tag_stack:
                raise Error("End tag with empty stack")
            if c.name != tag_stack.pop().name:
                raise Error("Expected end tag to match start")
            tb.end(TAGMAP[c.name])
            if c.name == "vector":
                break
    bio = io.BytesIO()
    elem = tb.close()
    if len(defs):
        elem.insert(0, defs)
    ET.ElementTree(elem).write(bio)
    print(bio.getvalue().decode())  # FIXME
    data = cairosvg.svg2png(bytestring=bio.getvalue(), output_width=size, output_height=size)
    assert isinstance(data, bytes)
    return data


# FIXME: tint?
# FIXME: resources?
def _convert_vector(tb: ET.TreeBuilder, c: binres.XMLElemStartChunk) -> None:
    _expect_attrs(c, "width", "height", "viewportWidth", "viewportHeight", "autoMirrored")
    vpw = c.attr_as_float("viewportWidth", android=True)
    vph = c.attr_as_float("viewportHeight", android=True)
    viewbox = f"0 0 {vpw} {vph}"
    tb.start("svg", {"xmlns": SCHEMA_SVG, "viewBox": viewbox})


# FIXME: rotate, ...
# FIXME: resources?
def _convert_group(tb: ET.TreeBuilder, c: binres.XMLElemStartChunk) -> None:
    _expect_attrs(c, "scaleX", "scaleY", "translateX", "translateY")
    sx = c.attr_as_float("scaleX", android=True, optional=True)
    sy = c.attr_as_float("scaleY", android=True, optional=True)
    tx = c.attr_as_float("translateX", android=True, optional=True)
    ty = c.attr_as_float("translateY", android=True, optional=True)
    scale_x = str(sx) if sx is not None else "1"
    scale_y = str(sy) if sy is not None else "1"
    transform = f"translate({str(tx or 0)}, {str(ty or 0)}) scale({scale_x}, {scale_y})"
    tb.start("g", {"transform": transform})


def _convert_path(zf: zipfile.ZipFile, infos: Dict[str, zipfile.ZipInfo],
                  tb: ET.TreeBuilder, c: binres.XMLElemStartChunk, *, defs: ET.Element,
                  resources: Optional[binres.ResourceTableChunk]) -> None:
    _expect_attrs(c, "pathData", "fillColor", "strokeColor", "strokeWidth", "strokeAlpha",
                  "fillAlpha", "strokeLineCap", "strokeLineJoin", "fillType")
    data = c.attr_as_str("pathData", android=True, optional=True) or ""
    fill = _colour(zf, infos, c, "fillColor", defs=defs, resources=resources)
    stroke = _colour(zf, infos, c, "strokeColor", defs=defs, resources=resources)
    sw = c.attr_as_float("strokeWidth", android=True, optional=True)
    sa = c.attr_as_float("strokeAlpha", android=True, optional=True)
    fa = c.attr_as_float("fillAlpha", android=True, optional=True)
    slc = c.attr_as_int("strokeLineCap", android=True, optional=True)
    slj = c.attr_as_int("strokeLineJoin", android=True, optional=True)
    ft = c.attr_as_int("fillType", android=True, optional=True)
    try:
        attrs = {
            "d": data, "fill": fill, "stroke": stroke,
            "stroke-width": str(sw or 0),
            "stroke-opacity": str(sa) if sa is not None else "1",
            "fill-opacity": str(fa) if fa is not None else "1",
            "stroke-linecap": CAP[slc or 0],
            "stroke-linejoin": JOIN[slj or 0],
            "fill-rule": FILL[ft if ft is not None else 1],
        }
    except KeyError as e:
        raise Error("Unsupported attr value") from e
    tb.start("path", attrs)


def _expect_attrs(c: binres.XMLElemStartChunk, *attrs: str) -> None:
    expected_attrs = [f"{{{binres.SCHEMA_ANDROID}}}{a}" for a in attrs]
    for attr in c.attrs_as_dict:
        if attr not in expected_attrs:
            raise Error(f"Unsupported attr for <{c.name}>: {attr!r}")


def _colour(zf: zipfile.ZipFile, infos: Dict[str, zipfile.ZipInfo],
            c: binres.XMLElemStartChunk, attr: str, *, defs: Optional[ET.Element],
            default: str = "none", resources: Optional[binres.ResourceTableChunk]) -> str:
    if not (a := c.attrs_as_dict.get(f"{{{binres.SCHEMA_ANDROID}}}{attr}")):
        return default
    colour = binres.brv_str_deref(a.typed_value, a.raw_value, resources=resources)
    if ARGB.fullmatch(colour):
        return "none" if colour == "#00000000" else _rgba(colour)
    if defs is not None and colour.endswith(".xml"):
        return _extract_gradient(zf, infos, colour, defs=defs, resources=resources)
    raise Error(f"Unsupported colour value: {colour!r}")


def _extract_gradient(zf: zipfile.ZipFile, infos: Dict[str, zipfile.ZipInfo], filename: str,
                      *, defs: ET.Element, resources: Optional[binres.ResourceTableChunk]) -> str:
    if filename not in infos:
        raise Error(f"Entry not found: {filename!r}")
    axml_chunk = binres.read_chunk(zf.read(infos[filename]))[0]
    if not isinstance(axml_chunk, binres.XMLChunk):
        raise Error("Unable to parse AXML")
    gradient, stops = None, []
    for i, c in enumerate(axml_chunk.children):
        if isinstance(c, binres.XMLElemStartChunk):
            if c.name == "gradient":
                if gradient:
                    raise Error("Duplicate <gradient>")
                gradient = c
            elif not gradient:
                raise Error("Expected <gradient>")
            elif c.name == "item":
                _expect_attrs(c, "color", "offset")
                colour = _colour(zf, infos, c, "color", defs=None, default="#000000", resources=resources)
                off = c.attr_as_float("offset", android=True, optional=True)
                stops.append(ET.Element("stop", {"stop-color": colour, "offset": str(off or 0)}))
            else:
                raise Error(f"Unsupported tag: {c.name!r}")
    if not gradient:
        raise Error("Expected <gradient>")
    _expect_attrs(gradient, "angle", "type", "centerX", "centerY", "gradientRadius",
                  "startX", "startY", "endX", "endY")
    ty = gradient.attr_as_int("type", android=True, optional=True)
    angle = gradient.attr_as_float("angle", android=True, optional=True)
    gtype = GRADIENT.get(ty or 0, str(ty))
    if angle is not None and angle % 45 != 0:
        raise Error(f"Unsupported <gradient> angle: {angle}")
    attrs = {"id": f"gradient_{len(defs)}"}
    if angle is not None:
        attrs["gradientTransform"] = f"rotate({angle})"
    if gtype == "linear":
        attrs["x1"] = str(gradient.attr_as_float("startX", android=True))
        attrs["x2"] = str(gradient.attr_as_float("endX", android=True))
        attrs["y1"] = str(gradient.attr_as_float("startY", android=True))
        attrs["y2"] = str(gradient.attr_as_float("endY", android=True))
    elif gtype == "radial":
        attrs["cx"] = str(gradient.attr_as_float("centerX", android=True))
        attrs["cy"] = str(gradient.attr_as_float("centerY", android=True))
        attrs["r"] = str(gradient.attr_as_float("gradientRadius", android=True))
    else:
        raise Error(f"Unsupported <gradient> type: {gtype!r}")
    elem = ET.Element(f"{gtype}Gradient", attrs)
    elem.extend(stops)
    defs.append(elem)
    return f"url(#{attrs['id']})"


def _rgba(colour: str) -> str:
    return colour if colour == "none" else f"#{colour[3:]}{colour[1:3]}"


# vim: set tw=80 sw=4 sts=4 et fdm=marker :
