#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2025 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

import argparse

import apkrepotool


def run(tc: apkrepotool.ToolConfig, *args: str) -> None:
    """Lint recipes."""
    parser = argparse.ArgumentParser(prog="apkrepotool lint")
    parser.add_argument("-v", "--verbose", action="store_true")
    opts = parser.parse_args(args)
    for recipe in tc.recipe_paths:
        if opts.verbose:
            print(f"Processing {str(recipe)!r}...")
        apkrepotool.parse_recipe_yaml(recipe, -1)   # parse & validate only


# vim: set tw=80 sw=4 sts=4 et fdm=marker :
