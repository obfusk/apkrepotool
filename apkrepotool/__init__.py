#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
apkrepotool - manage APK repos

FIXME
"""

import sys

from typing import Any

__version__ = "0.0.0"
NAME = "apkrepotool"


class Error(Exception):
    """Base class for errors."""


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
    except Error as e:
        print(f"Error: {e}.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

# vim: set tw=80 sw=4 sts=4 et fdm=marker :
