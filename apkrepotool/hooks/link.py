#!/usr/bin/python3
# encoding: utf-8
# SPDX-FileCopyrightText: 2025 FC (Fay) Stegerman <flx@obfusk.net>
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

from urllib.parse import urlparse

import apkrepotool


def run(tc: apkrepotool.ToolConfig, *args: str) -> None:
    """Print repo link."""
    assert tc.cfg is not None
    if args:
        raise apkrepotool.Error(f"Got unexpected extra arguments ({' '.join(args)})")
    fpr = apkrepotool.get_keystore_cert_fingerprint(tc.cfg, tc.java_stuff).upper()
    url = urlparse(tc.cfg.repo_url)
    if not url.path.endswith("/"):
        url = url._replace(path=f"{url.path}/")
    url = url._replace(query=f"fingerprint={fpr}")
    print(url.geturl())


# vim: set tw=80 sw=4 sts=4 et fdm=marker :
