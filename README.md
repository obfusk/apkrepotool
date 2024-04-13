<!-- SPDX-FileCopyrightText: 2024 FC (Fay) Stegerman <flx@obfusk.net> -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!--

[![GitHub Release](https://img.shields.io/github/release/obfusk/apkrepotool.svg?logo=github)](https://github.com/obfusk/apkrepotool/releases)
[![PyPI Version](https://img.shields.io/pypi/v/apkrepotool.svg)](https://pypi.python.org/pypi/apkrepotool)
[![Python Versions](https://img.shields.io/pypi/pyversions/apkrepotool.svg)](https://pypi.python.org/pypi/apkrepotool)
[![CI](https://github.com/obfusk/apkrepotool/actions/workflows/ci.yml/badge.svg)](https://github.com/obfusk/apkrepotool/actions/workflows/ci.yml)
[![AGPLv3+](https://img.shields.io/badge/license-AGPLv3+-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.html)

-->

# apkrepotool - manage APK repos

`apkrepotool` is a tool for managing APK repositories that can be used with an
F-Droid-compatible client, specifically for generating v1 & v2 index JSON & JAR
files from a compatible directory structure with the required YAML metadata and
fastlane metadata & image files.

## CLI

FIXME

```bash
...
```

## Directory Structure

FIXME

```
...
```

## Initial Setup

FIXME

## TODO

* [x] create `index-v1.json`
* [x] create `index-v2.json`
* [ ] create `entry.json`
* [ ] create `diffs/*.json`
* ...

## Installing

<!--

### Using pip

```bash
$ pip install apkrepotool
```

-->

### From git

NB: this installs the latest development version, not the latest release.

```bash
$ git clone https://github.com/obfusk/apkrepotool.git
$ cd apkrepotool
$ pip install -e .
```

NB: you may need to add e.g. `~/.local/bin` to your `$PATH` in order to run
`apkrepotool`.

To update to the latest development version:

```bash
$ cd apkrepotool
$ git pull --rebase
```

## Dependencies

Python >= 3.8 + `click` + `ruamel.yaml` + `repro-apk`.

NB: AXML support isn't released yet, so for now you need the `binres` branch
from git for `repro-apk`.

### Debian/Ubuntu

```bash
$ apt install python3-pip python3-click python3-ruamel.yaml
$ pip install git+https://github.com/obfusk/reproducible-apk-tools.git@binres-20240211
```

## License

[![AGPLv3+](https://www.gnu.org/graphics/agplv3-155x51.png)](https://www.gnu.org/licenses/agpl-3.0.html)

<!-- vim: set tw=70 sw=2 sts=2 et fdm=marker : -->
