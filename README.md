<!-- SPDX-FileCopyrightText: 2025 FC (Fay) Stegerman <flx@obfusk.net> -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

[![GitHub Release](https://img.shields.io/github/release/obfusk/apkrepotool.svg?logo=github)](https://github.com/obfusk/apkrepotool/releases)
[![PyPI Version](https://img.shields.io/pypi/v/apkrepotool.svg)](https://pypi.python.org/pypi/apkrepotool)
[![Python Versions](https://img.shields.io/pypi/pyversions/apkrepotool.svg)](https://pypi.python.org/pypi/apkrepotool)
[![CI](https://github.com/obfusk/apkrepotool/actions/workflows/ci.yml/badge.svg)](https://github.com/obfusk/apkrepotool/actions/workflows/ci.yml)
[![AGPLv3+](https://img.shields.io/badge/license-AGPLv3+-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.html)

<p align="center">
  <img src="icon.svg" alt="apkrepotool logo" width="160" />
</p>

# apkrepotool - manage APK repos

`apkrepotool` is a tool for managing APK repositories that can be used with an
F-Droid-compatible client; specifically, it generates v1 & v2 index JSON & JAR
files from a compatible directory structure with the required YAML metadata and
fastlane metadata & image files.

NB: **work in progress**; currently this is a first *alpha* release with
*minimum functionality for a simple repo*.  Testing, feedback, bug reports, and
feature requests are very welcome :)

## Setup

See "Keystore & Icon" below for how to generate a keystore and use a generic
icon if you don't have one of your own; see "Configuration Files" for
configuration file examples; see "Directory Structure" for where all the
necessary files go.

### Requirements: Apps, Configuration, Metadata

* keystore (to sign the index) -- keep this safe and backed up!
* PNG icon (for the repository itself)
* YAML config file (`config.yml`) specifying the repo details and paths to the keystore etc.
* per-app YAML files (`metadata/my.app.id.yml`) specifying details for each app
* fastlane-compatible metadata files (`full_description.txt` etc.)
* fastlane-compatible image files (`icon.png`, `featureGraphic.png`, etc.)
* APK files for each app

### Requirements: Software

* Python, `apkrepotool` and its dependencies (e.g. `pip install apkrepotool`)
* OpenJDK (e.g. `apt install openjdk-11-jdk-headless`)
* `apksigner` JAR file (e.g. `apt install apksigner` or e.g.
  `/path/to/Android/Sdk/build-tools/34.0.0/lib/apksigner.jar` from an installed
  Android SDK)

### Keystore & Icon

NB: you probably don't want to accidentally commit your keystore and/or
passwords to git!  And please make sure you pay attention to the key properties
since you can't change the signing key later.  You don't need to fill in your
full name but you'll want to avoid having fields set to "Unknown" and use e.g.
your handle/username so people can identify the key as belonging to you.

NB: this is an example; replace `myrepo` with something more appropriate and
make sure the key size and validity are appropriate for your use.

See "Configuration Files" below for options for storing the keystore password.

```bash
$ mkdir myrepo
$ cd myrepo
$ keytool -genkey -v -keystore keystore.jks -alias myrepo -keyalg RSA -keysize 4096 -sigalg SHA512withRSA -validity 10000
$ mkdir -p repo/icons
$ wget -O repo/icons/icon.png -- https://github.com/obfusk/apkrepotool/raw/master/icon.png
$ vim config.yml
[...]
```

## CLI

NB: `apkrepotool` should only be run in trusted directories under your control
as `config.yml` contains e.g. shell commands to be run to access the keystore,
can set `apkrepotool_dir` from which Java code will be executed, and can define
hooks that run Python code from `hooks/*.py`.

NB: `apkrepotool` will save a `Cert.java` (and `Cert.class` if `javac` is
available and can compile `Cert.java`) in `~/.apkrepotool` (unless a different
`apkrepotool_dir` is specified in `config.yml`); these are needed to interface
with the `apksigner` JAR file to verify APK signatures.

```bash
$ apkrepotool update -v
Processing 'repo/catima-v2.28.0.apk'...
  'me.hackerchick.catima':133 ('2.28.0')
Processing 'repo/catima-v2.29.0.apk'...
  'me.hackerchick.catima':134 ('2.29.0')
Processing 'repo/jiten-webview-1.0.3.apk'...
  'dev.obfusk.jiten_webview':202108010 ('1.0.3')
Processing 'metadata/dev.obfusk.jiten_webview.yml'...
Processing 'metadata/me.hackerchick.catima.yml'...
Writing index-v1.json...
Writing index-v2.json...
Writing diff/1714265787000.json...
Writing entry.json...
Writing cache/repo/1714266451000.json...
Signing index-v1.jar...
Signing entry.jar...
```

```bash
$ apkrepotool link
https://example.com/test/repo/?fingerprint=D79397F1A5615239F6D51DAF4814C56A1B9BE35B08B89CC472D801626D22FE7D
```

```bash
$ apkrepotool --help
Usage: apkrepotool [OPTIONS] COMMAND [ARGS]...

  apkrepotool - manage APK repos

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  link    print repo link
  lint    lint recipes
  update  generate/update index
$ apkrepotool link --help
[...]
$ apkrepotool update --help
[...]
```

## Directory Structure

<details>

```
.
├── cache                               # generated by apkrepotool
├── config.yml                          # main config file
├── keystore.jks                        # don't accidentally commit this!
├── metadata
│   ├── dev.obfusk.jiten_webview        # fastlane metadata
│   │   └── en-US
│   │       ├── full_description.txt
│   │       └── short_description.txt
│   ├── dev.obfusk.jiten_webview.yml    # app metadata
│   ├── me.hackerchick.catima           # fastlane metadata
│   │   ├── de-DE
│   │   │   ├── changelogs
│   │   │   │   ├── 133.txt
│   │   │   │   └── 134.txt
│   │   │   ├── full_description.txt
│   │   │   ├── short_description.txt
│   │   │   └── title.txt
│   │   ├── en-US
│   │   │   ├── changelogs
│   │   │   │   ├── 133.txt
│   │   │   │   └── 134.txt
│   │   │   ├── full_description.txt
│   │   │   ├── short_description.txt
│   │   │   └── title.txt
│   │   └── zh-TW
│   │       ├── full_description.txt
│   │       ├── short_description.txt
│   │       └── title.txt
│   └── me.hackerchick.catima.yml       # app metadata
└── repo
    ├── catima-v2.28.0.apk              # put APKs here
    ├── catima-v2.29.0.apk              # put APKs here
    ├── dev.obfusk.jiten_webview        # put images here
    │   └── en-US
    │       ├── featureGraphic.png
    │       ├── icon.png
    │       └── phoneScreenshots
    │           ├── 1.png
    │           ├── 2.png
    │           ├── 3.png
    │           ├── 4.png
    │           └── 5.png
    ├── diff                            # generated by apkrepotool
    ├── entry.jar                       # generated by apkrepotool
    ├── entry.json                      # generated by apkrepotool
    ├── icons
    │   └── icon.png                    # put icon.png here
    ├── index-v1.jar                    # generated by apkrepotool
    ├── index-v1.json                   # generated by apkrepotool
    ├── index-v2.json                   # generated by apkrepotool
    ├── jiten-webview-1.0.3.apk         # put APKs here
    └── me.hackerchick.catima           # put images here
        ├── de-DE
        │   └── featureGraphic.png
        ├── en-US
        │   ├── featureGraphic.png
        │   ├── icon.png
        │   └── phoneScreenshots
        │       ├── screenshot-01.png
        │       ├── screenshot-02.png
        │       ├── screenshot-03.png
        │       ├── screenshot-04.png
        │       ├── screenshot-05.png
        │       ├── screenshot-06.png
        │       ├── screenshot-07.png
        │       └── screenshot-08.png
        └── zh-TW
            └── featureGraphic.png
```

</details>

## Configuration Files

### config.yml

NB: this example uses `cat` and simply stores the passwords unencrypted in
plaintext files -- do not commit these to git! -- but you can easily use
something like `gpg -d /path/to/.keystorepass.gpg` to decrypt an encrypted
password file instead.

```yaml
# repo information
repo_url: https://example.com/fdroid/repo/
repo_name: My Repo
repo_description: >-
  This is a repository of apps to be used with an F-Droid-compatible client.
  Applications in this repository are official binaries built by the original
  application developers.

# signing config
repo_keyalias: myrepo
keystore: /path/to/keystore.jks
keystorepass_cmd: cat /path/to/.keystorepass
keypass_cmd: cat /path/to/.keypass

# optional settings
apkrepotool_dir: /path/to/apkrepotool_dir
apksigner_jar: /path/to/apksigner.jar
java_home: /usr/lib/jvm/java-11-openjdk-amd64
```

### metadata/me.hackerchick.catima.yml

```yaml
Categories:
  - Money
License: GPL-3.0-or-later
AuthorName: Sylvia van Os
AuthorEmail: catima@example.com
AuthorWebSite: https://sylviavanos.nl
WebSite: https://catima.app/
SourceCode: https://github.com/CatimaLoyalty/Android
IssueTracker: https://github.com/CatimaLoyalty/Android/issues
Translation: https://hosted.weblate.org/projects/catima/catima/
Changelog: https://github.com/CatimaLoyalty/Android/blob/HEAD/CHANGELOG.md
Donate: https://paypal.me/sylviavanos

Name: Catima

AllowedAPKSigningKeys: d405cd69ede4c22074c328fb825689a84ab3fca4b3fdf0b6cc1333af62c67eb3

CurrentVersion: 2.29.0
CurrentVersionCode: 134
```

## Hooks & Aliases

Hooks allow adding custom functionality via subcommands.  Aliases allow creating
short names for one or more subcommands plus options.  See below for an example.

Custom hooks are defined through the `hooks:` property in `config.yml` and a
corresponding `.py` file in the `hooks/` subdirectory of the repository (i.e.
the directory in which `apkrepotool` is run).  Similarly, aliases are defined
via the `aliases:` property.

Hooks can take command-line arguments (and can implement their own option
parsers if needed) but it is recommended they take configuration from
`config.yml` when possible; running an alias will pass all arguments to each of
its commands.

The only subcommand that is not a hook is `update`; `link` and `lint` are
built-in hooks (found in `apkrepotool/hooks/`).

NB: more built-in hooks -- to create a new repo, rename APKs, extract icons from
APKs, `rsync` the repo to a server, etc. -- are planned but currently not yet
implemented.

### hooks/example.py

This hook is meant as a comprehensive (though not particularly useful) example
and implements its functionality through a shell script it runs, to illustrate
how one can write hooks in other languages with some Python glue.  It is
generally recommended to write hooks directly in Python when possible (built-in
hooks always are).

<details>

```python
import os
import subprocess
import sys

from pathlib import Path

import apkrepotool


def run(tc: apkrepotool.ToolConfig, *args: str) -> None:
    assert tc.cfg is not None   # to make the type checker happy
    # per-hook configuration from config.yml
    config = tc.cfg.hooks["example"].config
    # JSON schema in the same directory
    schema_file = Path(__file__).with_suffix(".json")
    # shell script in the same directory
    shell_script = Path(__file__).with_suffix(".sh")
    schema = apkrepotool.load_json(schema_file)
    # validate the config against the JSON schema
    apkrepotool.validate_against_schema(config, schema, "(example hook config)")
    # put the config in environment variables for the shell script
    env = dict(COUNT_RECIPES=str(config["count_recipes"]).lower(),
               COUNT_APKS=str(config["count_apks"]).lower())
    print(f"RUNNING example.py\n  name={__name__}\n  config={config}\n  args={args}")
    sys.stdout.flush()          # flush before calling shell script b/c of buffering
    # run the shell script (and fail if it exits with a non-zero exit code)
    subprocess.run(["bash", str(shell_script), *args], check=True, env={**os.environ, **env})
```

</details>

### hooks/example.sh

The shell script part that simply displays the number of recipes and APKs (which
would have been easier to do in pure Python (using `len(tc.recipe_paths)` and
`len(tc.apk_paths())`).

<details>

```bash
#!/bin/bash
set -euo pipefail
shopt -s nullglob
echo "RUNNING example.sh"
echo "  args=(" "$@" ")"
if [ "$COUNT_RECIPES" = true ]; then
  recipes=( metadata/*.yml )
  echo "this repo contains ${#recipes[@]} recipe(s)"
fi
if [ "$COUNT_APKS" = true ]; then
  apks=( repo/*.apk )
  echo "this repo contains ${#apks[@]} APK(s)"
fi
```

</details>

### hooks/example.json

Having a JSON schema to validate the hook's configuration is entirely optional
but can be useful.

<details>

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "example hook config",
  "description": "example hook config (in config.yml)",
  "type": "object",
  "properties": {
    "count_recipes": {
      "type": "boolean"
    },
    "count_apks": {
      "type": "boolean"
    }
  },
  "required": [
    "count_recipes",
    "count_apks"
  ],
  "additionalProperties": false
}
```

</details>

### Relevant part of config.yml

<details>

```yaml
aliases:
  u: update
  test:
    - lint
    - update -v
    - link
    - example

hooks:
  - name: example
    info: example hook
    config:
      count_recipes: true
      count_apks: true
```

</details>

### Running --help with the hooks and aliases above

<details>

```bash
$ apkrepotool --help
Usage: apkrepotool [OPTIONS] COMMAND [ARGS]...

  apkrepotool - manage APK repos

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  example  example hook
  link     print repo link
  lint     lint recipes
  test     alias for lint, update -v, link, example
  u        alias for update
  update   generate/update index
```

</details>

### Another example: iterating over new APKs only

<details>

```python
def run(tc: apkrepotool.ToolConfig, *args: str) -> None:
    ...
    timestamps = apkrepotool.load_timestamps(tc.cur_dir)
    for apkfile in tc.apk_paths():
        if apkfile not in timestamps:
            # do something with new APK
    ...
```

</details>

## Installing

### Using pip

```bash
$ pip install apkrepotool
```

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

Python >= 3.9 + `click` + `jsonschema` + `ruamel.yaml` + `repro-apk` >= 0.2.7.

### Debian/Ubuntu

```bash
$ apt install python3-pip python3-click python3-jsonschema python3-ruamel.yaml
$ pip install git+https://github.com/obfusk/reproducible-apk-tools.git@v0.3.0
```

## License

[![AGPLv3+](https://www.gnu.org/graphics/agplv3-155x51.png)](https://www.gnu.org/licenses/agpl-3.0.html)

<!-- vim: set tw=70 sw=2 sts=2 et fdm=marker : -->
