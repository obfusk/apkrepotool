## v0.0.1

* [x] `index-v1.json`
* [x] `index-v2.json`
* [x] `entry.json`
* [x] `-vv` (show files processed?)
* [x] `timestamps.json`
* [x] keystore config (no passwds in yml)
* [x] signed & compressed JARs
* [x] `diffs/*.json`
* [x] CI
* [x] icon
* [x] hashed graphics files
* [x] `targetSdk=minSdk` if unset
* [x] `uses-permission-sdk-23`, ...
* [x] aask opt-out
* [x] more metadata (license, links, ...)
* [x] AntiFeatures
* [x] proper `repro-apk` `binres` release & dependency
* [x] README

## next

* [x] CI/testing: small test repo in submodule
* [x] nativecode
* [x] categories in index
* [x] ~/.apkrepotool: document & print() (#10)
* [x] link subcomand (get url w/ fingerprint) (#8)
* [x] implement & use `binres.get_manifest_info()` (#18)
* [x] test coverage (#11)
* [x] `cache/apks.json` (#7)
* [ ] run subcommand (hooks for deploy, init, etc.) (#9)
* [ ] lint subcommand & JSON schemas (#4)
* [ ] `--continue-on-errors` (skip those APKs) (#6)
* [ ] more YAML: RequiresRoot, Liberapay/OpenCollective/..., MaintainerNotes, ... (#16)
* [ ] advanced options (e.g. mirrors, custom AFs, localised config, per-APK AFs) (#14)
* [ ] transparency log (2x) + signature blocklist (#13)
* [ ] switch CI back to latest repro-apk instead of master (#20)
* [ ] increase test coverage: error paths (#21)

## more

* [ ] hooks for checks (#12)
* [ ] QR code (#17)
* [ ] HSM support (#15)
* [ ] .deb (#2)

## nice to have (#5)

* [x] get app name from APK
* [x] get PNG icons from APK
* [ ] get webp icons from APK
* [ ] get XML icons from APK
* [ ] `apkcache.json` -> `timestamps.json` script
* [ ] "API" ?!

## extensions (#3)

* [ ] RSS feed for announcements (e.g. app removals)
* [ ] exodus
* [ ] VT
* [ ] rbtlog
