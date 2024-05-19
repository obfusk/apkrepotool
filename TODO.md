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
* [ ] `--continue-on-errors` (skip those APKs)
* [ ] `cache/apks.json`
* [ ] repo fingerprint, QR, ...
* [ ] more missing fields
* [ ] RequiresRoot, Liberapay/OpenCollective/..., MaintainerNotes, ...
* [ ] advanced options (e.g. mirrors, custom AFs, localised config)
* [ ] transparency log (2x) + signature blocklist
* [ ] hooks for checks
* [ ] hooks for deploy, init, etc.
* [ ] JSON schemas

## nice to have

* [ ] get app name from APK
* [ ] get (XML) icons from APK
* [ ] HSM support
* [ ] `apkcache.json` -> `timestamps.json` script
* [ ] per-APK AntiFeatures
* [ ] "API" ?!

## extensions

* [ ] RSS feed for announcements (e.g. app removals)
* [ ] exodus
* [ ] VT
* [ ] rbtlog
