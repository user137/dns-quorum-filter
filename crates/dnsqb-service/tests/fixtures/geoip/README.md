# GeoIP test fixture

`GeoIP2-Country-Test.mmdb` is vendored directly from
[`maxmind/MaxMind-DB`](https://github.com/maxmind/MaxMind-DB), `test-data/GeoIP2-Country-Test.mmdb`
(fetched 2026-08-29, `main` branch). Dual-licensed Apache-2.0 or MIT by that repository — not a git
submodule (the `maxminddb` crate's own test suite gates its fixtures behind one; this repo only
needs this one small file, not the rest of that submodule's other fixture databases).

Used by `crates/dnsqb-service/src/geoip.rs`'s unit tests (T-74). Not a real DB-IP Lite or MaxMind
GeoLite2 database — a synthetic test file with a handful of known IP→country mappings, generated
by that repo's own `write-test-data` tooling. `89.160.20.112 → SE` is the same known-good
assertion `maxminddb`'s own `reader_test.rs::test_lookup_country` makes against this exact file.
