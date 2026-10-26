# Changelog

All notable changes to this pack are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [1.1.1] — 2026-10-26

### Fixed
- Loader `docker-compose.yml`: the external Wazuh network is now `wazuh-net` with a
  `<YOUR_WAZUH_NETWORK>` placeholder name and a hint comment (same pattern as `misp-net`).
  v1.1.0 referenced a fixed network name that a fresh install won't have, so
  `docker compose up` failed with "network ... declared as external, but could not be found".
- README: the configure step now says to set both external network names.

## [1.1.0] — 2026-10-26

### Added
- Three new CDB lists exported by the loader: `misp-urls` (`url`, `uri`), `misp-ja3`
  (`ja3-fingerprint-md5`, `ja3s-fingerprint-md5`) and `misp-files` (`filename`,
  `malware-sample`, `filename|<hash>`), with CDB-safe key normalisation.
- Rules **100227–100228** (URL), **100229–100231** (JA3, forward-looking) and
  **100232–100233** (filename).
- Loader: cold-cache warninglist warm-up probes (`WL_WARMUP_TRIES`, `WL_WARMUP_SLEEP`),
  `CRON_PULLALL` to skip the loader's own feed refresh when MISP workers already fetch.

### Changed
- Loader warninglist checking is now **fail-closed**: if MISP can't answer, that list is
  skipped and the last-known-good CDB stays in place (was fail-open).
- Loader refuses to push an empty list, refreshes an expired Wazuh API token once, and
  treats a 200 response carrying a per-item error as a failure. Failed pushes no longer
  count toward the manager reload.
- Loader exports before the staggered feed refresh, so a slow refresh can't delay the CDB
  update. `email-*` attribute types are never exported.
- README: new rules and lists, placeholder-list step, URL-matching limitation, extended
  ID-collision check.

## [1.0.0] — 2026-06-27

- Initial public release: IP / hash / domain CDB matching rules (100210–100218) and the
  MISP → Wazuh CDB loader.
