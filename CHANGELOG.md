# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Project scaffolding: package layout, build configuration, test and lint tooling.
- Detection engine (standard library only): bounded regular expressions, checksum
  validation and context rules for French social security numbers (NIR), SIREN,
  SIRET, RPPS, IBAN, payment cards, French phone numbers, emails, IP addresses,
  API keys, bearer tokens, JWTs, private keys and credentials in URLs or assignments.
- Redaction actions per entity: mask, keyed pseudonym (HMAC-SHA256), partial, keep.
- JSON-aware redaction of nested and double-encoded tool arguments, with sensitive
  field names (`customer_name`, `email`, `iban`...) replaced entirely.
- Attribute key rules (allow, mask, hash, drop) for OpenTelemetry-style attributes.
- Policies as TOML, YAML or JSON files on top of presets (`standard`, `strict`,
  `debug-local`, `none`).
- Detector plugins through the `caviard.detectors` entry point group.
- `caviard scan` and `caviard keygen` commands.
