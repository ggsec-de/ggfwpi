# Changelog

## Unreleased

## 0.7.0-beta — 2026-08-08

- Split the 7,600-line implementation into the importable `ggfw` package while
  retaining the versioned compatibility launcher and CLI exit contract.
- Added optional `cryptography` RSA verification with a fail-closed standard-library fallback.
- Hardened DER parsing and PKCS#1 v1.5 comparison behavior.
- Added bounded external weak-password dictionaries without reporting candidate values.
- Replaced flattened `nc`/`socat` shell-execution matching with structured argv parsing
  and a review-required heuristic finding.
- Added package entrypoints, installation metadata, and expanded regression coverage.
- Validated the package entrypoint, cryptographic self-test, read-only SPI EEPROM
  acquisition, live-config comparison, GGCap creation, and report accounting on
  a physical Raspberry Pi 5 (BCM2712).

## 0.6.6-beta

- Licensed the public project under Apache License 2.0.
- Added persistent project attribution for Maciej Gojny and GGSEC in `NOTICE`.
- Added SPDX and copyright headers to Python source files.
- Added `AUTHORS.md`.
- Added a version-aware regression runner that selects the newest semantic GGFWPi version.
- Added a release-pinned test entry point.
- Added an explicit regression target banner.
- Added protection against testing stale modules.
- Retained cryptographic known-answer tests and full Secure Boot fixture coverage.
- Retained gate and summary accounting invariants.
- Retained read-only SPI behavior.

## 0.6.5-beta

- Added fail-closed summary accounting invariants.
- Added top-level and passive partition validation.
- Added cross-cutting `overall` counters.
- Added multi-attribute finding regression coverage.

## 0.6.4-beta

- Fixed Secure Boot policy rollup reporting.
- Added complete gate accounting and exclusion reasons.
- Fixed summary alignment and singular/plural rendering.

## 0.6.0–0.6.3 beta

- Added customer Secure Boot cryptographic validation.
- Added OTP and external provisioning evidence integration.
- Added BCM2712 customer `bootsys` counter-signature validation.
- Added embedded cryptographic known-answer tests.
- Added leaf-only policy gating and aggregate reporting.
