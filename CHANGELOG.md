# Changelog

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
