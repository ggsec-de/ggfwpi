# GGFWPi

**Read-only Raspberry Pi firmware and platform security auditor with SPI EEPROM acquisition, Secure Boot chain validation, OTP evidence, boot integrity baselines, policy gates, and portable `.ggcap` evidence packages.**

Current release: **0.7.0-beta**

Developed by **GG Advanced IT Security UG** — [ggsec.de](https://ggsec.de)

## Overview

GGFWPi is a Python-based security auditing tool for Raspberry Pi platforms. It combines firmware, boot-chain, operating-system, credential, network, and evidence-quality checks in one report.

The tool is designed for technical security assessments, platform hardening, firmware research, appliance validation, and repeatable evidence collection. It distinguishes between:

- confirmed security findings;
- policy failures;
- evidence coverage gaps;
- aggregate findings;
- informational observations;
- controls that are not required by the selected policy.

This distinction is also reflected in process exit codes, remediation counts, gate accounting, and summary accounting invariants.

## Key capabilities

### Firmware and boot security

- Read-only SPI EEPROM acquisition through `flashrom` and `linux_spi`.
- SPI chip identification and SHA-256 measurement.
- Raw SPI boot configuration extraction.
- Raw EEPROM configuration versus live firmware configuration comparison.
- SPI status-register write-protection assessment.
- Boot-chain resolution from `config.txt` and related boot files.
- Device-specific boot integrity baselines and drift detection.
- Raspberry Pi EEPROM update, debug, network-install, boot-order, and A/B capability observations.

### Cryptographic Secure Boot validation

- Customer RSA-2048 public-key handling.
- `boot.img` and `boot.sig` SHA-256 and RSA PKCS#1 v1.5 verification.
- Signature timestamp and optional maximum-age policy.
- `target-soc` validation.
- EEPROM `pubkey.bin` parsing and consistency checks.
- EEPROM `bootconf.txt` and `bootconf.sig` validation.
- BCM2712 customer `bootsys` counter-signature validation.
- Customer public-key binding to OTP or external `rpiboot -j` provisioning metadata.
- Structured `VALID`, `INVALID`, and `UNVERIFIED` states.
- Embedded cryptographic known-answer self-tests.

GGFWPi validates the customer-controlled portion of the Secure Boot chain. Raspberry Pi vendor-root signatures are enforced by BootROM but are not independently replay-verified by GGFWPi.

### OTP and provisioning evidence

- Model-aware OTP decoding.
- BCM2711 Secure Boot and JTAG-lock state decoding.
- Fail-closed BCM2712 evidence model for fields not available through the public runtime mapping.
- Optional external provisioning metadata collected with `rpiboot -j`.
- Structured unresolved-field reporting without inferring undocumented OTP rows.

### Operating-system posture

- Weak and vendor-default credential detection.
- SSH configuration and authorized-key checks.
- Wildcard and potentially exposed network listeners.
- Firewall presence.
- APT repository transport and trust observations.
- Critical file permissions.
- Kernel mitigation and debug-interface checks.
- Suspicious process indicators.

### Evidence and reporting

- Timestamped evidence directory.
- Standalone JSON report support.
- ZIP-based `.ggcap` evidence package.
- Evidence source, acquisition method, and trust-level metadata.
- Positive checks as well as findings.
- Deduplicated remediation groups.
- Complete gate accounting with explicit inclusion and exclusion reasons.
- Fail-closed summary-accounting invariants.

## Tested environment

The current release has been hardware-tested on:

- Raspberry Pi 5;
- BCM2712;
- Kali Linux for Raspberry Pi;
- Python 3;
- Winbond W25Q16.V SPI EEPROM through `/dev/spidev10.0`.

The code contains platform-aware logic for other Raspberry Pi SoCs, with the most complete Secure Boot evidence paths currently implemented for BCM2711 and BCM2712.

## Requirements

GGFWPi uses only the Python standard library for its core operation. RSA verification
prefers the optional `cryptography` backend when installed and otherwise uses the
embedded fail-closed verifier. Password verification can use one of the following
backends:

- `passlib` — preferred;
- Python `crypt`, where available;
- system `libcrypt` through `ctypes`.

External tools used when available:

```text
vcgencmd
rpi-eeprom-config
rpi-eeprom-update
rpi-eeprom-ab
flashrom
```

Root privileges are required for complete host inspection, `/etc/shadow` access, and SPI EEPROM acquisition.

Check the available CLI and dependencies:

```bash
python3 -m ggfw --help
# Compatibility entrypoint retained for existing automation:
python3 GGFWPi_v0.7.0-beta.py --help
```

## Installation

Clone the repository:

```bash
git clone https://github.com/patapik/ggfwpi.git
cd ggfwpi
```

Install the package with both optional security backends:

```bash
python3 -m pip install '.[full]'
```

For a dependency-free checkout, `python3 -m ggfw` and the compatibility launcher
continue to work with the standard-library fallback implementations.

Optional password-verification backend on Debian-based systems:

```bash
sudo apt update
sudo apt install python3-passlib
```

Install the Raspberry Pi EEPROM tools and `flashrom` through the packages appropriate for the target distribution. Verify their locations with:

```bash
command -v vcgencmd
command -v rpi-eeprom-config
command -v rpi-eeprom-update
command -v rpi-eeprom-ab
command -v flashrom
```

## Quick start

### 1. Verify the cryptographic engine

This mode does not inspect the host or access SPI:

```bash
python3 GGFWPi_v0.7.0-beta.py --crypto-self-test
# Equivalent package entrypoint:
python3 -m ggfw --crypto-self-test
```

Expected result:

```text
[*] Crypto self-test result: PASS
[*] Process exit code: 0
```

### 2. Run a standard audit

```bash
sudo python3 GGFWPi_v0.7.0-beta.py \
  --policy-profile default \
  --show-passed
```

### 3. Create a device-specific boot baseline

```bash
sudo mkdir -p /var/lib/ggfw

sudo python3 GGFWPi_v0.7.0-beta.py \
  --create-baseline /var/lib/ggfw/boot-baseline.json \
  --policy-profile default
```

Review and protect the baseline after creation. A baseline is a device-specific reference measurement, not an official vendor allowlist.

### 4. Compare against the baseline

```bash
sudo python3 GGFWPi_v0.7.0-beta.py \
  --baseline /var/lib/ggfw/boot-baseline.json \
  --policy-profile hardened \
  --show-passed \
  --fail-on HIGH
```

### 5. Audit a Secure Boot policy

```bash
sudo python3 GGFWPi_v0.7.0-beta.py \
  --baseline /var/lib/ggfw/boot-baseline.json \
  --policy-profile secure-boot-required \
  --show-otp \
  --secure-boot-evidence \
  --fail-on HIGH
```

For provisioned systems, provide external provisioning evidence and the expected customer public key:

```bash
sudo python3 GGFWPi_v0.7.0-beta.py \
  --baseline /var/lib/ggfw/boot-baseline.json \
  --policy-profile secure-boot-required \
  --otp-metadata /path/to/rpiboot-json-or-directory \
  --secure-boot-public-key /path/to/customer-public.pem \
  --max-boot-signature-age-days 365 \
  --show-otp \
  --secure-boot-evidence \
  --fail-on HIGH
```

Explicit external input paths are validated before acquisition begins. Missing, unreadable, ambiguous, or malformed input causes a controlled tool error.

## Policy profiles

| Profile | Intended use |
|---|---|
| `default` | General platform assessment without requiring Secure Boot. |
| `hardened` | Stricter runtime and platform posture; incomplete Secure Boot evidence is surfaced for review. |
| `secure-boot-required` | Requires the customer Secure Boot controls and cryptographic evidence expected by the policy. |
| `resilient-appliance` | Treats EEPROM A/B update capability and resilience controls as required where applicable. |

## Gate semantics

Example CI gate:

```bash
sudo python3 GGFWPi_v0.7.0-beta.py \
  --policy-profile hardened \
  --fail-on HIGH
```

Severity-based gates evaluate leaf security and policy findings. By default:

- coverage gaps do not trigger a severity gate;
- aggregate findings never trigger process exit;
- every candidate finding is reported as either matched or excluded;
- excluded findings include explicit reasons.

Include leaf coverage gaps in a severity gate:

```bash
--fail-on HIGH --fail-on-coverage
```

Run a dedicated evidence-completeness gate:

```bash
--fail-on COVERAGE_GAP
```

Explicitly exclude finding attributes from gate evaluation:

```bash
--gate-exclude COVERAGE_GAP
--gate-exclude AGGREGATE
```

Exclusions affect process gating only. Findings remain visible in reports and evidence packages.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Audit completed and the selected policy gate was not triggered. |
| `1` | Tool, argument, acquisition, baseline, packaging, or accounting failure. |
| `2` | Audit completed and the selected `--fail-on` policy gate was triggered. |

A security finding is not a tool failure. Exit code `2` indicates that the audit completed successfully and found conditions matching the configured gate.

## Output

By default, GGFWPi creates:

```text
ggfw-evidence/
├── ggfw-<timestamp>-<soc>/
│   ├── report.json
│   └── evidence/
└── ggfw-<timestamp>-<soc>.ggcap
```

The `.ggcap` file is a ZIP-based evidence container containing the report, manifest, collected artifacts, hashes, Secure Boot evidence, and supporting metadata.

Specify a package path:

```bash
--output /path/to/audit.ggcap
```

Write an additional standalone JSON report:

```bash
--json-output /path/to/report.json
```

Skip SPI acquisition when it is not available or not required:

```bash
--skip-spi
```

Run only OTP and Secure Boot evidence collection:

```bash
sudo python3 GGFWPi_v0.7.0-beta.py \
  --otp-only \
  --show-otp \
  --secure-boot-evidence
```

Extend the built-in weak/default password audit with a local UTF-8 wordlist:

```bash
sudo python3 -m ggfw --weak-password-file /secure/path/weak-passwords.txt
```

The file is bounded and read before the scan starts. Its contents and matched
passwords are never written to reports; only candidate counts and the file's
SHA-256 digest are recorded.

## Read-only SPI design

GGFWPi does not write, erase, or modify SPI flash and does not enable or disable write protection. SPI interaction is limited to:

- programmer/chip probing;
- write-protection status queries;
- EEPROM reads.

Remediation instructions may describe external provisioning or recovery procedures, but the auditor itself remains read-only.

## Evidence trust model

Most evidence collected from a running system is classified as **in-band** and normally receives `MEDIUM` trust because the examined operating system or firmware interface mediates the observation.

Higher-trust evidence can include:

- independent external SPI acquisition;
- offline file measurements;
- independently verified signed artifacts;
- externally acquired provisioning metadata with controlled provenance.

GGFWPi reports evidence limitations separately from confirmed security failures. Missing evidence is not automatically treated as a broken cryptographic signature.

## Running the regression tests

Use the version-aware test runner:

```bash
python3 test_GGFWPi_latest.py
```

The first line identifies the selected module:

```text
[*] GGFW regression target: GGFWPi_v0.7.0-beta.py
```

The suite covers:

- package and compatibility-launcher entrypoints;
- optional and built-in RSA backend behavior;
- strict DER rejection and fail-closed backend errors;
- bounded external weak-password dictionaries without credential disclosure;
- structured dual-use process heuristics;
- OTP decoders;
- Secure Boot positive and negative cryptographic fixtures;
- full BCM2711 and BCM2712 customer-chain scenarios;
- malformed and missing signature states;
- policy and gate behavior;
- summary and gate accounting invariants;
- `.ggcap` packaging;
- semantic selection of the current module.

Run the release-pinned suite:

```bash
python3 test_GGFWPi_v0.7.0.py
```

## Important limitations

- A normal in-band SPI read is mediated by the running kernel and is not equivalent to an independent hardware-programmer acquisition.
- Public BCM2712 runtime OTP output does not expose every customer Secure Boot field. Use externally collected `rpiboot -j` metadata where conclusive provisioning evidence is required.
- Raspberry Pi vendor-root signatures are enforced by BootROM but are not independently replay-verified by GGFWPi.
- A device-specific baseline detects drift from the recorded state; it does not prove that the recorded state was originally trustworthy.
- A `PASS` for the embedded cryptographic self-test proves the known-answer implementation paths, not the provisioning state of the inspected device.

## Repository layout

```text
.
├── GGFWPi_v0.7.0-beta.py       # compatibility launcher
├── pyproject.toml
├── ggfw/
│   ├── models/                 # findings, evidence, reports
│   ├── parsers/                # config, cmdline, EEPROM image
│   ├── boot/                   # resolution and integrity
│   ├── hardware/               # platform, interrogation, OTP
│   ├── crypto/                 # RSA, signatures, validation, KAT
│   ├── engines/                # host and hardware policies
│   ├── spi/                    # read-only EEPROM acquisition
│   ├── reporting/              # console and policy gates
│   └── packaging/              # .ggcap evidence package
├── test_GGFWPi_latest.py
├── test_GGFWPi_v0.7.0.py
├── README.md
├── LICENSE
├── NOTICE
├── AUTHORS.md
├── SECURITY.md
├── CHANGELOG.md
└── .gitignore
```

## Security reports

Do not publish suspected vulnerabilities in public GitHub issues. Follow the process in [`SECURITY.md`](SECURITY.md).

## Project status

GGFWPi is currently a **beta** security engineering and evidence-collection tool. Reports should be reviewed by a qualified analyst, particularly before destructive remediation, OTP provisioning, or irreversible Secure Boot configuration changes.

## Author and project attribution

GGFWPi was developed by **Maciej Gojny** for **GGSEC — GG Advanced IT Security UG**.

Project website: https://ggsec.de

The original attribution is recorded in [`NOTICE`](NOTICE) and additional project information is available in [`AUTHORS.md`](AUTHORS.md).

## License

GGFWPi is licensed under the **Apache License, Version 2.0**. Everyone may use, copy, modify, distribute, sublicense, and use the software commercially under the terms of that license.

Redistributions and derivative works must retain the applicable copyright, license, and attribution notices. Keep the [`LICENSE`](LICENSE) file and the attribution contained in [`NOTICE`](NOTICE) with redistributed copies, as required by Apache-2.0.

Copyright © 2026 GG Advanced IT Security UG.  
Developed by Maciej Gojny for GGSEC.
