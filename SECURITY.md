# Security policy

## Reporting a vulnerability

Do not disclose suspected GGFWPi vulnerabilities in a public GitHub issue.

Send the report privately to GG Advanced IT Security using the contact channel published at:

https://ggsec.de

Include, where available:

- affected GGFWPi version;
- operating system and Raspberry Pi model;
- exact command line;
- relevant terminal output;
- minimal reproduction steps;
- expected and observed behavior;
- whether the issue can cause a false `PASS`, false `INVALID`, incorrect exit code, evidence loss, or unintended device modification.

## Priority issues

The following classes should be treated as high priority:

- invalid cryptographic evidence accepted as valid;
- missing evidence reported as cryptographically valid;
- confirmed invalid signatures downgraded to informational states;
- read-only SPI guarantees violated;
- evidence package integrity or manifest bypass;
- policy or summary accounting invariants bypassed;
- credential material exposed in reports or logs;
- path traversal or arbitrary file overwrite through output handling.

## Supported versions

During beta development, only the latest published release is actively maintained unless otherwise stated in a release notice.
