# 172X Command Releases

Proprietary distribution surface for verified 172X Command binaries and release metadata. The
Command source remains private and is not licensed or published by this repository.

GitHub Releases is the only required artifact store. Release automation may create or replace a
complete five-file **draft** release only after the signed and notarized DMG, SLSA provenance,
CycloneDX SBOM, checksums, and `release-record-v1.json` pass validation. Automatic updates are
disabled, so updater archives and signatures are forbidden unless a separately approved contract
introduces a trusted updater public key. Drafts are private; public promotion is a separate manual
decision. Core downloads are free and never depend on Founder or supporter payment.

Unsigned, unstapled, unnotarized, incomplete, or metadata-mismatched artifacts are untrusted and
must not be downloaded or published. Rollback means deliberately selecting and publishing a prior
verified release; released assets are never silently mutated.

Run the required local gate:

```sh
./scripts/verify.sh
```

Security reports and release support: [SECURITY.md](SECURITY.md).

Copyright Mastylo Labs LLC. All rights reserved. No source-code license is granted.
