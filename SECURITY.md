# Security Policy

This document describes how to report vulnerabilities affecting Autofirma (Cliente @firma) and the security commitments of the project. It is published in compliance with the spirit of the [EU Cyber Resilience Act (Regulation (EU) 2024/2847)](https://eur-lex.europa.eu/eli/reg/2024/2847) and [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).

> **Note:** This file is a working draft. The upstream maintainer (Agencia Estatal de Administración Digital, AEAD / Centro de Transferencia de Tecnología) is the entity that ratifies the contact addresses, PGP fingerprints, SLAs, and supported-version commitments below. Any deviations between this document and an official upstream policy at <https://administracionelectronica.gob.es/ctt/clienteafirma> take effect in favour of the upstream document.

## Reporting a vulnerability

**Do not open public GitHub issues for security reports.** Use one of the channels below in this preference order:

1. **Email**: `soporte.afirma@correo.gob.es` (the support address listed in `pom.xml`). Encrypt the message with the project's PGP key when handling sensitive details (key fingerprint published at the AEAD support portal; if no fingerprint is yet published, request one via the same address before sending exploit details).
2. **GitHub private vulnerability reporting**: at <https://github.com/ctt-gob-es/clienteafirma/security/advisories/new> (only effective on the upstream repository, not on forks).
3. **CSIRT-AAPP / CCN-CERT** (Spanish public-sector CSIRT) for incidents already in active exploitation: <https://www.ccn-cert.cni.es/>.

Please include:

- The affected version (see `version` in `pom.xml`; current is **1.9.1** for the client / **2.9.1** for the triphase service).
- Reproduction steps, ideally a minimal proof-of-concept.
- The platforms tested (Windows / macOS / Linux, JDK version, browser if the `afirma://` protocol handler is involved).
- Whether the issue affects the desktop client, one of the WAR services (`afirma-server-triphase-signer`, `afirma-signature-retriever`, `afirma-signature-storage`), one of the published Maven artifacts, or the bundled plugins.
- Your contact preference and any disclosure timeline you propose.

## Service level

| Stage | Target | Notes |
|---|---|---|
| Acknowledgement of receipt | 5 business days | Auto-reply confirmation does not count. |
| Initial triage and severity assessment | 10 business days | CVSS 3.1 base score assigned. |
| Patch / mitigation availability | Per CVSS severity (see below) | From triage close, not from initial report. |
| Public advisory and CVE | Coordinated with reporter | Default 90-day embargo, extendable on request. |

### Severity-driven patching SLA

| CVSS 3.1 base score | Action |
|---|---|
| 9.0 – 10.0 (Critical) | Out-of-band patch; advisory within 7 days of fix. |
| 7.0 – 8.9 (High) | Patch in next minor release; mitigation guidance shipped immediately. Build is **blocked** in CI when a dependency reaches this severity (see "Supported configurations" below). |
| 4.0 – 6.9 (Medium) | Patch in next scheduled release. Tracking issue opened automatically. |
| 0.1 – 3.9 (Low) | Documented in release notes; fixed at maintainer's discretion. |

## Supported configurations

| Component | Supported versions | End of security support |
|---|---|---|
| `afirma-simple` (Autofirma desktop) | Latest minor only (1.10.x) | When the next minor lands and after a 90-day overlap. |
| `afirma-server-triphase-signer` | Latest minor only (3.0.x) — **Jakarta EE 9+ / Servlet 6.0**, requires Tomcat 10.1+ / Jetty 12+ | Same as desktop. |
| `afirma-signature-retriever` / `afirma-signature-storage` | Latest minor only — also Jakarta EE 9+ as of 1.10.0 | Same as desktop. |
| Published Maven artifacts (`es.gob.afirma:*`) | Latest minor only | Pinned by the same lifecycle. |
| `afirma-server-triphase-signer 2.9.x` (servlet 2.5 / Tomcat 9) | **Not supported as of 1.10.0.** | Tomcat 9 is in maintenance-only mode upstream and does not load Jakarta EE 9 WARs. |
| Older majors (1.9.x, 1.8.x, …) | **Not supported.** | Already past EoL. |

The current Java target is **JDK 21 LTS** (migrated from 1.8 on 2026-05-07). Security commitments apply to running on the most recent **Adoptium Temurin 21** maintenance release. Older builds packaged for JDK 8 are not security-supported.

### Platform support matrix

| OS | Architecture | Status |
|---|---|---|
| Windows | x64 | **Supported** (native installer + JRE bundle) |
| Windows | ARM64 | Supported via Windows-on-ARM x64 emulation; native installer pending |
| Windows | x86 (32-bit) | **Dropped in 1.10.0** — Adoptium Temurin 21 does not ship x86 builds |
| Linux | x64 | Supported (DEB / RPM, system JDK 21+) |
| Linux | ARM64 (aarch64) | Supported (DEB / RPM, system JDK 21+); bundled certutil falls back to system `nss-tools` |
| macOS | x64 (Intel) | Supported |
| macOS | ARM64 (Apple Silicon) | Supported, bundled certutil now Mach-O arm64 native (M3.4, NSS 3.123 from Homebrew) — Rosetta 2 no longer required |

## Compromised material in this repository

The following secrets are present in `git` history and **must be considered compromised**:

- `afirma-simple/afirma.keystore` — JKS keystore used to sign Autofirma JARs. Alias `codesign`, password `afirma` (visible in `pom.xml`).
- `afirma-simple-installer/Autofirma_sign.pfx` — PFX used by `signtool` to sign the Windows `.exe` / `.msi` installers, with the password embedded in `Autofirma_sign_*.bat`.

If you are a downstream consumer pinning a specific Autofirma version, validate the published artifacts against the GPG signatures attached to Maven Central (the GPG signing key is separate from the keystores above) and against the SBOM (CycloneDX) attached to each release. Request rotation of the keystores from the upstream maintainer if you depend on installer signatures for trust decisions.

Future releases will:

1. Rotate both signing keys.
2. Provision them only via CI secrets, never in the repository.
3. Sign artifacts with **Sigstore cosign** (keyless, OIDC) in addition to GPG, so that signatures are independently verifiable against the GitHub Actions OIDC issuer.

## Coordinated disclosure

We follow [ISO/IEC 29147](https://www.iso.org/standard/72311.html) and request a default **90-day** embargo from the date of the initial report. Extensions are negotiated per-case. We credit reporters by name and affiliation in the advisory unless they request anonymity. We will request a CVE through MITRE / the GitHub CNA and add it to the advisory.

## Build integrity and supply chain

Each release ships:

- A **CycloneDX 1.5 SBOM** (`bom.xml` + `bom.json`) generated by `cyclonedx-maven-plugin` and attached to the release.
- A **dependency-check** report listing known CVEs at build time.
- GPG signatures on Maven Central artifacts (legacy).
- Sigstore cosign signatures and SLSA provenance attestations on GitHub releases (planned; see roadmap milestone "Supply chain CI hardening").

To verify a release locally:

```bash
# SBOM is attached to the release as bom.xml / bom.json
sha256sum -c bom.json.sha256
# Sigstore verification (once releases ship cosign signatures)
cosign verify-blob \
    --certificate-identity-regexp "https://github.com/ctt-gob-es/clienteafirma/.*" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --signature bom.json.sig bom.json
```

## Hall of fame

Reporters who help improve Autofirma will be credited here unless they prefer to remain anonymous.

_(empty so far)_
