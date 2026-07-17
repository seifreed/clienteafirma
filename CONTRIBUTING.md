# Contributing to Autofirma / clienteafirma

Thanks for considering a contribution. This document covers what you need to know to send a useful patch. The authoritative project lives at <https://github.com/ctt-gob-es/clienteafirma>; forks should rebase before opening upstream pull requests.

## Before you open a pull request

1. **Search existing issues and PRs.** Avoid duplicating in-flight work.
2. **For non-trivial changes, open an issue first.** This is a regulated electronic-signature product used by Spanish public administrations. Architectural changes need agreement before code review.
3. **Read `CLAUDE.md`.** It documents build profiles, the triphase architecture, the JDK 21 target, and the Maven module layout. Anything that contradicts those constraints will not merge.
4. **Read `SECURITY.md`.** Vulnerabilities go through the disclosure channel, never through public PRs.

## Development setup

```bash
# Default profile (libraries only, fast feedback)
mvn clean install

# Full set of deliverables (apps, WARs, plugins)
mvn clean install -Denv=install

# Skip tests during exploration
mvn clean install -DskipTests
```

Required toolchain:

- **JDK 21 LTS** on `PATH` / `JAVA_HOME`. The project targets `21` (`<release>21</release>`); modern features are fair game (`var`, records, sealed types, pattern matching, switch expressions, virtual threads, etc.). Migrated from 1.8 on 2026-05-07; pre-existing files still use the JDK 8 idiom — match the surrounding style instead of mass-converting.
- **Maven 3.8+**. The repo has no Gradle wrapper; ignore tooling that assumes Gradle.

Working on a single module:

```bash
mvn -pl afirma-crypto-cades -am clean install
mvn -pl afirma-crypto-cades test -Dtest=TestCAdESCoSigner
mvn -pl afirma-crypto-cades test -Dtest=TestCAdESCoSigner#testCoSignSimple
```

`mvn -pl <module>` only resolves modules listed under the active profile. The default profile (`env-dev`) excludes the application/service/plugin modules; add `-Denv=install` to operate on those.

## Coding conventions

- Match the surrounding file. Existing code uses **tabs** for indentation, **Spanish JavaDoc**, and the `es.gob.afirma.*` package prefix.
- Keep functions small and single-purpose; prefer descriptive names over comments. Only comment non-obvious *why* — hidden constraints, workarounds for known bugs, subtle invariants.
- Trust internal calls between core libraries. Validate at boundaries only — desktop UI input, the `afirma://` protocol handler, and HTTP request bodies in the WARs.
- Domain logic in `afirma-core` and the `afirma-crypto-*` libraries must remain independent of UI (`afirma-ui-*`, `afirma-simple`), HTTP/Servlet code, and installer concerns. Do not let those layers leak inward.
- The SPI modules (`afirma-server-triphase-signer-cache`, `-document`, `afirma-simple-plugins`) exist precisely to keep infrastructure pluggable. Do not bypass them by importing concrete implementations across module boundaries.

## Regression contract

Public APIs (`AOSigner`, `AOSignerFactory`, `TriphaseData`, the `*-tri-client` HTTP contracts, the plugin SPI, the `afirma://` protocol) are **regression contracts**. Any modification:

1. Updates every call site.
2. Adds or updates JUnit 4 tests that lock in the new behaviour.
3. Documents the change in the PR description (what changed, why, who is affected downstream).

Before refactoring, ensure there is JUnit coverage for the current behaviour. If coverage is missing, write a regression test first, then refactor.

## Adding a new module

1. Create the module directory with its own `pom.xml` declaring the parent `es.gob.afirma:afirma-client:<version>`.
2. Register it under **every relevant `<profile><modules>`** block in the root `pom.xml` (typically `env-dev`, `env-install`, `sonar`, `env-deploy`, and `minhap` if applicable). A module that is not listed in the active profile is silently skipped — this is the most common cause of "my module is not built" tickets.
3. Inherit `cyclonedx-maven-plugin` and `dependency-check-maven` from the root configuration; do not redeclare them.

## Quality gates

Every PR must pass these locally before review:

```bash
# Compile + tests
mvn -Denv=install verify

# SBOM generation (CycloneDX 1.5)
mvn -Denv=install package
ls afirma-simple/target/bom.xml afirma-simple/target/bom.json

# Vulnerability scan (report-only at present; will fail builds at CVSS ≥7 in future)
mvn -DnvdApiKey=$NVD_API_KEY org.owasp:dependency-check-maven:aggregate
```

**NVD API key is mandatory** for the vulnerability scan to be usable. Without it, the plugin downloads the National Vulnerability Database from NIST under heavy rate-limiting (potentially hours per first run). Get a free key at <https://nvd.nist.gov/developers/request-an-api-key> (registration takes ~5 minutes). Then either:

- Export `NVD_API_KEY` in your shell and pass it as `-DnvdApiKey=$NVD_API_KEY`, or
- Add it to `~/.m2/settings.xml` under `<profiles><profile><properties><nvdApiKey>...</nvdApiKey></properties></profile></profiles>` (do not commit).

Subsequent runs reuse a 1-week local cache (`<nvdValidForHours>168</nvdValidForHours>`) so they finish in seconds.

In CI, the same key must be provisioned as repository secret **`NVD_API_KEY`** under `Settings → Secrets and variables → Actions`. The `.github/workflows/build.yml` workflow reads it via `${{ secrets.NVD_API_KEY }}`. Without the secret, the dep-check step in CI is rate-limited and may time out.

## CI / Pull request gates

The repository runs the following GitHub Actions workflows automatically:

- **`build.yml`** (PR + push to `master`): compiles the `env-install` profile across `ubuntu-24.04`, `windows-2022`, and `macos-14`; runs JUnit on Linux; uploads CycloneDX SBOMs and the OWASP dep-check report (HTML / JSON / SARIF) as artifacts; submits the SARIF to the repository Security tab.
- **`codeql.yml`** (PR + push to `master` + Mondays 06:00 UTC): SAST analysis with the `security-extended` query suite. Findings appear in the Security tab.
- **`release.yml`** (tag `v*`): builds release assets, signs each asset with keyless Sigstore (`cosign sign-blob`), and attaches SLSA3 provenance for the published hashes.
- **Renovate** (`renovate.json`): opens dependency-update PRs grouped by family (BouncyCastle, jmulticard, Maven plugins, Mozilla Rhino — manual gating, see the file). Schedule: Monday mornings, Europe/Madrid.
- **Dependabot** (`.github/dependabot.yml`): pins GitHub Actions by SHA and updates them weekly.

A PR cannot be merged unless `build`, `tests`, and `analyze (java)` pass green. Branch-protection enforcement is the admin's call (this fork: see repo settings; upstream: see CTT).

Do not bypass failing checks with rule suppressions, `--no-verify`, `-x <task>`, or by editing the gate's configuration to whitelist the offending code. If a check is wrong, fix the check or open a discussion before merging.

## Pull request checklist

- [ ] Linked to an issue (mandatory for non-trivial changes).
- [ ] Tests added or updated for changed behaviour.
- [ ] No new compiler warnings.
- [ ] No new `dependency-check` findings of CVSS ≥ 7 (or a justified suppression added with explanation).
- [ ] Public-API changes documented in the PR description.
- [ ] Regression tests for any change that touches `afirma-crypto-*` signature generation or validation.
- [ ] No credentials, keystores, `.pfx`, or `.p12` files added to the repository.
- [ ] Commit messages in the imperative mood, in Spanish or English, referencing the issue (`#NNN`) when applicable.

## License

By submitting a contribution you agree to license it under both **GPL-2.0-or-later** and **EUPL-1.1**, the dual licence Autofirma is distributed under (see `pom.xml` and `license/`).
