# scripts/

Operational scripts that produce reproducible artifacts outside of the regular
Maven build.

## NSS toolkit repack (M3.4)

The Autofirma configurator bundles `certutil.<os>.zip` resources to register the
Autofirma trust root in Mozilla NSS profile databases. Until M3.4 (2026-05-07)
those bundles contained NSS binaries from **April 2010** — a 15-year-old SQLite
inside is responsible for the long list of suppressions in
`.dependency-check-suppressions.xml`.

These scripts produce fresh bundles from upstream sources. They are NOT invoked
during `mvn package`; they are release/maintenance tooling. Run them when:

- the bundled NSS is older than ~2 years, or
- a new Autofirma release ships, or
- a downstream CVE in NSS/SQLite is published.

After running, copy the produced `certutil.<os>.zip` into both:

- `afirma-ui-simple-configurator/src/main/resources/<os>/`
- `afirma-simple/src/main/resources/<os>/`

Then commit the new resources and let `mvn -Denv=install verify` validate that
the structure still matches what `ConfiguratorFirefox<Os>.java` expects.

### Linux — `repack-nss-linux.sh`

Produces `certutil.linux.zip` (x86_64) by extracting `libnss3-tools` and the
required runtime libraries from Debian stable via Docker.

```bash
./scripts/repack-nss-linux.sh ./certutil.linux.zip
```

Requires Docker. Output is reproducible (Debian stable is a stable target).
For a Linux ARM64 build, change the `--platform` flag inside the script to
`linux/arm64` and the lib path glob accordingly.

### macOS — `repack-nss-macos.sh`

Produces `certutil.osx.zip` (arm64 native on Apple Silicon, x86_64 on Intel)
by copying the Homebrew-installed NSS binaries and rewriting their dylib install
names so the binary resolves siblings via `@executable_path`.

```bash
./scripts/repack-nss-macos.sh ./certutil.osx.zip
```

Requires Homebrew. The script will run `brew install nss` if needed.
**Native Apple Silicon support — no Rosetta 2 required.**

### Windows — `repack-nss-windows.ps1`

Produces `certutil.windows.zip` by extracting NSS components from a local
Mozilla Firefox installation. **Mozilla does not publish standalone NSS Windows
binaries**, so this is the most practical reproducible source on Windows.

```powershell
.\scripts\repack-nss-windows.ps1
.\scripts\repack-nss-windows.ps1 -FirefoxRoot "C:\Program Files\Mozilla Firefox"
```

Run on a Windows machine (or a Windows runner in CI) with Firefox installed.
The bundled binaries inherit the Authenticode signature of the Firefox install,
which is acceptable for our use because we only invoke `certutil -A` / `-D`
locally on the user's own NSS profile.

For Windows ARM64, install the Firefox ARM64 build first.

## Verification

After regenerating a zip, sanity-check the bundle:

```bash
unzip -l certutil.<os>.zip
file <extracted>/certutil/certutil*    # confirm architecture
```

And run the project tests for the configurator module:

```bash
mvn -B -Denv=install -Ddependency-check.skip=true \
    -pl afirma-ui-simple-configurator -am test -Dtest=TestCertUtil
```
