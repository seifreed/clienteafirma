<p align="center">
  <img src="logo_autofirma.png" alt="Logo de la Suite @firma" width="240">
</p>

<h1 align="center">Autofirma — fork de modernización 2026</h1>

<p align="center">
  <strong>Cliente de firma electrónica del Gobierno de España, modernizado para JDK&nbsp;21&nbsp;LTS y conforme al EU Cyber Resilience Act</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/licencia-GPL%202.0%20%2F%20EUPL%201.1-blue?style=flat-square" alt="Licencia GPL/EUPL">
  <img src="https://img.shields.io/badge/JDK-21%20LTS-orange?style=flat-square&logo=openjdk&logoColor=white" alt="JDK 21 LTS">
  <img src="https://img.shields.io/badge/build-Apache%20Maven-c71a36?style=flat-square&logo=apachemaven&logoColor=white" alt="Maven">
  <img src="https://img.shields.io/badge/SBOM-CycloneDX%201.5-darkgreen?style=flat-square" alt="CycloneDX 1.5 SBOM">
  <img src="https://img.shields.io/badge/CRA-trabajo%20en%20curso-yellow?style=flat-square" alt="CRA work in progress">
  <img src="https://img.shields.io/badge/upstream-ctt--gob--es%2Fclienteafirma-blue?style=flat-square&logo=github" alt="Upstream CTT">
</p>

---

## Resumen

**Autofirma** (parte de la Suite **@firma**) es la herramienta oficial de firma electrónica del Gobierno de España, distribuida por la Agencia Estatal de Administración Digital. Funciona como aplicación de escritorio en Windows, Linux y macOS, e integra firma desde navegador mediante el protocolo `afirma://`. Es **software libre** bajo licencia dual **GPL&nbsp;2.0+** y **EUPL&nbsp;1.1**.

Este repositorio es un **fork de modernización** del proyecto oficial:

> Upstream: <https://github.com/ctt-gob-es/clienteafirma>

El upstream se mantiene como referencia de producto. Este fork añade un programa de modernización 2026 estructurado en cuatro hitos secuenciales (M1–M4) cuyo objetivo es:

1. **Cumplir el EU Cyber Resilience Act (CRA)** — obligación efectiva diciembre&nbsp;2027.
2. **Salir de Java&nbsp;8** y adoptar **JDK&nbsp;21&nbsp;LTS** (soporte hasta sept&nbsp;2031).
3. **Interoperar con la EU Digital Identity Wallet** (eIDAS&nbsp;2) cuando los estándares se estabilicen.
4. **Automatizar la cadena de suministro** con CI, SBOM y firmas reproducibles.

El plan completo vive en `~/.claude/plans/` y se referencia desde el código mediante comentarios `M3.x` etc.

### Estado del programa de modernización

| Hito | Tema | Estado |
| --- | --- | --- |
| **M1** | CRA Wave 1 — `SECURITY.md`, SBOM CycloneDX, dependency-check, builds reproducibles | ✅ Completado |
| **M2** | Cadena de suministro CI — GitHub Actions, CodeQL, Renovate, Dependabot | ✅ Completado — PR-gate, SAST, Renovate, Dependabot, Sigstore keyless y provenance SLSA en releases por tag |
| **M3.1** | JDK 8 → JDK 21 LTS sin cambios funcionales | ✅ Completado |
| **M3.2** | `javax.servlet` → `jakarta.servlet` (3 WARs triphase) | ✅ Completado (Tomcat 10.1+ / Jetty 12+; triphase service 3.0.0) |
| **M3.3** | SpongyCastle 1.58 (2018) → BouncyCastle 1.84+ | ✅ Completado |
| **M3.4** | Repack del toolkit Mozilla NSS embebido (binarios de 2010) | 🟡 Linux + macOS hechos (NSS 3.123, **arm64 nativo macOS**); Windows pendiente (requiere host con Firefox) |
| **M3.5** | Fork de iText 1.7 (2009) → OpenPDF | 🔴 **Bloqueado** — `afirma-lib-itext` es un hard fork con parches PAdES propios de la AEAD (`PdfPKCS7.getPkcs1()`, `InvalidPageNumberException`, firmas custom de `createSignature`/`preClose`/`PdfSignature`) que OpenPDF 1.3/2.x/3.x no tiene. Migración requiere portar parches o mantener fork propio (~2-3 semanas dedicadas). |
| **M3.6** | Hardening (Jazzer, PIT, JaCoCo) y JUnit | ✅ Completado — JaCoCo siempre activo; PIT bajo `-Pmutation` con `pitest-junit5-plugin`; Jazzer bajo `-Pfuzz` con 3 harnesses (`DerValue`, `TriphaseData`, `ProtocolUri`); JUnit Platform 6.1.2 + Jupiter + Vintage Engine en classpath de tests (los 146 `Test*.java` JUnit 4 corren sin tocarse, vía Vintage; nuevos tests usan `org.junit.jupiter.api.*` directamente). |
| **M4**  | eIDAS&nbsp;2 / EUDI Wallet — JAdES, TSL/LOTL, OID4VP, SD-JWT | 🟡 Esqueleto fase 2 — `afirma-crypto-jades` (B-B compact + JWS JSON Serialization; JAdES-T JSON con `tsaURL` RFC 3161 o token aportado por el llamador), `afirma-trust-tsl` (parser ETSI TS 119 612 + verificador XMLDSig con clave pinada o certificado `KeyInfo`, loader LOTL HTTPS + cache 24h + `TrustListService`), `afirma-eudiw-bridge` (OID4VP `AuthorizationRequest` con DCQL/JAR/JARM, SD-JWT VC parser/verifier, cliente HTTP), `EudiwProtocolHandler` cableado en `ProtocolInvocationLauncher` con deep-link `walletUri` y POST REST `walletEndpoint`. Política TSA CTT por defecto, JAdES LT/LTA, pin oficial Comisión para LOTL, conformance EU Reference Wallet y coordinación móvil pendientes (TODO M4.x). |

### Diferencias principales frente al upstream

| Área | Upstream (1.9.1) | Este fork (1.10-dev) |
| --- | --- | --- |
| Compile target | Java&nbsp;1.8 | **Java&nbsp;21 LTS** (`<release>21</release>`) |
| Cripto provider | SpongyCastle 1.58.0.0 (2018, sin mantenimiento) | **BouncyCastle 1.85** (`bcprov-jdk18on` + `bcpkix-jdk18on` + `bcutil-jdk18on`); 72 archivos `.java` migrados |
| `xmlsec` (Apache Santuario) | 3.0.5 | **4.0.4** con dereferenciadores migrados a `XMLSignatureNodeInput` |
| `dependency-check-maven` | — | **12.2.2** con `failBuildOnCVSS=7` en `env-deploy` |
| `cyclonedx-maven-plugin` | — | **2.9.2** generando SBOM CycloneDX&nbsp;1.5 por módulo |
| `maven-release-plugin` | 2.5.3 (2015) | **3.3.1** |
| `org.mozilla:rhino-runtime` (transitivo) | 1.7.13 (CVE-2025-66453) | **1.7.15.1** (forzado en `dependencyManagement`) |
| Plataforma de tests | `junit:junit:4.13.2` aislada | **JUnit Platform 6.1.2** (Jupiter + Vintage); JUnit 4 corre vía Vintage sin tocar tests existentes |
| Coverage | — | **JaCoCo 0.8.15** activo siempre; reportes en `<módulo>/target/site/jacoco/` |
| Mutation testing | — | **PIT 1.25.7** + `pitest-junit5-plugin 1.2.3` bajo `-Pmutation` |
| Fuzzing | — | **Jazzer 0.24.0** bajo `-Pfuzz` (módulo `afirma-fuzz`, 3 harnesses) |
| `javax.servlet:servlet-api` (3 WARs) | 2.5 (2007) | **`jakarta.servlet:jakarta.servlet-api:6.1.0`** (target Tomcat 10.1+ / Jetty 12+) |
| `afirma-server-triphase-signer` | 2.9.1 | **3.0.0** (major bump por breaking jakarta) |
| `SECURITY.md`, `CONTRIBUTING.md` | — | Presentes con SLA y matriz de soporte |
| Workflows GitHub Actions | — | `build.yml` (matrix Linux/Win/macOS), `codeql.yml`, `renovate.json`, `dependabot.yml` |
| Windows x86 (32-bit) | Soportado | **Eliminado en 1.10.0** (Adoptium Temurin 21 no se distribuye para x86) |

### Trabajo pendiente

- **M3.4-windows — repack del bundle NSS para Windows.** Ejecutar `scripts/repack-nss-windows.ps1` en un host Windows con Firefox instalado. Eliminará la última supresión activa de `sqlite3.dll` (CVE-2021-36690). Es trabajo de release flow / CI con runner Windows, no se puede hacer desde un host macOS/Linux porque Mozilla no publica binarios standalone de NSS para Windows.
- **M3.5 — fork iText → OpenPDF (bloqueado).** El fork interno `afirma-lib-itext:1.7` (namespace `com.aowagie.*`, ~2009) tiene parches de PAdES específicos de la AEAD que OpenPDF 1.3/2/3 no incorpora: `PdfPKCS7.getPkcs1()` para firma triphase, `InvalidPageNumberException`, sobrecargas de `createSignature(..., char, null, boolean, Calendar)`, `PdfStamper.preClose(HashMap, Calendar, ...)`, constructor extra de `PdfSignature`, etc. Sustituir requiere o portar los parches a OpenPDF (PR aguas arriba) o mantener un fork propio del fork. Estimación 2-3 semanas dedicadas. La sesión 2026-05-07 dejó la coordenada OpenPDF probada en `dependencyManagement` como referencia (revertida ahora a `afirma-lib-itext` para mantener verde).
- **M3.6 — migración progresiva JUnit 4 → Jupiter (no bloqueante).** El JUnit Platform 5.13.2 ya está disponible en el classpath de tests vía `junit-bom` y los 146 `Test*.java` siguen ejecutando sin cambios a través de `junit-vintage-engine`. Cuando se quiera modernizar un test concreto basta con cambiar las imports a `org.junit.jupiter.api.*` y las aserciones a `org.junit.jupiter.api.Assertions.*`. Hecho como prueba de vida en `afirma-core/.../TestBase64.java`. No hay urgencia; convertir cuando se toque cada test por otro motivo.
- **M4 — fase 2 (después de fase 1).** Lo que la sesión 2026-05-07 dejó pendiente:
  - **JAdES T/LT/LTA:** JAdES-T ya puede obtener un token RFC 3161 desde `tsaURL` o serializar en `etsiU` un token aportado por el llamador mediante JWS JSON Serialization flattened. Quedan la política TSA CTT por defecto y la conexión con `afirma-trust-tsl` para LT/LTA.
  - **TSL/LOTL real:** `LotlLoader` ya descarga la LOTL por HTTPS (<https://ec.europa.eu/tools/lotl/eu-lotl.xml>), verifica XMLDSig con clave pública pinada suministrada por el integrador y persiste cache local verificada con fallback si falla la red o llega una descarga no válida. Queda fijar el pin oficial del certificado de firma de la Comisión y la política de distribución/rotación CTT.
  - **OID4VP completo:** perfiles finales de interoperabilidad. DCQL nativo ya sustituye al legacy `presentation_definition_uri` cuando se declara; JAR by value ya genera Request Objects firmados con `iss` y vigencia corta; `response_uri` exige HTTPS y `response_mode` queda limitado a `direct_post`/`direct_post.jwt`; JARM `direct_post.jwt` ya se solicita y valida, incluidos `iss`, `exp`/`nbf`.
  - **SD-JWT VC:** `SdJwtVerifier` ya valida issuer JWT contra TSL, vigencia `exp`/`nbf`, disclosures como arrays JSON referenciados por `_sd`, firma del Holder, `typ`, `iat`, `aud`, `nonce` y `sd_hash` del Key Binding JWT.
  - **Conformance:** suites EU Reference Wallet + eIDAS Test Bench.
  - **Mobile:** `EudiwProtocolHandler` ya permite `walletUri` para deep-link móvil configurable y `walletEndpoint` para entrega REST same-device. Quedan contratos cerrados con `afirma-android` y `afirma-ios` (repos separados en CTT).

---

## Soporte de plataformas

| SO | Arquitectura | Estado |
| --- | --- | --- |
| Windows | x64 | ✅ Instalador NSIS + JRE empaquetado |
| Windows | ARM64 | 🟡 Vía emulación Windows-on-ARM x64; instalador nativo pendiente (jpackage) |
| Windows | x86 (32-bit) | ❌ Drop oficial 1.10.0 |
| Linux | x64 | ✅ DEB / RPM, requiere JDK&nbsp;21+ del sistema |
| Linux | ARM64 (aarch64) | ✅ DEB / RPM `noarch`, JDK&nbsp;21 ARM64; bundled certutil ahora x86_64 ELF (M3.4), funciona vía qemu-user en runtime ARM o usa `nss-tools` system como fallback (`ConfiguratorFirefoxLinux.java`) |
| macOS | x64 (Intel) | ✅ Pkgproj `Autofirma_Packages_x64` |
| macOS | ARM64 (Apple Silicon) | ✅ Pkgproj `Autofirma_Packages_aarch64` + `certutil` Mach-O arm64 nativo (M3.4) — Rosetta 2 ya no requerida |

---

## Construcción

### Requisitos

- **JDK 21 LTS** (Adoptium Temurin recomendado) en `PATH` / `JAVA_HOME`.
- **Apache Maven 3.9+**.
- Para `dependency-check`: clave gratuita de la **NVD** en <https://nvd.nist.gov/developers/request-an-api-key>, exportada como `NVD_API_KEY`.

### Comandos comunes

```bash
# Perfil por defecto (env-dev): librerías core, ~32 módulos
mvn clean install

# Aplicaciones, plugins y servicios (Autofirma.jar, configurador, 3 WARs)
mvn -Denv=install clean install

# Saltar tests
mvn clean install -DskipTests

# Despliegue en Maven Central (firma GPG + sources + javadoc + cosign)
mvn -Denv=deploy clean deploy

# Sólo el SBOM de un módulo
mvn -pl afirma-simple org.cyclonedx:cyclonedx-maven-plugin:makeBom

# Sólo el escaneo de vulnerabilidades
mvn -DnvdApiKey="$NVD_API_KEY" org.owasp:dependency-check-maven:aggregate

# Lint baseline (modo solo-reporte; ver tabla "Roadmap gates" en CLAUDE.md)
mvn -Plint-report verify           # Checkstyle → target/checkstyle-result.xml
mvn spotless:check                 # Formato (ad-hoc, no rompe build)
mvn pmd:pmd                        # PMD (ad-hoc; requiere JDK 21)
mvn spotbugs:spotbugs              # SpotBugs (ad-hoc; requiere JDK 21)
```

### Trabajar en un solo módulo

```bash
mvn -pl afirma-crypto-cades -am clean install
mvn -pl afirma-crypto-cades test -Dtest=TestCAdESCoSigner
mvn -pl afirma-crypto-cades test -Dtest=TestCAdESCoSigner#testCoSignSimple
```

`mvn -pl <módulo>` solo resuelve módulos listados bajo el perfil activo. El default (`env-dev`) excluye apps/servicios; añade `-Denv=install` para llegar a ellos.

### Perfiles Maven

| Perfil | Activación | Para qué |
| --- | --- | --- |
| `env-dev` (default) | Activo por defecto | Librerías core, crypto, keystores |
| `env-install` | `-Denv=install` | Lo anterior **+** `afirma-simple`, configurador, plugins, 3 WARs |
| `autofirma` | `-Pautofirma` | Sólo la app desktop + UI |
| `sonar` | `-Psonar` | Análisis SonarQube |
| `minhap` | `-Pminhap` | Despliegue al repo interno SCAE / redsara |
| `env-deploy` | `-Denv=deploy` | Maven Central: source jar, javadoc, GPG + cosign, dep-check con `failBuildOnCVSS=7` |
| `mutation` | `-Pmutation,env-dev` | Mutation testing con PIT 1.20 (M3.6). Reportes en `<módulo>/target/pit-reports/index.html`. |
| `fuzz` | `-Pfuzz` | Añade el módulo `afirma-fuzz` con harnesses Jazzer (M3.6). |

### Calidad — gates M3.6 (mutation, fuzz, coverage)

```bash
# Coverage JaCoCo (siempre activo; reporte en cada módulo)
mvn -pl afirma-core verify
open afirma-core/target/site/jacoco/index.html

# Mutation testing — un módulo a la vez (PIT crea minion JVMs por test)
mvn -P mutation,env-dev -pl afirma-crypto-cades test
open afirma-crypto-cades/target/pit-reports/index.html

# Fuzzing — script wrapper, usa libFuzzer interno de Jazzer
scripts/run-fuzz.sh DerValueFuzzer 60       # 60 segundos sobre el parser DER
scripts/run-fuzz.sh TriphaseDataFuzzer 300  # 5 minutos sobre TriphaseData.parser(byte[])
scripts/run-fuzz.sh ProtocolUriFuzzer 300   # 5 minutos sobre afirma:// URI handler
# Crashes y reproducers caen en afirma-fuzz/target/fuzz/<harness>/crashes/
```

> **Nota:** la gate `jacoco:check` (umbral mínimo) está intencionalmente sin
> bindear hasta medir baseline por módulo (follow-up M3.6). PIT y Jazzer son
> suplementarios — útiles ad-hoc, no bloquean PRs en CI hasta que los corpus
> de fuzz estén estables.

---

## Calidad y supply chain (M1 + M2)

### Gates locales

```bash
# Build estricto + tests
mvn -Denv=install clean verify

# SBOM CycloneDX 1.5 (raíz + cada módulo)
ls **/target/bom.{xml,json}

# CVEs (con clave NVD)
mvn -DnvdApiKey="$NVD_API_KEY" -Denv=install org.owasp:dependency-check-maven:aggregate

# Build reproducible (timestamp determinista)
mvn -Denv=install package -DoutputTimestamp=2026-05-07T00:00:00Z
```

### Gates en CI (GitHub Actions)

| Workflow | Trigger | Qué hace |
| --- | --- | --- |
| `.github/workflows/build.yml` | PR + push a `master` | Matrix Linux/Win/macOS · JDK&nbsp;21 · `mvn -Denv=install verify` · sube SBOMs y `dependency-check-report.{html,json,sarif}` como artifacts · empuja SARIF a la pestaña Security |
| `.github/workflows/codeql.yml` | PR + push + lunes 06:00&nbsp;UTC | SAST con `security-extended` |
| `.github/workflows/release.yml` | Push de tag `v*` | Construye deliverables · firma assets con Sigstore keyless (`cosign sign-blob`) · adjunta provenance SLSA3 para los hashes publicados |
| `renovate.json` | Lunes 8:00 Madrid | PRs agrupados por familia (BC, jmulticard, plugins, Rhino con gating manual) |
| `.github/dependabot.yml` | Semanal | Sólo `github-actions` con pin por SHA |

### Política de severidades CVE

| CVSS 3.1 | Acción |
| --- | --- |
| 9.0–10.0 (Critical) | Parche fuera de ciclo; advisory en 7&nbsp;días |
| 7.0–8.9 (High) | Bloquea `env-deploy` (`failBuildOnCVSS=7`); parche en próximo minor |
| 4.0–6.9 (Medium) | Issue automática, SLA 30&nbsp;días |
| 0.1–3.9 (Low) | Documentado en notas de release |

Las supresiones aceptadas con justificación viven en `.dependency-check-suppressions.xml`. Cada entrada incluye razonamiento de reachability, tracking y caducidad.

---

## Arquitectura — visión general

El proyecto es una pila de tres capas:

1. **Librerías core / criptográficas** (`afirma-core`, `afirma-crypto-*`, `afirma-keystores-*`)
   - Tipos cross-cutting: `AOSigner`, `AOSignerFactory`, `AOSignConstants`, `TriphaseData`.
   - Una librería por formato: CAdES, CMS, XAdES, XMLdSig, PAdES, ODF, OOXML, FacturaE.
   - Clientes triphase (`*-tri-client`) para invocar firma trifásica en servidor.
2. **Servicios server / triphase** (`afirma-server-triphase-signer*`, `afirma-signature-retriever`, `afirma-signature-storage`)
   - Procesadores específicos por formato bajo `es.gob.afirma.triphase.signer`.
   - SPI para cache (`-cache`) y persistencia de documentos (`-document`).
   - WARs Servlet para Tomcat / Jetty.
3. **Aplicación desktop + plugins** (`afirma-simple`, `afirma-ui-*`, `afirma-simple-plugin-*`, `afirma-simple-installer`)
   - Swing app + protocolo `afirma://` / `afirma-batch://`.
   - Plugins instalables (hash, validatecerts).
   - Instaladores NSIS/MSI (Windows), DEB/RPM (Linux), pkg (macOS).

### Firma trifásica

1. **Pre-firma**: el servidor lee el documento, prepara la estructura y devuelve los bytes a firmar + un `TriphaseData`.
2. **Firma PKCS#1**: el cliente realiza la operación con la clave privada localmente (la clave nunca sale del dispositivo).
3. **Post-firma**: el servidor combina el PKCS#1 en el documento final.

Cualquier cambio en `TriphaseData`, los `*-tri-client` o `afirma-server-triphase-signer-core` debe respetar el contrato bilateral.

---

## Familias de firma soportadas

```text
Sobres CAdES        CAdES, ASiC-CAdES, cofirmas, contrafirmas
Sobres XAdES        XAdES, ASiC-XAdES, FacturaE
Sobres XMLDSig      XMLdSig (sin atributos AdES)
PDF                 PAdES (firma visible / invisible / campos)
Office              ODF, OOXML
PKCS#7              CMS, sobres digitales
```

---

## Reportar vulnerabilidades

No abras issues públicas para reportes de seguridad. Sigue el proceso descrito en [`SECURITY.md`](SECURITY.md): canal preferente <soporte.afirma@correo.gob.es> (cifrado PGP recomendado), o el reporte privado de GitHub en el upstream.

SLA de triaje: 5 días hábiles. Embargo coordinado por defecto: 90 días.

---

## Contribuir

- Lee [`CONTRIBUTING.md`](CONTRIBUTING.md) antes de abrir un PR.
- Estilo: tabulaciones, JavaDoc en español, prefijo `es.gob.afirma.*`.
- Contratos de regresión sobre APIs públicas (`AOSigner`, `TriphaseData`, `*-tri-client`, plugin SPI, protocolo `afirma://`) — toda modificación requiere actualizar tests y describir el impacto downstream.
- Compatible con Java&nbsp;21 (records, `var`, virtual threads, etc. son aceptables, pero respeta el estilo del archivo que tocas).

Para proponer cambios al producto oficial, abre PR contra <https://github.com/ctt-gob-es/clienteafirma>. Este fork existe para experimentar con la modernización; lo que demuestre valor se propone aguas arriba.

---

## Licencia

Distribuido bajo doble licencia:

- **GPL-2.0-or-later** — <http://www.gnu.org/licenses/gpl-2.0.txt>
- **EUPL-1.1** — <http://joinup.ec.europa.eu/system/files/ES/EUPL%20v.1.1%20-%20Licencia.pdf>

Las dependencias de terceros y sus licencias están trazadas en `license/`.

---

## Créditos

- **Producto original**: Agencia Estatal de Administración Digital (AEAD) / Centro de Transferencia de Tecnología (CTT) del Gobierno de España.
- **Repositorio oficial**: <https://github.com/ctt-gob-es/clienteafirma>.
- **Documentación**: <https://administracionelectronica.gob.es/ctt/clienteafirma>.

Más información sobre la Suite @firma en la [forja del CTT](https://github.com/ctt-gob-es/).
