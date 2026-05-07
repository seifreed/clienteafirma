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
| **M2** | Cadena de suministro CI — GitHub Actions, CodeQL, Renovate, Dependabot | 🟡 Parcial (PR-gate + SAST + Renovate listos; Sigstore/SLSA pendiente) |
| **M3.1** | JDK 8 → JDK 21 LTS sin cambios funcionales | ✅ Completado |
| **M3.2** | `javax.servlet` → `jakarta.servlet` (3 WARs triphase) | ⏳ Pendiente |
| **M3.3** | SpongyCastle 1.58 (2018) → BouncyCastle 1.84+ | ⏳ Pendiente |
| **M3.4** | Repack del toolkit Mozilla NSS embebido (binarios de 2010) | ⏳ Pendiente |
| **M3.5** | Fork de iText 1.7 (2009) → OpenPDF | ⏳ Pendiente |
| **M3.6** | Hardening (Jazzer, PIT) y JUnit 5 | ⏳ Pendiente |
| **M4**  | eIDAS&nbsp;2 / EUDI Wallet — JAdES, TSL/LOTL, OID4VP, SD-JWT | ⏳ Diseño |

### Diferencias principales frente al upstream

| Área | Upstream (1.9.1) | Este fork (1.10-dev) |
| --- | --- | --- |
| Compile target | Java&nbsp;1.8 | **Java&nbsp;21 LTS** (`<release>21</release>`) |
| Cripto provider transitivo | SpongyCastle 1.58.0.0 (2018) | Igual *por ahora*; M3.3 migra a BouncyCastle |
| `xmlsec` (Apache Santuario) | 3.0.5 | **3.0.6** (4.0.x bloqueado por API removal en `XMLSignatureInput(Node)`) |
| `dependency-check-maven` | — | **12.2.2** con `failBuildOnCVSS=7` en `env-deploy` |
| `cyclonedx-maven-plugin` | — | **2.9.1** generando SBOM CycloneDX&nbsp;1.5 por módulo |
| `maven-release-plugin` | 2.5.3 (2015) | **3.3.1** |
| `org.mozilla:rhino-runtime` (transitivo) | 1.7.13 (CVE-2025-66453) | **1.7.15.1** (forzado en `dependencyManagement`) |
| `SECURITY.md`, `CONTRIBUTING.md` | — | Presentes con SLA y matriz de soporte |
| Workflows GitHub Actions | — | `build.yml` (matrix Linux/Win/macOS), `codeql.yml`, `renovate.json`, `dependabot.yml` |
| Windows x86 (32-bit) | Soportado | **Eliminado en 1.10.0** (Adoptium Temurin 21 no se distribuye para x86) |

---

## Soporte de plataformas

| SO | Arquitectura | Estado |
| --- | --- | --- |
| Windows | x64 | ✅ Instalador NSIS + JRE empaquetado |
| Windows | ARM64 | 🟡 Vía emulación Windows-on-ARM x64; instalador nativo pendiente (jpackage) |
| Windows | x86 (32-bit) | ❌ Drop oficial 1.10.0 |
| Linux | x64 | ✅ DEB / RPM, requiere JDK&nbsp;21+ del sistema |
| Linux | ARM64 (aarch64) | ✅ DEB / RPM `noarch`, JDK&nbsp;21 ARM64 + `nss-tools` system |
| macOS | x64 (Intel) | ✅ Pkgproj `Autofirma_Packages_x64` |
| macOS | ARM64 (Apple Silicon) | 🟡 Pkgproj `Autofirma_Packages_aarch64` (`certutil` empaquetado x86_64 → Rosetta 2; nativo en M3.4) |

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

```
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
