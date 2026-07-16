/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Pruebas del parser TSL sobre un fixture mínimo embebido. */
final class TestTslParser {

	private static final String MINI_TSL = """
		<?xml version="1.0" encoding="UTF-8"?>
		<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
		  <SchemeInformation>
		    <SchemeOperatorName>
		      <Name>Ministerio de Asuntos Económicos y Transformación Digital</Name>
		    </SchemeOperatorName>
		    <SchemeTerritory>ES</SchemeTerritory>
		    <NextUpdate>
		      <dateTime>2026-12-31T23:59:59Z</dateTime>
		    </NextUpdate>
		  </SchemeInformation>
		  <TrustServiceProviderList>
		    <TrustServiceProvider>
		      <TSPInformation>
		        <Name>FNMT-RCM</Name>
		        <TradeName>FNMT-RCM</TradeName>
		        <PostalCode>ES</PostalCode>
		      </TSPInformation>
		      <TSPServices>
		        <TSPService>
		          <ServiceInformation>
		            <ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier>
		            <ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus>
		          </ServiceInformation>
		        </TSPService>
		      </TSPServices>
		    </TrustServiceProvider>
		  </TrustServiceProviderList>
		</TrustServiceStatusList>
		""";

	@Test
	@DisplayName("Parser extrae territorio, operador, NextUpdate y TSPs sin errores")
	void parsesMinimalTsl() throws TslException {
		final TslParser parser = new TslParser();
		final TslDocument tsl = parser.parse(MINI_TSL.getBytes(StandardCharsets.UTF_8));

		assertEquals("ES", tsl.territory());
		assertTrue(tsl.schemeOperatorName().contains("Ministerio"));
		assertEquals(1, tsl.providers().size());
		assertFalse(tsl.signed(), "Fixture sin firma — TslDocument.signed() debe ser false");

		final TrustServiceProvider tsp = tsl.providers().get(0);
		assertEquals("FNMT-RCM", tsp.name());
		assertEquals("ES", tsp.countryCode(), "El countryCode del TSP debe heredar del SchemeTerritory");
		assertEquals(1, tsp.services().size());

		final TrustServiceProvider.TrustService svc = tsp.services().get(0);
		assertTrue(svc.isGranted(), "El servicio debería estar 'granted'");
		assertTrue(svc.typeIdentifier().endsWith("CA/QC"));
	}

	@Test
	@DisplayName("TrustListService.findIssuer devuelve empty si la TSL no se ha cargado")
	void emptyServiceReturnsNothing() {
		final TrustListService svc = new TrustListService();
		assertEquals(0, svc.loadedCount());
		assertTrue(svc.findIssuer(null).isEmpty());
		assertThrows(IllegalArgumentException.class, () -> svc.get(null));
		assertThrows(IllegalArgumentException.class, () -> svc.get(" ")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> svc.get(" ES")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new TslDocument(" ", "ES", null, List.of(), false)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TslDocument("Operator", " ", null, List.of(), false)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TslDocument(" Operator", "ES", null, List.of(), false)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TslDocument("Operator", " ES", null, List.of(), false)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TslDocument("Operator", "ESP", null, List.of(), false)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TslDocument("Operator", "es", null, List.of(), false)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TrustServiceProvider(" ", null, "ES", List.of())); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TrustServiceProvider("TSP", null, " ", List.of())); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TrustServiceProvider("TSP", null, " ES", List.of())); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TrustServiceProvider("TSP", null, "ESP", List.of())); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TrustServiceProvider("TSP", null, "es", List.of())); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TrustServiceProvider.TrustService(" ", "granted", List.of())); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TrustServiceProvider.TrustService("type", " ", List.of())); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TrustServiceProvider.TrustService(" type", "granted", List.of())); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new TrustServiceProvider.TrustService("type", " granted", List.of())); //$NON-NLS-1$ //$NON-NLS-2$
		assertFalse(new TrustServiceProvider.TrustService(
				"type", "https://example.invalid/status/granted", List.of()).isGranted()); //$NON-NLS-1$ //$NON-NLS-2$
	}

	@Test
	@DisplayName("TrustListService refresca la TSL solo al caducar la cache")
	void getOrRefreshUsesTwentyFourHourCache() throws Exception {
		final TslDocument es = new TslDocument("Operator", "ES", null, List.of(), false);
		final AtomicInteger loads = new AtomicInteger();
		final TrustListService fresh = new TrustListService(
				Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC),
				Duration.ofHours(24));
		assertThrows(NullPointerException.class, () -> fresh.getOrRefresh("ES", null)); //$NON-NLS-1$

		assertEquals(es, fresh.getOrRefresh("ES", () -> {
			loads.incrementAndGet();
			return es;
		}));
		assertEquals(es, fresh.getOrRefresh("ES", () -> {
			loads.incrementAndGet();
			return es;
		}));
		assertEquals(1, loads.get(), "La cache fresca no debe recargar");

		final TrustListService expired = new TrustListService(
				Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC),
				Duration.ZERO);
		assertEquals(es, expired.getOrRefresh("ES", () -> es));
		assertThrows(TslException.class,
				() -> expired.getOrRefresh("ES",
						() -> new TslDocument("Operator", "FR", null, List.of(), false)));

		final AtomicInteger nextUpdateLoads = new AtomicInteger();
		final MutableClock nextUpdateClock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
		final TrustListService nextUpdateExpired = new TrustListService(
				nextUpdateClock,
				Duration.ofHours(24));
		final TslDocument oldNextUpdate = new TslDocument("Operator", "ES", //$NON-NLS-1$ //$NON-NLS-2$
				Instant.parse("2026-01-01T23:59:59Z"), List.of(), false);
		nextUpdateExpired.ingest(oldNextUpdate);
		nextUpdateClock.now = Instant.parse("2026-01-02T00:00:00Z"); //$NON-NLS-1$
		nextUpdateExpired.getOrRefresh("ES", () -> { //$NON-NLS-1$
			nextUpdateLoads.incrementAndGet();
			return es;
		});
		assertEquals(1, nextUpdateLoads.get(), "NextUpdate caducado debe forzar recarga"); //$NON-NLS-1$
		final TrustListService rejectsExpiredLoad = new TrustListService(
				Clock.fixed(Instant.parse("2026-01-02T00:00:00Z"), ZoneOffset.UTC),
				Duration.ZERO);
		assertThrows(TslException.class, () -> rejectsExpiredLoad.getOrRefresh("ES", //$NON-NLS-1$
				() -> new TslDocument("Operator", "ES", //$NON-NLS-1$ //$NON-NLS-2$
						Instant.parse("2026-01-01T23:59:59Z"), List.of(), false)));
		assertThrows(IllegalArgumentException.class, () -> rejectsExpiredLoad.ingest(
				new TslDocument("Operator", "ES", //$NON-NLS-1$ //$NON-NLS-2$
						Instant.parse("2026-01-01T23:59:59Z"), List.of(), false)));
	}

	@Test
	@DisplayName("Parser rechaza entradas vacías")
	void rejectsEmpty() {
		final TslParser parser = new TslParser();
		assertThrows(TslException.class, () -> parser.parse(new byte[0]));
		assertThrows(TslException.class, () -> parser.parse(null));
		assertThrows(TslException.class, () -> parser.parse("""
			<?xml version="1.0" encoding="UTF-8"?>
			<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
			  <SchemeInformation>
			    <SchemeOperatorName><Name>Operator</Name></SchemeOperatorName>
			  </SchemeInformation>
			</TrustServiceStatusList>
			""".getBytes(StandardCharsets.UTF_8)));
		assertThrows(TslException.class, () -> parser.parse("""
			<?xml version="1.0" encoding="UTF-8"?>
			<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
			  <SchemeInformation>
			    <SchemeTerritory>ES</SchemeTerritory>
			  </SchemeInformation>
			  <TrustServiceProviderList>
			    <TrustServiceProvider>
			      <TSPInformation><Name>FNMT-RCM</Name></TSPInformation>
			    </TrustServiceProvider>
			  </TrustServiceProviderList>
			</TrustServiceStatusList>
			""".getBytes(StandardCharsets.UTF_8)));
		assertThrows(TslException.class, () -> parser.parse(
				MINI_TSL.replace("<Name>FNMT-RCM</Name>", "").getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(TslException.class, () -> parser.parse(
				MINI_TSL.replaceAll("(?s)<TSPService>.*?</TSPService>", "") //$NON-NLS-1$ //$NON-NLS-2$
						.getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	@DisplayName("findIssuer resuelve un certificado a su TSP verificando la clave issuer")
	void findIssuerByIssuerSubject() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		final KeyPair caKp = kpg.generateKeyPair();
		final X509Certificate caCert = selfSigned(caKp, "CN=CA Test, O=AEAD");

		// Cert hijo emitido por la "CA": issuer = subject del CA cert
		final KeyPair leafKp = kpg.generateKeyPair();
		final X509Certificate leaf = issuedBy(caKp, caCert, leafKp,
				"CN=Suscriptor, O=Prueba");

		final TrustServiceProvider tsp = new TrustServiceProvider(
				"FNMT-RCM", "FNMT-RCM", "ES",
				List.of(new TrustServiceProvider.TrustService(
						"http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
						"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
						List.of(caCert))));
		final TslDocument tsl = new TslDocument(
				"Operator", "ES", null, List.of(tsp), false);

		final TrustListService svc = new TrustListService();
		svc.ingest(tsl);
		assertEquals(1, svc.loadedCount());
		assertTrue(svc.findIssuer(leaf).isPresent(), "Debe resolver leaf → TSP por issuer DN y firma");
		assertEquals("FNMT-RCM", svc.findIssuer(leaf).get().name());
	}

	@Test
	@DisplayName("findIssuer rechaza un issuer con el mismo DN pero distinta clave")
	void findIssuerRejectsSameSubjectDifferentKey() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final KeyPair trustedCaKp = kpg.generateKeyPair();
		final X509Certificate trustedCa = selfSigned(trustedCaKp, "CN=CA Test, O=AEAD"); //$NON-NLS-1$
		final KeyPair otherCaKp = kpg.generateKeyPair();
		final X509Certificate otherCa = selfSigned(otherCaKp, "CN=CA Test, O=AEAD"); //$NON-NLS-1$
		final X509Certificate leaf = issuedBy(otherCaKp, otherCa, kpg.generateKeyPair(),
				"CN=Suscriptor, O=Prueba"); //$NON-NLS-1$

		final TrustServiceProvider tsp = new TrustServiceProvider(
				"FNMT-RCM", "FNMT-RCM", "ES", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				List.of(new TrustServiceProvider.TrustService(
						"http://uri.etsi.org/TrstSvc/Svctype/CA/QC", //$NON-NLS-1$
						"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted", //$NON-NLS-1$
						List.of(trustedCa))));
		final TrustListService svc = new TrustListService();
		svc.ingest(new TslDocument("Operator", "ES", null, List.of(tsp), false)); //$NON-NLS-1$ //$NON-NLS-2$

		assertTrue(svc.findIssuer(leaf).isEmpty());
	}

	@Test
	@DisplayName("findIssuer ignora servicios TSL no granted")
	void findIssuerIgnoresNonGrantedServices() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final KeyPair caKp = kpg.generateKeyPair();
		final X509Certificate caCert = selfSigned(caKp, "CN=CA Test, O=AEAD"); //$NON-NLS-1$
		final X509Certificate leaf = issuedBy(caKp, caCert, kpg.generateKeyPair(),
				"CN=Suscriptor, O=Prueba"); //$NON-NLS-1$
		final TrustServiceProvider tsp = new TrustServiceProvider(
				"FNMT-RCM", "FNMT-RCM", "ES", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				List.of(new TrustServiceProvider.TrustService(
						"http://uri.etsi.org/TrstSvc/Svctype/CA/QC", //$NON-NLS-1$
						"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/notgranted", //$NON-NLS-1$
						List.of(caCert))));
		final TrustListService svc = new TrustListService();
		svc.ingest(new TslDocument("Operator", "ES", null, List.of(tsp), false)); //$NON-NLS-1$ //$NON-NLS-2$

		assertTrue(svc.findIssuer(leaf).isEmpty());
	}

	@Test
	@DisplayName("findIssuer ignora servicios concedidos que no emiten certificados")
	void findIssuerIgnoresNonCaServices() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final KeyPair caKp = kpg.generateKeyPair();
		final X509Certificate caCert = selfSigned(caKp, "CN=CA Test, O=AEAD"); //$NON-NLS-1$
		final X509Certificate leaf = issuedBy(caKp, caCert, kpg.generateKeyPair(),
				"CN=Suscriptor, O=Prueba"); //$NON-NLS-1$
		final TrustServiceProvider tsp = new TrustServiceProvider(
				"FNMT-RCM", "FNMT-RCM", "ES", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				List.of(new TrustServiceProvider.TrustService(
						"http://uri.etsi.org/TrstSvc/Svctype/TSA", //$NON-NLS-1$
						"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted", //$NON-NLS-1$
						List.of(caCert))));
		final TrustListService svc = new TrustListService();
		svc.ingest(new TslDocument("Operator", "ES", null, List.of(tsp), false)); //$NON-NLS-1$ //$NON-NLS-2$

		assertTrue(svc.findIssuer(leaf).isEmpty());
	}

	@Test
	@DisplayName("findIssuer ignora identidades de servicio caducadas")
	void findIssuerIgnoresExpiredServiceIdentities() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final KeyPair caKp = kpg.generateKeyPair();
		final Instant expired = Instant.now().minus(Duration.ofDays(2));
		final X509Certificate caCert = selfSigned(caKp, "CN=CA Test, O=AEAD", //$NON-NLS-1$
				expired, expired.plus(Duration.ofDays(1)));
		final X509Certificate leaf = issuedBy(caKp, caCert, kpg.generateKeyPair(),
				"CN=Suscriptor, O=Prueba"); //$NON-NLS-1$
		final TrustServiceProvider tsp = new TrustServiceProvider(
				"FNMT-RCM", "FNMT-RCM", "ES", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				List.of(new TrustServiceProvider.TrustService(
						"http://uri.etsi.org/TrstSvc/Svctype/CA/QC", //$NON-NLS-1$
						"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted", //$NON-NLS-1$
						List.of(caCert))));
		final TrustListService svc = new TrustListService();
		svc.ingest(new TslDocument("Operator", "ES", null, List.of(tsp), false)); //$NON-NLS-1$ //$NON-NLS-2$

		assertTrue(svc.findIssuer(leaf).isEmpty());
	}

	@Test
	@DisplayName("findIssuer ignora certificados consultados caducados")
	void findIssuerIgnoresExpiredLeafCertificates() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final KeyPair caKp = kpg.generateKeyPair();
		final X509Certificate caCert = selfSigned(caKp, "CN=CA Test, O=AEAD"); //$NON-NLS-1$
		final Instant expired = Instant.now().minus(Duration.ofDays(2));
		final X509Certificate leaf = issuedBy(caKp, caCert, kpg.generateKeyPair(),
				"CN=Suscriptor, O=Prueba", expired, expired.plus(Duration.ofDays(1))); //$NON-NLS-1$
		final TrustServiceProvider tsp = new TrustServiceProvider(
				"FNMT-RCM", "FNMT-RCM", "ES", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				List.of(new TrustServiceProvider.TrustService(
						"http://uri.etsi.org/TrstSvc/Svctype/CA/QC", //$NON-NLS-1$
						"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted", //$NON-NLS-1$
						List.of(caCert))));
		final TrustListService svc = new TrustListService();
		svc.ingest(new TslDocument("Operator", "ES", null, List.of(tsp), false)); //$NON-NLS-1$ //$NON-NLS-2$

		assertTrue(svc.findIssuer(leaf).isEmpty());
	}

	@Test
	@DisplayName("Parser endurecido contra DOCTYPE (XXE)")
	void rejectsDoctype() {
		final String xxe = """
			<?xml version="1.0"?>
			<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
			<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"/>
			""";
		final TslParser parser = new TslParser();
		assertThrows(TslException.class,
				() -> parser.parse(xxe.getBytes(StandardCharsets.UTF_8)));
	}

	private static X509Certificate selfSigned(final KeyPair kp, final String subject) throws Exception {
		final Instant now = Instant.now();
		return selfSigned(kp, subject, now, now.plus(Duration.ofDays(365)));
	}

	private static X509Certificate selfSigned(final KeyPair kp, final String subject,
			final Instant notBefore, final Instant notAfter) throws Exception {
		final X500Name dn = new X500Name(subject);
		final BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		final X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
				dn, serial, Date.from(notBefore), Date.from(notAfter),
				dn, kp.getPublic())
				.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()));
		return (X509Certificate) CertificateFactory.getInstance("X.509")
				.generateCertificate(new java.io.ByteArrayInputStream(holder.getEncoded()));
	}

	private static X509Certificate issuedBy(final KeyPair issuerKp, final X509Certificate issuerCert,
			final KeyPair subjectKp, final String subjectDn) throws Exception {
		final Instant now = Instant.now();
		return issuedBy(issuerKp, issuerCert, subjectKp, subjectDn,
				now, now.plus(Duration.ofDays(365)));
	}

	private static X509Certificate issuedBy(final KeyPair issuerKp, final X509Certificate issuerCert,
			final KeyPair subjectKp, final String subjectDn,
			final Instant notBefore, final Instant notAfter) throws Exception {
		// Reconstruir issuer desde los bytes del DN del CA evita la inversión RDN
		// que produce X500Name(String) sobre un nombre con varios componentes.
		final X500Name issuer = X500Name.getInstance(
				issuerCert.getSubjectX500Principal().getEncoded());
		final X500Name subject = new X500Name(subjectDn);
		final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
				.build(issuerKp.getPrivate());
		final X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
				issuer, BigInteger.valueOf(System.currentTimeMillis() + 1),
				Date.from(notBefore), Date.from(notAfter),
				subject, subjectKp.getPublic())
				.build(signer);
		return (X509Certificate) CertificateFactory.getInstance("X.509")
				.generateCertificate(new java.io.ByteArrayInputStream(holder.getEncoded()));
	}

	private static final class MutableClock extends Clock {
		private Instant now;

		MutableClock(final Instant now) {
			this.now = now;
		}

		@Override
		public ZoneOffset getZone() {
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(final java.time.ZoneId zone) {
			return this;
		}

		@Override
		public Instant instant() {
			return this.now;
		}
	}
}
