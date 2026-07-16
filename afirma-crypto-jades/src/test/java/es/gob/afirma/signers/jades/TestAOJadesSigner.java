/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.signers.jades;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Properties;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Verifica que {@link AOJadesSigner} produce un compact JWS bien formado con
 * los campos JAdES-B-B obligatorios. No depende de fixtures externos: el par
 * de claves y el certificado se generan al vuelo con BouncyCastle.
 */
final class TestAOJadesSigner {

	private static KeyPair RSA_KEY;
	private static Certificate[] RSA_CHAIN;

	@BeforeAll
	static void setUp() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		RSA_KEY = kpg.generateKeyPair();
		RSA_CHAIN = new Certificate[] { selfSigned(RSA_KEY, "CN=JAdES Test, O=AEAD") };
	}

	@Test
	@DisplayName("RS256 detached produce un compact JWS de 2 puntos con header JOSE válido")
	void signRsa256Detached() throws Exception {
		final byte[] payload = "Hola JAdES".getBytes(java.nio.charset.StandardCharsets.UTF_8);
		final AOJadesSigner signer = new AOJadesSigner();

		final byte[] jws = signer.sign(payload, "SHA256withRSA",
				RSA_KEY.getPrivate(), RSA_CHAIN, new Properties());

		assertNotNull(jws);
		assertTrue(signer.isSign(jws), "El resultado debería identificarse como JWS");

		final String header = AOJadesSigner.decodeProtectedHeader(jws);
		assertTrue(header.contains("\"alg\":\"RS256\""), "Header debe declarar alg=RS256");
		assertTrue(header.contains("\"x5t#S256\""), "Header debe incluir x5t#S256 (JAdES-B-B)");
		assertTrue(header.contains("\"x5c\""), "Header debe incluir cadena x5c");
		assertTrue(header.contains("\"sigT\""), "Header debe incluir sigT (claim crítico JAdES)");
		assertTrue(header.contains("\"crit\""), "Header debe declarar crit");

		final String compact = new String(jws, java.nio.charset.StandardCharsets.UTF_8);
		final long dots = compact.chars().filter(c -> c == '.').count();
		assertEquals(2L, dots, "Compact JWS debe tener exactamente 2 puntos (header.payload.signature)");
	}

	@Test
	@DisplayName("Detached omite el payload entre los puntos")
	void detachedOmitsPayload() throws Exception {
		final AOJadesSigner signer = new AOJadesSigner();
		final byte[] jws = signer.sign("payload".getBytes(),
				"SHA256withRSA", RSA_KEY.getPrivate(), RSA_CHAIN, new Properties());
		final String s = new String(jws, java.nio.charset.StandardCharsets.UTF_8);
		final int firstDot = s.indexOf('.');
		final int secondDot = s.indexOf('.', firstDot + 1);
		assertEquals(firstDot + 1, secondDot, "Sección de payload debe estar vacía en detached");
	}

	@Test
	@DisplayName("Sin contentType custom el header no incluye cty")
	void noContentTypeIfNotProvided() throws Exception {
		final AOJadesSigner signer = new AOJadesSigner();
		final byte[] jws = signer.sign("x".getBytes(), "SHA256withRSA",
				RSA_KEY.getPrivate(), RSA_CHAIN, new Properties());
		final String header = AOJadesSigner.decodeProtectedHeader(jws);
		assertTrue(!header.contains("\"cty\""), "Sin extraParam contentType no debe haber cty en header");
	}

	@Test
	@DisplayName("jsonSerialization=true emite JWS JSON flattened detached")
	void signRsa256JsonSerialization() throws Exception {
		final Properties params = new Properties();
		params.setProperty(AOJadesSigner.EXTRA_PARAM_JSON_SERIALIZATION, "true"); //$NON-NLS-1$
		final AOJadesSigner signer = new AOJadesSigner();

		final byte[] jws = signer.sign("payload".getBytes(), //$NON-NLS-1$
				"SHA256withRSA", RSA_KEY.getPrivate(), RSA_CHAIN, params); //$NON-NLS-1$
		final String json = new String(jws, java.nio.charset.StandardCharsets.UTF_8);

		assertTrue(signer.isSign(jws), "El JSON serialization debe reconocerse como firma JAdES");
		assertTrue(json.startsWith("{"), "Debe emitirse objeto JSON");
		assertTrue(json.contains("\"protected\""));
		assertTrue(json.contains("\"signature\""));
		assertTrue(!json.contains("\"payload\""), "Detached JSON serialization no debe incluir payload");
	}

	@Test
	@DisplayName("isSign rechaza entradas que no son JWS compact")
	void isSignRejectsNonJws() {
		final AOJadesSigner signer = new AOJadesSigner();
		assertDoesNotThrow(() -> {
			assertTrue(!signer.isSign("not a jws".getBytes()));
			assertTrue(!signer.isSign(new byte[] { 0x30, (byte) 0x82 })); // un DER no es un JWS
			assertTrue(!signer.isSign(new byte[0]));
		});
	}

	private static X509Certificate selfSigned(final KeyPair kp, final String subject) throws Exception {
		final Instant now = Instant.now();
		final X500Name dn = new X500Name(subject);
		final BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				dn, serial, Date.from(now), Date.from(now.plus(Duration.ofDays(365))),
				dn, kp.getPublic());
		final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
		final X509CertificateHolder holder = builder.build(signer);
		final byte[] der = holder.getEncoded();
		return (X509Certificate) CertificateFactory.getInstance("X.509")
				.generateCertificate(new java.io.ByteArrayInputStream(der));
	}
}
