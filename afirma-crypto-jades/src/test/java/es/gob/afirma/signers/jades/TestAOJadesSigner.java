/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.signers.jades;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.sun.net.httpserver.HttpServer;

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
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
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
		final Properties params = new Properties();
		params.setProperty(AOJadesSigner.EXTRA_PARAM_CONTENT_TYPE, " application/json"); //$NON-NLS-1$
		assertThrows(es.gob.afirma.core.AOException.class,
				() -> signer.sign("x".getBytes(), "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
						RSA_KEY.getPrivate(), RSA_CHAIN, params));
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
	@DisplayName("isSign reconoce JWS JSON Serialization general")
	void isSignAcceptsGeneralJsonSerialization() throws Exception {
		final Properties params = new Properties();
		params.setProperty(AOJadesSigner.EXTRA_PARAM_JSON_SERIALIZATION, "true"); //$NON-NLS-1$
		final AOJadesSigner signer = new AOJadesSigner();
		final Map<String, Object> flattened = JSONObjectUtils.parse(new String(
				signer.sign("payload".getBytes(), "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
						RSA_KEY.getPrivate(), RSA_CHAIN, params),
				java.nio.charset.StandardCharsets.UTF_8));
		final Map<String, Object> signature = Map.of(
				"protected", flattened.get("protected"), //$NON-NLS-1$ //$NON-NLS-2$
				"signature", flattened.get("signature")); //$NON-NLS-1$ //$NON-NLS-2$
		final Map<String, Object> general = Map.of("signatures", List.of(signature)); //$NON-NLS-1$

		assertTrue(signer.isSign(JSONObjectUtils.toJSONString(general)
				.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
		assertTrue(!signer.isSign("{\"signatures\":[]}".getBytes())); //$NON-NLS-1$
	}

	@Test
	@DisplayName("timestampTokenBase64 rechaza Base64 que no es RFC3161")
	void rejectsMalformedTimestampToken() {
		final Properties params = new Properties();
		params.setProperty(AOJadesSigner.EXTRA_PARAM_JSON_SERIALIZATION, "true"); //$NON-NLS-1$
		params.setProperty(AOJadesSigner.EXTRA_PARAM_TIMESTAMP_TOKEN_BASE64, "MAMCAQE="); //$NON-NLS-1$
		final AOJadesSigner signer = new AOJadesSigner();

		assertThrows(es.gob.afirma.core.AOException.class,
				() -> signer.sign("payload".getBytes(), //$NON-NLS-1$
						"SHA256withRSA", RSA_KEY.getPrivate(), RSA_CHAIN, params)); //$NON-NLS-1$
		params.setProperty(AOJadesSigner.EXTRA_PARAM_TIMESTAMP_TOKEN_BASE64, " MAMCAQE="); //$NON-NLS-1$
		assertThrows(es.gob.afirma.core.AOException.class,
				() -> signer.sign("payload".getBytes(), //$NON-NLS-1$
						"SHA256withRSA", RSA_KEY.getPrivate(), RSA_CHAIN, params)); //$NON-NLS-1$
	}

	@Test
	@DisplayName("timestampTokenBase64 rechaza RFC3161 que no sella la firma JWS")
	void rejectsTimestampTokenForDifferentImprint() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final KeyPair tsaKey = kpg.generateKeyPair();
		final X509Certificate tsaCert = selfSigned(tsaKey, "CN=JAdES TSA, O=AEAD", true); //$NON-NLS-1$
		final String token = timestampTokenBase64(
				timestampTokenGenerator(tsaKey, tsaCert),
				MessageDigest.getInstance("SHA-256").digest("otra-firma".getBytes())); //$NON-NLS-1$ //$NON-NLS-2$
		final Properties params = new Properties();
		params.setProperty(AOJadesSigner.EXTRA_PARAM_JSON_SERIALIZATION, "true"); //$NON-NLS-1$
		params.setProperty(AOJadesSigner.EXTRA_PARAM_TIMESTAMP_TOKEN_BASE64, token);
		final AOJadesSigner signer = new AOJadesSigner();

		assertThrows(es.gob.afirma.core.AOException.class,
				() -> signer.sign("payload".getBytes(), //$NON-NLS-1$
						"SHA256withRSA", RSA_KEY.getPrivate(), RSA_CHAIN, params)); //$NON-NLS-1$
	}

	@Test
	@DisplayName("timestampTokenBase64 requiere JWS JSON Serialization")
	void timestampTokenRequiresJsonSerialization() {
		final Properties params = new Properties();
		params.setProperty(AOJadesSigner.EXTRA_PARAM_TIMESTAMP_TOKEN_BASE64, "MAMCAQE="); //$NON-NLS-1$
		final AOJadesSigner signer = new AOJadesSigner();

		assertThrows(es.gob.afirma.core.AOException.class,
				() -> signer.sign("payload".getBytes(), "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
						RSA_KEY.getPrivate(), RSA_CHAIN, params));
	}

	@Test
	@DisplayName("JAdES-T rechaza token RFC3161 y TSA configurados a la vez")
	void rejectsAmbiguousTimestampSource() {
		final Properties params = new Properties();
		params.setProperty(AOJadesSigner.EXTRA_PARAM_JSON_SERIALIZATION, "true"); //$NON-NLS-1$
		params.setProperty(AOJadesSigner.EXTRA_PARAM_TIMESTAMP_TOKEN_BASE64, "MAMCAQE="); //$NON-NLS-1$
		params.setProperty(AOJadesSigner.EXTRA_PARAM_TSA_URL, "https://tsa.example/test"); //$NON-NLS-1$

		assertThrows(es.gob.afirma.core.AOException.class,
				() -> new AOJadesSigner().sign("payload".getBytes(), "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
						RSA_KEY.getPrivate(), RSA_CHAIN, params));
	}

	@Test
	@DisplayName("sign rechaza certificado firmante que no es X.509")
	void rejectsNonX509SignerCertificate() {
		final AOJadesSigner signer = new AOJadesSigner();

		assertThrows(es.gob.afirma.core.AOException.class,
				() -> signer.sign("payload".getBytes(), "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
						RSA_KEY.getPrivate(), new Certificate[] { rawCertificate() }, new Properties()));
	}

	@Test
	@DisplayName("sign rechaza clave privada que no corresponde al certificado firmante")
	void rejectsSignerCertificateWithDifferentPrivateKey() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final Certificate[] otherChain = new Certificate[] {
				selfSigned(kpg.generateKeyPair(), "CN=JAdES Otro, O=AEAD") }; //$NON-NLS-1$
		final AOJadesSigner signer = new AOJadesSigner();

		assertThrows(es.gob.afirma.core.AOException.class,
				() -> signer.sign("payload".getBytes(), "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
						RSA_KEY.getPrivate(), otherChain, new Properties()));
	}

	@Test
	@DisplayName("sign rechaza certificado firmante caducado")
	void rejectsExpiredSignerCertificate() throws Exception {
		final Instant expired = Instant.now().minus(Duration.ofDays(2));
		final Certificate[] expiredChain = new Certificate[] {
				selfSigned(RSA_KEY, "CN=JAdES Expired, O=AEAD", false, //$NON-NLS-1$
						expired, expired.plus(Duration.ofDays(1))) };
		final AOJadesSigner signer = new AOJadesSigner();

		assertThrows(es.gob.afirma.core.AOException.class,
				() -> signer.sign("payload".getBytes(), "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
						RSA_KEY.getPrivate(), expiredChain, new Properties()));
		final Instant future = Instant.now().plus(Duration.ofDays(1));
		final Certificate[] futureChain = new Certificate[] {
				RSA_CHAIN[0],
				selfSigned(RSA_KEY, "CN=JAdES Intermediate Future, O=AEAD", false, //$NON-NLS-1$
						future, future.plus(Duration.ofDays(1))) };
		assertThrows(es.gob.afirma.core.AOException.class,
				() -> signer.sign("payload".getBytes(), "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
						RSA_KEY.getPrivate(), futureChain, new Properties()));
	}

	@Test
	@DisplayName("sign rechaza x5c JAdES con certificados no vigentes")
	void rejectsExpiredCertificateInChain() throws Exception {
		final Instant expired = Instant.now().minus(Duration.ofDays(2));
		final Certificate[] expiredChain = new Certificate[] {
				RSA_CHAIN[0],
				selfSigned(RSA_KEY, "CN=JAdES Intermediate Expired, O=AEAD", false, //$NON-NLS-1$
						expired, expired.plus(Duration.ofDays(1))) };
		final AOJadesSigner signer = new AOJadesSigner();

		assertThrows(es.gob.afirma.core.AOException.class,
				() -> signer.sign("payload".getBytes(), "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
						RSA_KEY.getPrivate(), expiredChain, new Properties()));
	}

	@Test
	@DisplayName("sign rechaza cadena JAdES con certificados no X.509")
	void rejectsNonX509CertificateInChain() {
		final AOJadesSigner signer = new AOJadesSigner();
		final Certificate nonX509 = rawCertificate();

		assertThrows(es.gob.afirma.core.AOException.class,
				() -> signer.sign("payload".getBytes(), "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
						RSA_KEY.getPrivate(), new Certificate[] { RSA_CHAIN[0], nonX509 }, new Properties()));
	}

	@Test
	@DisplayName("tsaURL genera token RFC3161 sobre la firma JWS y lo inserta en etsiU")
	void signRsa256JsonSerializationWithLocalTsa() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		final KeyPair tsaKey = kpg.generateKeyPair();
		final X509Certificate tsaCert = selfSigned(tsaKey, "CN=JAdES TSA, O=AEAD", true); //$NON-NLS-1$
		final TimeStampTokenGenerator tokenGenerator = timestampTokenGenerator(tsaKey, tsaCert);
		final AtomicInteger requests = new AtomicInteger();
		final HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0); //$NON-NLS-1$
		server.createContext("/tsa", exchange -> { //$NON-NLS-1$
			try {
				final TimeStampRequest request = new TimeStampRequest(exchange.getRequestBody().readAllBytes());
				final TimeStampResponse response = new TimeStampResponseGenerator(
						tokenGenerator,
						TSPAlgorithms.ALLOWED)
								.generate(request, BigInteger.valueOf(requests.incrementAndGet()), new Date());
				final byte[] responseBytes = response.getEncoded();
				exchange.getResponseHeaders().set("Content-Type", "application/timestamp-reply"); //$NON-NLS-1$ //$NON-NLS-2$
				exchange.sendResponseHeaders(200, responseBytes.length);
				exchange.getResponseBody().write(responseBytes);
			}
			catch (final Exception e) {
				throw new IOException("No se pudo generar la respuesta RFC3161 de prueba", e); //$NON-NLS-1$
			}
			finally {
				exchange.close();
			}
		});
		server.start();
		try {
			final Properties params = new Properties();
			params.setProperty(AOJadesSigner.EXTRA_PARAM_JSON_SERIALIZATION, "true"); //$NON-NLS-1$
			params.setProperty(AOJadesSigner.EXTRA_PARAM_TSA_URL,
					"http://127.0.0.1:" + server.getAddress().getPort() + "/tsa"); //$NON-NLS-1$ //$NON-NLS-2$
			params.setProperty("tsaHashAlgorithm", "SHA-256"); //$NON-NLS-1$ //$NON-NLS-2$
			final AOJadesSigner signer = new AOJadesSigner();

			final byte[] jws = signer.sign("payload".getBytes(), //$NON-NLS-1$
					"SHA256withRSA", RSA_KEY.getPrivate(), RSA_CHAIN, params); //$NON-NLS-1$
			final Map<String, Object> json = JSONObjectUtils.parse(
					new String(jws, java.nio.charset.StandardCharsets.UTF_8));
			final String signature = (String) json.get("signature"); //$NON-NLS-1$
			final String tokenBase64 = timestampTokenFromHeader(json);
			final TimeStampToken tst = new TimeStampToken(
					new CMSSignedData(java.util.Base64.getDecoder().decode(tokenBase64)));
			final byte[] expectedImprint = MessageDigest.getInstance("SHA-256") //$NON-NLS-1$
					.digest(Base64URL.from(signature).decode());

			assertEquals(1, requests.get(), "Debe solicitar un sello a la TSA local");
			assertArrayEquals(expectedImprint, tst.getTimeStampInfo().getMessageImprintDigest(),
					"El token RFC3161 debe sellar la firma JWS");
		}
		finally {
			server.stop(0);
		}
	}

	@Test
	@DisplayName("tsaURL rechaza token RFC3161 sin certificado TSA embebido")
	void rejectsTimestampTokenWithoutEmbeddedCertificate() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final KeyPair tsaKey = kpg.generateKeyPair();
		final X509Certificate tsaCert = selfSigned(tsaKey, "CN=JAdES TSA, O=AEAD", true); //$NON-NLS-1$
		final TimeStampTokenGenerator tokenGenerator = timestampTokenGenerator(tsaKey, tsaCert, false);
		final HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0); //$NON-NLS-1$
		server.createContext("/tsa", exchange -> { //$NON-NLS-1$
			try {
				final TimeStampRequest request = new TimeStampRequest(exchange.getRequestBody().readAllBytes());
				final TimeStampResponse response = new TimeStampResponseGenerator(
						tokenGenerator,
						TSPAlgorithms.ALLOWED)
								.generate(request, BigInteger.ONE, new Date());
				final byte[] responseBytes = response.getEncoded();
				exchange.sendResponseHeaders(200, responseBytes.length);
				exchange.getResponseBody().write(responseBytes);
			}
			catch (final Exception e) {
				throw new IOException("No se pudo generar la respuesta RFC3161 de prueba", e); //$NON-NLS-1$
			}
			finally {
				exchange.close();
			}
		});
		server.start();
		try {
			final Properties params = new Properties();
			params.setProperty(AOJadesSigner.EXTRA_PARAM_JSON_SERIALIZATION, "true"); //$NON-NLS-1$
			params.setProperty(AOJadesSigner.EXTRA_PARAM_TSA_URL,
					"http://127.0.0.1:" + server.getAddress().getPort() + "/tsa"); //$NON-NLS-1$ //$NON-NLS-2$
			params.setProperty("tsaHashAlgorithm", "SHA-256"); //$NON-NLS-1$ //$NON-NLS-2$

			assertThrows(es.gob.afirma.core.AOException.class,
					() -> new AOJadesSigner().sign("payload".getBytes(), //$NON-NLS-1$
							"SHA256withRSA", RSA_KEY.getPrivate(), RSA_CHAIN, params)); //$NON-NLS-1$
		}
		finally {
			server.stop(0);
		}
	}

	@Test
	@DisplayName("tsaURL rechaza certificado TSA caducado")
	void rejectsTimestampTokenWithExpiredTsaCertificate() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final KeyPair tsaKey = kpg.generateKeyPair();
		final Instant expired = Instant.now().minus(Duration.ofDays(2));
		final X509Certificate tsaCert = selfSigned(tsaKey, "CN=JAdES TSA Expired, O=AEAD", true, //$NON-NLS-1$
				expired, expired.plus(Duration.ofDays(1)));
		final TimeStampTokenGenerator tokenGenerator = timestampTokenGenerator(tsaKey, tsaCert);
		final HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0); //$NON-NLS-1$
		server.createContext("/tsa", exchange -> { //$NON-NLS-1$
			try {
				final TimeStampRequest request = new TimeStampRequest(exchange.getRequestBody().readAllBytes());
				final TimeStampResponse response = new TimeStampResponseGenerator(
						tokenGenerator,
						TSPAlgorithms.ALLOWED)
								.generate(request, BigInteger.ONE, new Date());
				final byte[] responseBytes = response.getEncoded();
				exchange.sendResponseHeaders(200, responseBytes.length);
				exchange.getResponseBody().write(responseBytes);
			}
			catch (final Exception e) {
				throw new IOException("No se pudo generar la respuesta RFC3161 de prueba", e); //$NON-NLS-1$
			}
			finally {
				exchange.close();
			}
		});
		server.start();
		try {
			final Properties params = new Properties();
			params.setProperty(AOJadesSigner.EXTRA_PARAM_JSON_SERIALIZATION, "true"); //$NON-NLS-1$
			params.setProperty(AOJadesSigner.EXTRA_PARAM_TSA_URL,
					"http://127.0.0.1:" + server.getAddress().getPort() + "/tsa"); //$NON-NLS-1$ //$NON-NLS-2$
			params.setProperty("tsaHashAlgorithm", "SHA-256"); //$NON-NLS-1$ //$NON-NLS-2$

			assertThrows(es.gob.afirma.core.AOException.class,
					() -> new AOJadesSigner().sign("payload".getBytes(), //$NON-NLS-1$
							"SHA256withRSA", RSA_KEY.getPrivate(), RSA_CHAIN, params)); //$NON-NLS-1$
		}
		finally {
			server.stop(0);
		}
	}

	@Test
	@DisplayName("isSign rechaza entradas que no son JWS compact")
	void isSignRejectsNonJws() throws Exception {
		final AOJadesSigner signer = new AOJadesSigner();
		assertDoesNotThrow(() -> {
			assertTrue(!signer.isSign("not a jws".getBytes()));
			assertTrue(!signer.isSign(new byte[] { 0x30, (byte) 0x82 })); // un DER no es un JWS
			assertTrue(!signer.isSign(new byte[0]));
			assertTrue(!signer.isSign("a.b.c".getBytes())); //$NON-NLS-1$
			assertTrue(!signer.isSign("eyJhbGciOiJSUzI1NiJ9..YWJj".getBytes())); //$NON-NLS-1$
			assertTrue(!signer.isSign("eyJhbGciOiJSUzI1NiJ9..".getBytes())); //$NON-NLS-1$
			assertTrue(!signer.isSign("eyJhbGciOiJSUzI1NiJ9..not-base64url!!".getBytes())); //$NON-NLS-1$
			assertTrue(!signer.isSign("{\"protected\":\"x\",\"signature\":\"\"}".getBytes())); //$NON-NLS-1$
			assertTrue(!signer.isSign("{\"protected\":\"not-base64url!!\",\"signature\":\"abc\"}".getBytes())); //$NON-NLS-1$
			assertTrue(!signer.isSign("{\"protected\":\"bm90LWpzb24\",\"signature\":\"abc\"}".getBytes())); //$NON-NLS-1$
			assertTrue(!signer.isSign("{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"YWJj\"}".getBytes())); //$NON-NLS-1$
			assertTrue(!signer.isSign("{\"protected\":\"eyJhbGciOiJSUzI1NiJ9\",\"signature\":\"not-base64url!!\"}".getBytes())); //$NON-NLS-1$
			assertTrue(!signer.isSign("{\"protected-text\":\"x\",\"signature-text\":\"y\"}".getBytes())); //$NON-NLS-1$
			assertTrue(!signer.isSign("{not-json".getBytes())); //$NON-NLS-1$
		});
		final Properties attached = new Properties();
		attached.setProperty(AOJadesSigner.EXTRA_PARAM_DETACHED, "false"); //$NON-NLS-1$
		final String jades = new String(signer.sign("payload".getBytes(), //$NON-NLS-1$
				"SHA256withRSA", RSA_KEY.getPrivate(), RSA_CHAIN, attached), //$NON-NLS-1$
				java.nio.charset.StandardCharsets.UTF_8);
		final int firstDot = jades.indexOf('.');
		final int secondDot = jades.indexOf('.', firstDot + 1);
		assertTrue(!signer.isSign((jades.substring(0, firstDot + 1)
				+ "not-base64url!!" + jades.substring(secondDot)).getBytes())); //$NON-NLS-1$
		final Properties attachedJson = new Properties();
		attachedJson.setProperty(AOJadesSigner.EXTRA_PARAM_JSON_SERIALIZATION, "true"); //$NON-NLS-1$
		attachedJson.setProperty(AOJadesSigner.EXTRA_PARAM_DETACHED, "false"); //$NON-NLS-1$
		final Map<String, Object> json = JSONObjectUtils.parse(new String(
				signer.sign("payload".getBytes(), "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
						RSA_KEY.getPrivate(), RSA_CHAIN, attachedJson),
				java.nio.charset.StandardCharsets.UTF_8));
		json.put("payload", "not-base64url!!"); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(!signer.isSign(JSONObjectUtils.toJSONString(json)
				.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
	}

	private static X509Certificate selfSigned(final KeyPair kp, final String subject) throws Exception {
		return selfSigned(kp, subject, false);
	}

	private static Certificate rawCertificate() {
		return new Certificate("RAW") { //$NON-NLS-1$
			@Override
			public byte[] getEncoded() { return new byte[] { 1 }; }
			@Override
			public void verify(final PublicKey key) { /* No usado. */ }
			@Override
			public void verify(final PublicKey key, final String sigProvider) { /* No usado. */ }
			@Override
			public String toString() { return "RAW"; } //$NON-NLS-1$
			@Override
			public PublicKey getPublicKey() { return RSA_KEY.getPublic(); }
		};
	}

	private static X509Certificate selfSigned(final KeyPair kp, final String subject, final boolean timestamping) throws Exception {
		final Instant now = Instant.now();
		return selfSigned(kp, subject, timestamping, now, now.plus(Duration.ofDays(365)));
	}

	private static X509Certificate selfSigned(final KeyPair kp, final String subject,
			final boolean timestamping, final Instant notBefore, final Instant notAfter) throws Exception {
		final X500Name dn = new X500Name(subject);
		final BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				dn, serial, Date.from(notBefore), Date.from(notAfter),
				dn, kp.getPublic());
		if (timestamping) {
			builder.addExtension(Extension.extendedKeyUsage, true,
					new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
		}
		final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
		final X509CertificateHolder holder = builder.build(signer);
		final byte[] der = holder.getEncoded();
		return (X509Certificate) CertificateFactory.getInstance("X.509")
				.generateCertificate(new java.io.ByteArrayInputStream(der));
	}

	private static TimeStampTokenGenerator timestampTokenGenerator(final KeyPair tsaKey,
			final X509Certificate tsaCert) throws Exception {
		return timestampTokenGenerator(tsaKey, tsaCert, true);
	}

	private static TimeStampTokenGenerator timestampTokenGenerator(final KeyPair tsaKey,
			final X509Certificate tsaCert, final boolean embedCertificate) throws Exception {
		final DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME)
				.build();
		final ContentSigner tsaSigner = new JcaContentSignerBuilder("SHA256withRSA") //$NON-NLS-1$
				.setProvider(BouncyCastleProvider.PROVIDER_NAME)
				.build(tsaKey.getPrivate());
		final TimeStampTokenGenerator generator = new TimeStampTokenGenerator(
				new JcaSignerInfoGeneratorBuilder(digestProvider).build(tsaSigner, tsaCert),
				digestProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
				new ASN1ObjectIdentifier("1.3.6.1.4.1.5734.1.1")); //$NON-NLS-1$
		if (embedCertificate) {
			generator.addCertificates(new JcaCertStore(List.of(tsaCert)));
		}
		return generator;
	}

	private static String timestampTokenBase64(final TimeStampTokenGenerator generator,
			final byte[] imprint) throws Exception {
		final TimeStampRequest request = new TimeStampRequestGenerator()
				.generate(TSPAlgorithms.SHA256, imprint);
		final TimeStampResponse response = new TimeStampResponseGenerator(
				generator, TSPAlgorithms.ALLOWED)
						.generate(request, BigInteger.ONE, new Date());
		return java.util.Base64.getEncoder().encodeToString(
				response.getTimeStampToken().getEncoded());
	}

	private static String timestampTokenFromHeader(final Map<String, Object> json) throws Exception {
		final Map<String, Object> header = JSONObjectUtils.getJSONObject(json, "header"); //$NON-NLS-1$
		final List<Object> etsiU = JSONObjectUtils.getJSONArray(header, "etsiU"); //$NON-NLS-1$
		final Object container = etsiU.get(0);
		final List<Object> tokens = JSONObjectUtils.getJSONArray(asJsonObject(container), "tstTokens"); //$NON-NLS-1$
		final Object token = tokens.get(0);
		return JSONObjectUtils.getString(asJsonObject(token), "val"); //$NON-NLS-1$
	}

	private static Map<String, Object> asJsonObject(final Object object) {
		if (!(object instanceof Map<?, ?> map)) {
			throw new IllegalArgumentException("El valor no es un objeto JSON"); //$NON-NLS-1$
		}
		final Map<String, Object> typed = new HashMap<>();
		for (final Map.Entry<?, ?> entry : map.entrySet()) {
			if (!(entry.getKey() instanceof String key)) {
				throw new IllegalArgumentException("La clave JSON no es una cadena"); //$NON-NLS-1$
			}
			typed.put(key, entry.getValue());
		}
		return typed;
	}
}
