/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import es.gob.afirma.eudiw.sdjwt.SdJwtVerifiableCredential;
import es.gob.afirma.eudiw.sdjwt.SdJwtVerificationException;
import es.gob.afirma.eudiw.sdjwt.SdJwtVerifier;
import es.gob.afirma.trust.tsl.TrustListService;
import es.gob.afirma.trust.tsl.TrustServiceProvider;
import es.gob.afirma.trust.tsl.TslDocument;

final class TestSdJwtVerifiableCredential {

	private static final String DISCLOSURE_JSON =
			"[\"r\u0301andom-salt\",\"family_name\",\"García\"]"; //$NON-NLS-1$

	@Test
	@DisplayName("Parser extrae issuer JWT + 1 disclosure + sin Key Binding")
	void parsesIssuerAndDisclosures() throws Exception {
		final String issuerJwt = makeUnsignedJwt();
		final String disclosure = Base64.getUrlEncoder().withoutPadding()
				.encodeToString(DISCLOSURE_JSON.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		// trailing '~' = sin Key Binding
		final String compact = issuerJwt + "~" + disclosure + "~";

		final SdJwtVerifiableCredential vc = SdJwtVerifiableCredential.parse(compact);
		assertEquals(JWSAlgorithm.HS256, vc.issuerSignedJwt().getHeader().getAlgorithm());
		assertEquals(1, vc.decodedDisclosures().size());
		assertTrue(vc.decodedDisclosures().get(0).contains("García"));
		assertFalse(vc.keyBindingJwt().isPresent(), "Sin Key Binding cuando termina en '~'");
	}

	@Test
	@DisplayName("Parser detecta Key Binding JWT al final cuando NO hay tilde de cierre")
	void parsesKeyBinding() throws Exception {
		final String issuerJwt = makeUnsignedJwt();
		final String kb = makeUnsignedJwt(); // misma forma para el test
		final String compact = issuerJwt + "~" + kb;

		final SdJwtVerifiableCredential vc = SdJwtVerifiableCredential.parse(compact);
		assertTrue(vc.keyBindingJwt().isPresent());
		assertEquals(0, vc.decodedDisclosures().size());
	}

	@Test
	@DisplayName("Parser rechaza entradas vacías o sin issuer JWT")
	void rejectsEmpty() {
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse(""));
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse("~"));
		assertThrows(NullPointerException.class, () -> SdJwtVerifiableCredential.parse(null));
	}

	@Test
	@DisplayName("Verifier valida issuer JWT, TSL, disclosures y Key Binding")
	void verifiesIssuerTrustDisclosureAndKeyBinding() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final KeyPair caKp = kpg.generateKeyPair();
		final X509Certificate caCert = selfSigned(caKp, "CN=EUDI CA, O=AEAD"); //$NON-NLS-1$
		final KeyPair issuerKp = kpg.generateKeyPair();
		final X509Certificate issuerCert = issuedBy(caKp, caCert, issuerKp,
				"CN=EUDI Issuer, O=AEAD"); //$NON-NLS-1$
		final KeyPair holderKp = kpg.generateKeyPair();
		final RSAKey holderJwk = new RSAKey.Builder(
				(java.security.interfaces.RSAPublicKey) holderKp.getPublic())
				.algorithm(JWSAlgorithm.RS256)
				.keyID("holder-1") //$NON-NLS-1$
				.build();

		final String disclosure = Base64.getUrlEncoder().withoutPadding()
				.encodeToString(DISCLOSURE_JSON.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		final String disclosureHash = disclosureHash(disclosure);
		final String issuerJwt = signedIssuerJwt(issuerKp, issuerCert, holderJwk, disclosureHash);
		final String presentation = issuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String kbJwt = signedKeyBindingJwt(holderKp, "https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(presentation));
		final SdJwtVerifiableCredential vc = SdJwtVerifiableCredential.parse(
				presentation + kbJwt);

		final TrustListService trust = new TrustListService();
		final TrustServiceProvider.TrustService service =
				new TrustServiceProvider.TrustService(
						"http://uri.etsi.org/TrstSvc/Svctype/CA/QC", //$NON-NLS-1$
						"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted", //$NON-NLS-1$
						List.of(caCert));
		final TrustServiceProvider provider = new TrustServiceProvider(
				"EUDI Provider", "EUDI Provider", "ES", List.of(service)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		trust.ingest(new TslDocument("Operator", "ES", null, List.of(provider), false)); //$NON-NLS-1$ //$NON-NLS-2$

		assertEquals("EUDI Provider", SdJwtVerifier.verify( //$NON-NLS-1$
				vc, trust, "https://verifier.example.es", "nonce-1").name()); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(vc, trust,
						"https://verifier.example.es", "wrong")); //$NON-NLS-1$ //$NON-NLS-2$
		final String replayedKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", presentationHash(issuerJwt + "~")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		final SdJwtVerifiableCredential replayedVc = SdJwtVerifiableCredential.parse(
				presentation + replayedKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(replayedVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String badDisclosure = "not-base64url!!"; //$NON-NLS-1$
		final String badIssuerJwt = signedIssuerJwt(issuerKp, issuerCert, holderJwk,
				disclosureHash(badDisclosure));
		final SdJwtVerifiableCredential badVc = SdJwtVerifiableCredential.parse(
				badIssuerJwt + "~" + badDisclosure + "~" + kbJwt); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(badVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	private static String makeUnsignedJwt() throws Exception {
		final byte[] secret = new byte[32];
		java.util.Arrays.fill(secret, (byte) 0x42);
		final JWSObject jws = new JWSObject(
				new JWSHeader.Builder(JWSAlgorithm.HS256).build(),
				new Payload("{\"sub\":\"test\"}"));
		jws.sign(new MACSigner(secret));
		return jws.serialize();
	}

	private static String signedIssuerJwt(final KeyPair issuerKp,
			final X509Certificate issuerCert, final RSAKey holderJwk,
			final String sdHash) throws Exception {
		final SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.RS256)
						.x509CertChain(List.of(com.nimbusds.jose.util.Base64
								.encode(issuerCert.getEncoded())))
						.build(),
				new JWTClaimsSet.Builder()
						.issuer("https://issuer.example.es") //$NON-NLS-1$
						.subject("pid-1") //$NON-NLS-1$
						.claim("_sd_alg", "sha-256") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("_sd", List.of(sdHash)) //$NON-NLS-1$
						.claim("cnf", Map.of("jwk", holderJwk.toPublicJWK().toJSONObject())) //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		jwt.sign(new RSASSASigner(issuerKp.getPrivate()));
		return jwt.serialize();
	}

	private static String signedKeyBindingJwt(final KeyPair holderKp,
			final String audience, final String nonce, final String sdHash) throws Exception {
		final SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
				new JWTClaimsSet.Builder()
						.audience(audience)
						.claim("nonce", nonce) //$NON-NLS-1$
						.claim("sd_hash", sdHash) //$NON-NLS-1$
						.build());
		jwt.sign(new RSASSASigner(holderKp.getPrivate()));
		return jwt.serialize();
	}

	private static String disclosureHash(final String disclosure) throws Exception {
		return sha256Base64Url(disclosure);
	}

	private static String presentationHash(final String presentation) throws Exception {
		return sha256Base64Url(presentation);
	}

	private static String sha256Base64Url(final String value) throws Exception {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(
				java.security.MessageDigest.getInstance("SHA-256") //$NON-NLS-1$
						.digest(value.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
	}

	private static X509Certificate selfSigned(final KeyPair kp, final String subject)
			throws Exception {
		final Instant now = Instant.now();
		final X500Name dn = new X500Name(subject);
		final X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
				dn, BigInteger.valueOf(System.currentTimeMillis()),
				Date.from(now), Date.from(now.plus(Duration.ofDays(365))),
				dn, kp.getPublic())
				.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())); //$NON-NLS-1$
		return (X509Certificate) CertificateFactory.getInstance("X.509") //$NON-NLS-1$
				.generateCertificate(new java.io.ByteArrayInputStream(holder.getEncoded()));
	}

	private static X509Certificate issuedBy(final KeyPair issuerKp,
			final X509Certificate issuerCert, final KeyPair subjectKp,
			final String subjectDn) throws Exception {
		final Instant now = Instant.now();
		final X500Name issuer = X500Name.getInstance(
				issuerCert.getSubjectX500Principal().getEncoded());
		final X500Name subject = new X500Name(subjectDn);
		final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA") //$NON-NLS-1$
				.build(issuerKp.getPrivate());
		final X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
				issuer, BigInteger.valueOf(System.currentTimeMillis() + 1),
				Date.from(now), Date.from(now.plus(Duration.ofDays(365))),
				subject, subjectKp.getPublic())
				.build(signer);
		return (X509Certificate) CertificateFactory.getInstance("X.509") //$NON-NLS-1$
				.generateCertificate(new java.io.ByteArrayInputStream(holder.getEncoded()));
	}
}
