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

import com.nimbusds.jose.JOSEObjectType;
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
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse(makeUnsignedJwt() + "~~"));
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
				() -> SdJwtVerifier.verify(vc, trust, " ", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(vc, trust,
						"https://verifier.example.es", " ")); //$NON-NLS-1$ //$NON-NLS-2$
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
		final String untypedKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", presentationHash(presentation), false); //$NON-NLS-1$ //$NON-NLS-2$
		final SdJwtVerifiableCredential untypedVc = SdJwtVerifiableCredential.parse(
				presentation + untypedKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(untypedVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String expiredKb = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", presentationHash(presentation), //$NON-NLS-1$ //$NON-NLS-2$
				true, Date.from(Instant.now().minus(Duration.ofMinutes(1))), null);
		final SdJwtVerifiableCredential expiredKbVc = SdJwtVerifiableCredential.parse(
				presentation + expiredKb);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(expiredKbVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String earlyKb = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", presentationHash(presentation), //$NON-NLS-1$ //$NON-NLS-2$
				true, null, Date.from(Instant.now().plus(Duration.ofMinutes(1))));
		final SdJwtVerifiableCredential earlyKbVc = SdJwtVerifiableCredential.parse(
				presentation + earlyKb);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(earlyKbVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String expiredIssuerJwt = signedIssuerJwt(issuerKp, issuerCert, holderJwk,
				disclosureHash, Date.from(Instant.now().minus(Duration.ofDays(1))));
		final String expiredPresentation = expiredIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String expiredKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", presentationHash(expiredPresentation)); //$NON-NLS-1$ //$NON-NLS-2$
		final SdJwtVerifiableCredential expiredVc = SdJwtVerifiableCredential.parse(
				expiredPresentation + expiredKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(expiredVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final Instant expiredCertTime = Instant.now().minus(Duration.ofDays(2));
		final X509Certificate expiredIssuerCert = issuedBy(caKp, caCert, issuerKp,
				"CN=EUDI Issuer Expired, O=AEAD", expiredCertTime, //$NON-NLS-1$
				expiredCertTime.plus(Duration.ofDays(1)));
		final String expiredCertIssuerJwt = signedIssuerJwt(issuerKp, expiredIssuerCert,
				holderJwk, disclosureHash);
		final String expiredCertPresentation = expiredCertIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String expiredCertKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(expiredCertPresentation));
		final SdJwtVerifiableCredential expiredCertVc = SdJwtVerifiableCredential.parse(
				expiredCertPresentation + expiredCertKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(expiredCertVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String nonArrayDisclosure = Base64.getUrlEncoder().withoutPadding()
				.encodeToString("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8)); //$NON-NLS-1$
		final String nonArrayIssuerJwt = signedIssuerJwt(issuerKp, issuerCert, holderJwk,
				disclosureHash(nonArrayDisclosure));
		final String nonArrayPresentation = nonArrayIssuerJwt + "~" + nonArrayDisclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String nonArrayKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", presentationHash(nonArrayPresentation)); //$NON-NLS-1$ //$NON-NLS-2$
		final SdJwtVerifiableCredential nonArrayVc = SdJwtVerifiableCredential.parse(
				nonArrayPresentation + nonArrayKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(nonArrayVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String shortDisclosure = Base64.getUrlEncoder().withoutPadding()
				.encodeToString("[\"salt\",\"family_name\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8)); //$NON-NLS-1$
		final String shortDisclosureIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, disclosureHash(shortDisclosure));
		final String shortDisclosurePresentation = shortDisclosureIssuerJwt + "~" + shortDisclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String shortDisclosureKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(shortDisclosurePresentation));
		final SdJwtVerifiableCredential shortDisclosureVc = SdJwtVerifiableCredential.parse(
				shortDisclosurePresentation + shortDisclosureKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(shortDisclosureVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String duplicatedPresentation = issuerJwt + "~" + disclosure + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		final String duplicatedKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", presentationHash(duplicatedPresentation)); //$NON-NLS-1$ //$NON-NLS-2$
		final SdJwtVerifiableCredential duplicatedVc = SdJwtVerifiableCredential.parse(
				duplicatedPresentation + duplicatedKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(duplicatedVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String duplicatedSdIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, List.of(disclosureHash, disclosureHash));
		final String duplicatedSdPresentation = duplicatedSdIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String duplicatedSdKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(duplicatedSdPresentation));
		final SdJwtVerifiableCredential duplicatedSdVc = SdJwtVerifiableCredential.parse(
				duplicatedSdPresentation + duplicatedSdKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(duplicatedSdVc, trust,
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
		return signedIssuerJwt(issuerKp, issuerCert, holderJwk, List.of(sdHash));
	}

	private static String signedIssuerJwt(final KeyPair issuerKp,
			final X509Certificate issuerCert, final RSAKey holderJwk,
			final List<String> sdHashes) throws Exception {
		return signedIssuerJwt(issuerKp, issuerCert, holderJwk, sdHashes,
				Date.from(Instant.now().plus(Duration.ofDays(1))));
	}

	private static String signedIssuerJwt(final KeyPair issuerKp,
			final X509Certificate issuerCert, final RSAKey holderJwk,
			final String sdHash, final Date expirationTime) throws Exception {
		return signedIssuerJwt(issuerKp, issuerCert, holderJwk, List.of(sdHash), expirationTime);
	}

	private static String signedIssuerJwt(final KeyPair issuerKp,
			final X509Certificate issuerCert, final RSAKey holderJwk,
			final List<String> sdHashes, final Date expirationTime) throws Exception {
		final SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.RS256)
						.x509CertChain(List.of(com.nimbusds.jose.util.Base64
								.encode(issuerCert.getEncoded())))
						.build(),
				new JWTClaimsSet.Builder()
						.issuer("https://issuer.example.es") //$NON-NLS-1$
						.subject("pid-1") //$NON-NLS-1$
						.expirationTime(expirationTime)
						.claim("_sd_alg", "sha-256") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("_sd", sdHashes) //$NON-NLS-1$
						.claim("cnf", Map.of("jwk", holderJwk.toPublicJWK().toJSONObject())) //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		jwt.sign(new RSASSASigner(issuerKp.getPrivate()));
		return jwt.serialize();
	}

	private static String signedKeyBindingJwt(final KeyPair holderKp,
			final String audience, final String nonce, final String sdHash) throws Exception {
		return signedKeyBindingJwt(holderKp, audience, nonce, sdHash, true);
	}

	private static String signedKeyBindingJwt(final KeyPair holderKp,
			final String audience, final String nonce, final String sdHash,
			final boolean typed) throws Exception {
		return signedKeyBindingJwt(holderKp, audience, nonce, sdHash, typed, null, null);
	}

	private static String signedKeyBindingJwt(final KeyPair holderKp,
			final String audience, final String nonce, final String sdHash,
			final boolean typed, final Date expirationTime, final Date notBeforeTime)
			throws Exception {
		final JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);
		if (typed) {
			headerBuilder.type(new JOSEObjectType("kb+jwt")); //$NON-NLS-1$
		}
		final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
				.audience(audience)
				.issueTime(new Date())
				.claim("nonce", nonce) //$NON-NLS-1$
				.claim("sd_hash", sdHash); //$NON-NLS-1$
		if (expirationTime != null) {
			claims.expirationTime(expirationTime);
		}
		if (notBeforeTime != null) {
			claims.notBeforeTime(notBeforeTime);
		}
		final SignedJWT jwt = new SignedJWT(
				headerBuilder.build(),
				claims.build());
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
		return issuedBy(issuerKp, issuerCert, subjectKp, subjectDn,
				now, now.plus(Duration.ofDays(365)));
	}

	private static X509Certificate issuedBy(final KeyPair issuerKp,
			final X509Certificate issuerCert, final KeyPair subjectKp,
			final String subjectDn, final Instant notBefore, final Instant notAfter) throws Exception {
		final X500Name issuer = X500Name.getInstance(
				issuerCert.getSubjectX500Principal().getEncoded());
		final X500Name subject = new X500Name(subjectDn);
		final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA") //$NON-NLS-1$
				.build(issuerKp.getPrivate());
		final X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
				issuer, BigInteger.valueOf(System.currentTimeMillis() + 1),
				Date.from(notBefore), Date.from(notAfter),
				subject, subjectKp.getPublic())
				.build(signer);
		return (X509Certificate) CertificateFactory.getInstance("X.509") //$NON-NLS-1$
				.generateCertificate(new java.io.ByteArrayInputStream(holder.getEncoded()));
	}
}
