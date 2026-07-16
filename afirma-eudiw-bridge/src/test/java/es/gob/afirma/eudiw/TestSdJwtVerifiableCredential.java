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
import java.util.ArrayList;
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
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse(" " + makeUnsignedJwt() + "~")); //$NON-NLS-1$ //$NON-NLS-2$
		final String disclosure = Base64.getUrlEncoder().withoutPadding()
				.encodeToString(DISCLOSURE_JSON.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse(makeUnsignedJwt() + "~" + disclosure)); //$NON-NLS-1$
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse(makeUnsignedJwt() + "~ " + disclosure + "~")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse(makeUnsignedJwt() + "~" //$NON-NLS-1$
				+ disclosure.substring(0, 4) + "\n" + disclosure.substring(4) + "~")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse(makeUnsignedJwt() + "~abc.def~")); //$NON-NLS-1$
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse(makeUnsignedJwt() + "~abc=~")); //$NON-NLS-1$
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse(makeUnsignedJwt() + "~not-base64url!!~")); //$NON-NLS-1$
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
				.privateKey((java.security.interfaces.RSAPrivateKey) holderKp.getPrivate())
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
				() -> SdJwtVerifier.verify(null, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(vc, null,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(vc, trust, " ", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(vc, trust, " https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(vc, trust, "https://verifier\n.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(vc, trust,
						"https://verifier.example.es", " ")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(vc, trust,
						"https://verifier.example.es", " nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(vc, trust,
						"https://verifier.example.es", "non\nce-1")); //$NON-NLS-1$ //$NON-NLS-2$
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
		final String mismatchedAlgKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", presentationHash(presentation), //$NON-NLS-1$ //$NON-NLS-2$
				true, Date.from(Instant.now().plus(Duration.ofMinutes(5))), null, new Date(),
				JWSAlgorithm.RS512);
		final SdJwtVerifiableCredential mismatchedAlgVc = SdJwtVerifiableCredential.parse(
				presentation + mismatchedAlgKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(mismatchedAlgVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final SignedJWT validIssuerJwt = SignedJWT.parse(issuerJwt);
		final SignedJWT symmetricIssuerJwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.HS256)
						.type(new JOSEObjectType("dc+sd-jwt")) //$NON-NLS-1$
						.x509CertChain(validIssuerJwt.getHeader().getX509CertChain())
						.build(),
				validIssuerJwt.getJWTClaimsSet());
		symmetricIssuerJwt.sign(new MACSigner("01234567890123456789012345678901")); //$NON-NLS-1$
		final SdJwtVerifiableCredential symmetricIssuerVc = SdJwtVerifiableCredential.parse(
				symmetricIssuerJwt.serialize() + "~" + disclosure + "~" + kbJwt); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(symmetricIssuerVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final SignedJWT validKbJwt = SignedJWT.parse(kbJwt);
		final SignedJWT symmetricKbJwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.HS256)
						.type(new JOSEObjectType("kb+jwt")) //$NON-NLS-1$
						.build(),
				validKbJwt.getJWTClaimsSet());
		symmetricKbJwt.sign(new MACSigner("01234567890123456789012345678901")); //$NON-NLS-1$
		final SdJwtVerifiableCredential symmetricKbVc = SdJwtVerifiableCredential.parse(
				presentation + symmetricKbJwt.serialize());
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(symmetricKbVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final SignedJWT noHolderJwkIssuerJwt = new SignedJWT(
				validIssuerJwt.getHeader(),
				new JWTClaimsSet.Builder(validIssuerJwt.getJWTClaimsSet())
						.claim("cnf", Map.of()) //$NON-NLS-1$
						.build());
		noHolderJwkIssuerJwt.sign(new RSASSASigner(issuerKp.getPrivate()));
		final String noHolderJwkPresentation = noHolderJwkIssuerJwt.serialize() + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String noHolderJwkKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(noHolderJwkPresentation));
		final SdJwtVerifiableCredential noHolderJwkVc = SdJwtVerifiableCredential.parse(
				noHolderJwkPresentation + noHolderJwkKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(noHolderJwkVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final SignedJWT controlCnfKeyIssuerJwt = new SignedJWT(
				validIssuerJwt.getHeader(),
				new JWTClaimsSet.Builder(validIssuerJwt.getJWTClaimsSet())
						.claim("cnf", Map.of( //$NON-NLS-1$
								"jwk", holderJwk.toPublicJWK().toJSONObject(), //$NON-NLS-1$
								"jw\nk", "x")) //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		controlCnfKeyIssuerJwt.sign(new RSASSASigner(issuerKp.getPrivate()));
		final String controlCnfKeyPresentation = controlCnfKeyIssuerJwt.serialize()
				+ "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String controlCnfKeyKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(controlCnfKeyPresentation));
		final SdJwtVerifiableCredential controlCnfKeyVc = SdJwtVerifiableCredential.parse(
				controlCnfKeyPresentation + controlCnfKeyKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(controlCnfKeyVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final RSAKey controlKidHolderJwk = new RSAKey.Builder(
				(java.security.interfaces.RSAPublicKey) holderKp.getPublic())
				.algorithm(JWSAlgorithm.RS256)
				.keyID("holder\n1") //$NON-NLS-1$
				.build();
		final String controlKidIssuerJwt = signedIssuerJwt(issuerKp, issuerCert, controlKidHolderJwk,
				disclosureHash);
		final String controlKidPresentation = controlKidIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String controlKidKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(controlKidPresentation));
		final SdJwtVerifiableCredential controlKidVc = SdJwtVerifiableCredential.parse(
				controlKidPresentation + controlKidKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(controlKidVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String blankNonceKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", " ", presentationHash(presentation)); //$NON-NLS-1$ //$NON-NLS-2$
		final SdJwtVerifiableCredential blankNonceKbVc = SdJwtVerifiableCredential.parse(
				presentation + blankNonceKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(blankNonceKbVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String unnormalizedNonceKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", " nonce-1", presentationHash(presentation)); //$NON-NLS-1$ //$NON-NLS-2$
		final SdJwtVerifiableCredential unnormalizedNonceKbVc = SdJwtVerifiableCredential.parse(
				presentation + unnormalizedNonceKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(unnormalizedNonceKbVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String controlNonceKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "non\nce-1", presentationHash(presentation)); //$NON-NLS-1$ //$NON-NLS-2$
		final SdJwtVerifiableCredential controlNonceKbVc = SdJwtVerifiableCredential.parse(
				presentation + controlNonceKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(controlNonceKbVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String noAudienceKbJwt = signedKeyBindingJwt(holderKp,
				List.of(), "nonce-1", presentationHash(presentation)); //$NON-NLS-1$
		final SdJwtVerifiableCredential noAudienceKbVc = SdJwtVerifiableCredential.parse(
				presentation + noAudienceKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(noAudienceKbVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String unnormalizedAudienceKbJwt = signedKeyBindingJwt(holderKp,
				List.of("https://verifier.example.es", " other"), "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				presentationHash(presentation));
		final SdJwtVerifiableCredential unnormalizedAudienceKbVc = SdJwtVerifiableCredential.parse(
				presentation + unnormalizedAudienceKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(unnormalizedAudienceKbVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String controlAudienceKbJwt = signedKeyBindingJwt(holderKp,
				List.of("https://verifier.example.es", "oth\ner"), "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				presentationHash(presentation));
		final SdJwtVerifiableCredential controlAudienceKbVc = SdJwtVerifiableCredential.parse(
				presentation + controlAudienceKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(controlAudienceKbVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String noExpirationKb = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", presentationHash(presentation), //$NON-NLS-1$ //$NON-NLS-2$
				true, null, null);
		final SdJwtVerifiableCredential noExpirationKbVc = SdJwtVerifiableCredential.parse(
				presentation + noExpirationKb);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(noExpirationKbVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String futureIatKb = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", presentationHash(presentation), //$NON-NLS-1$ //$NON-NLS-2$
				true, Date.from(Instant.now().plus(Duration.ofMinutes(5))), null,
				Date.from(Instant.now().plus(Duration.ofMinutes(1))));
		final SdJwtVerifiableCredential futureIatKbVc = SdJwtVerifiableCredential.parse(
				presentation + futureIatKb);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(futureIatKbVc, trust,
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
		final String noExpirationIssuerJwt = signedIssuerJwt(issuerKp, issuerCert, holderJwk,
				disclosureHash, null);
		final String noExpirationPresentation = noExpirationIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String noExpirationKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(noExpirationPresentation));
		final SdJwtVerifiableCredential noExpirationVc = SdJwtVerifiableCredential.parse(
				noExpirationPresentation + noExpirationKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(noExpirationVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String futureIatIssuerJwt = signedIssuerJwt(issuerKp, issuerCert, holderJwk,
				disclosureHash, Date.from(Instant.now().plus(Duration.ofDays(1))),
				true, Date.from(Instant.now().plus(Duration.ofMinutes(1))));
		final String futureIatPresentation = futureIatIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String futureIatKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(futureIatPresentation));
		final SdJwtVerifiableCredential futureIatVc = SdJwtVerifiableCredential.parse(
				futureIatPresentation + futureIatKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(futureIatVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String untypedIssuerJwt = signedIssuerJwt(issuerKp, issuerCert, holderJwk,
				List.of(disclosureHash), Date.from(Instant.now().plus(Duration.ofDays(1))),
				true, null, List.of(issuerCert), false);
		final String untypedIssuerPresentation = untypedIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String untypedIssuerKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(untypedIssuerPresentation));
		final SdJwtVerifiableCredential untypedIssuerVc = SdJwtVerifiableCredential.parse(
				untypedIssuerPresentation + untypedIssuerKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(untypedIssuerVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String noIssuerJwt = signedIssuerJwt(issuerKp, issuerCert, holderJwk,
				List.of(disclosureHash), Date.from(Instant.now().plus(Duration.ofDays(1))),
				true, null, List.of(issuerCert), true, null);
		final String noIssuerPresentation = noIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String noIssuerKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(noIssuerPresentation));
		final SdJwtVerifiableCredential noIssuerVc = SdJwtVerifiableCredential.parse(
				noIssuerPresentation + noIssuerKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(noIssuerVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String unnormalizedIssuerJwt = signedIssuerJwt(issuerKp, issuerCert, holderJwk,
				List.of(disclosureHash), Date.from(Instant.now().plus(Duration.ofDays(1))),
				true, null, List.of(issuerCert), true, " https://issuer.example.es"); //$NON-NLS-1$
		final String unnormalizedIssuerPresentation = unnormalizedIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String unnormalizedIssuerKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(unnormalizedIssuerPresentation));
		final SdJwtVerifiableCredential unnormalizedIssuerVc = SdJwtVerifiableCredential.parse(
				unnormalizedIssuerPresentation + unnormalizedIssuerKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(unnormalizedIssuerVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String controlIssuerJwt = signedIssuerJwt(issuerKp, issuerCert, holderJwk,
				List.of(disclosureHash), Date.from(Instant.now().plus(Duration.ofDays(1))),
				true, null, List.of(issuerCert), true, "https://issuer\n.example.es"); //$NON-NLS-1$
		final String controlIssuerPresentation = controlIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String controlIssuerKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(controlIssuerPresentation));
		final SdJwtVerifiableCredential controlIssuerVc = SdJwtVerifiableCredential.parse(
				controlIssuerPresentation + controlIssuerKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(controlIssuerVc, trust,
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

		final X509Certificate expiredExtraX5c = selfSigned(kpg.generateKeyPair(),
				"CN=EUDI Expired Extra, O=AEAD", expiredCertTime, //$NON-NLS-1$
				expiredCertTime.plus(Duration.ofDays(1)));
		final String expiredChainIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, List.of(disclosureHash), Date.from(Instant.now().plus(Duration.ofDays(1))),
				true, null, List.of(issuerCert, expiredExtraX5c));
		final String expiredChainPresentation = expiredChainIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String expiredChainKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(expiredChainPresentation));
		final SdJwtVerifiableCredential expiredChainVc = SdJwtVerifiableCredential.parse(
				expiredChainPresentation + expiredChainKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(expiredChainVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final X509Certificate unrelatedExtraX5c = selfSigned(kpg.generateKeyPair(),
				"CN=EUDI Unrelated Extra, O=AEAD"); //$NON-NLS-1$
		final String unlinkedChainIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, List.of(disclosureHash), Date.from(Instant.now().plus(Duration.ofDays(1))),
				true, null, List.of(issuerCert, unrelatedExtraX5c));
		final String unlinkedChainPresentation = unlinkedChainIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String unlinkedChainKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(unlinkedChainPresentation));
		final SdJwtVerifiableCredential unlinkedChainVc = SdJwtVerifiableCredential.parse(
				unlinkedChainPresentation + unlinkedChainKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(unlinkedChainVc, trust,
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

		final String blankNameDisclosure = Base64.getUrlEncoder().withoutPadding()
				.encodeToString("[\"salt\",\" \",\"García\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8)); //$NON-NLS-1$
		final String blankNameIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, disclosureHash(blankNameDisclosure));
		final String blankNamePresentation = blankNameIssuerJwt + "~" + blankNameDisclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String blankNameKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(blankNamePresentation));
		final SdJwtVerifiableCredential blankNameVc = SdJwtVerifiableCredential.parse(
				blankNamePresentation + blankNameKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(blankNameVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String controlNameDisclosure = Base64.getUrlEncoder().withoutPadding()
				.encodeToString("[\"salt\",\"family\\nname\",\"García\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8)); //$NON-NLS-1$
		final String controlNameIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, disclosureHash(controlNameDisclosure));
		final String controlNamePresentation = controlNameIssuerJwt + "~" + controlNameDisclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String controlNameKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(controlNamePresentation));
		final SdJwtVerifiableCredential controlNameVc = SdJwtVerifiableCredential.parse(
				controlNamePresentation + controlNameKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(controlNameVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final String controlSdIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, List.of(disclosureHash.substring(0, 8) + "\n" + disclosureHash.substring(8))); //$NON-NLS-1$
		final String controlSdPresentation = controlSdIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String controlSdKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(controlSdPresentation));
		final SdJwtVerifiableCredential controlSdVc = SdJwtVerifiableCredential.parse(
				controlSdPresentation + controlSdKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(controlSdVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String unnormalizedSaltDisclosure = Base64.getUrlEncoder().withoutPadding()
				.encodeToString("[\" salt\",\"family_name\",\"García\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8)); //$NON-NLS-1$
		final String unnormalizedSaltIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, disclosureHash(unnormalizedSaltDisclosure));
		final String unnormalizedSaltPresentation = unnormalizedSaltIssuerJwt + "~" + unnormalizedSaltDisclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String unnormalizedSaltKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(unnormalizedSaltPresentation));
		final SdJwtVerifiableCredential unnormalizedSaltVc = SdJwtVerifiableCredential.parse(
				unnormalizedSaltPresentation + unnormalizedSaltKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(unnormalizedSaltVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String unnormalizedNameDisclosure = Base64.getUrlEncoder().withoutPadding()
				.encodeToString("[\"salt\",\" family_name\",\"García\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8)); //$NON-NLS-1$
		final String unnormalizedNameIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, disclosureHash(unnormalizedNameDisclosure));
		final String unnormalizedNamePresentation = unnormalizedNameIssuerJwt + "~" + unnormalizedNameDisclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String unnormalizedNameKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(unnormalizedNamePresentation));
		final SdJwtVerifiableCredential unnormalizedNameVc = SdJwtVerifiableCredential.parse(
				unnormalizedNamePresentation + unnormalizedNameKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(unnormalizedNameVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String longDisclosure = Base64.getUrlEncoder().withoutPadding()
				.encodeToString("[\"salt\",\"family_name\",\"García\",\"extra\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8)); //$NON-NLS-1$
		final String longDisclosureIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, disclosureHash(longDisclosure));
		final String longDisclosurePresentation = longDisclosureIssuerJwt + "~" + longDisclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String longDisclosureKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(longDisclosurePresentation));
		final SdJwtVerifiableCredential longDisclosureVc = SdJwtVerifiableCredential.parse(
				longDisclosurePresentation + longDisclosureKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(longDisclosureVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String duplicatedPresentation = issuerJwt + "~" + disclosure + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		final String duplicatedKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", presentationHash(duplicatedPresentation)); //$NON-NLS-1$ //$NON-NLS-2$
		final SdJwtVerifiableCredential duplicatedVc = SdJwtVerifiableCredential.parse(
				duplicatedPresentation + duplicatedKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(duplicatedVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String sameClaimDisclosure = Base64.getUrlEncoder().withoutPadding()
				.encodeToString("[\"otra-sal\",\"family_name\",\"López\"]".getBytes(java.nio.charset.StandardCharsets.UTF_8)); //$NON-NLS-1$
		final String sameClaimIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, List.of(disclosureHash, disclosureHash(sameClaimDisclosure)));
		final String sameClaimPresentation = sameClaimIssuerJwt + "~" + disclosure + "~" + sameClaimDisclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		final String sameClaimKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(sameClaimPresentation));
		final SdJwtVerifiableCredential sameClaimVc = SdJwtVerifiableCredential.parse(
				sameClaimPresentation + sameClaimKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(sameClaimVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String missingDisclosureIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, List.of(disclosureHash, disclosureHash(sameClaimDisclosure)));
		final String missingDisclosurePresentation = missingDisclosureIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String missingDisclosureKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(missingDisclosurePresentation));
		final SdJwtVerifiableCredential missingDisclosureVc = SdJwtVerifiableCredential.parse(
				missingDisclosurePresentation + missingDisclosureKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(missingDisclosureVc, trust,
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

		final String blankSdIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, List.of("")); //$NON-NLS-1$
		final String blankSdPresentation = blankSdIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String blankSdKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(blankSdPresentation));
		final SdJwtVerifiableCredential blankSdVc = SdJwtVerifiableCredential.parse(
				blankSdPresentation + blankSdKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(blankSdVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String emptySdIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, List.of());
		final String emptySdPresentation = emptySdIssuerJwt + "~"; //$NON-NLS-1$
		final String emptySdKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(emptySdPresentation));
		final SdJwtVerifiableCredential emptySdVc = SdJwtVerifiableCredential.parse(
				emptySdPresentation + emptySdKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(emptySdVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String unnormalizedSdIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, List.of(" " + disclosureHash)); //$NON-NLS-1$
		final String unnormalizedSdPresentation = unnormalizedSdIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String unnormalizedSdKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(unnormalizedSdPresentation));
		final SdJwtVerifiableCredential unnormalizedSdVc = SdJwtVerifiableCredential.parse(
				unnormalizedSdPresentation + unnormalizedSdKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(unnormalizedSdVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String shortSdIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, List.of("YWJj")); //$NON-NLS-1$
		final String shortSdPresentation = shortSdIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String shortSdKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(shortSdPresentation));
		final SdJwtVerifiableCredential shortSdVc = SdJwtVerifiableCredential.parse(
				shortSdPresentation + shortSdKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(shortSdVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String privateHolderIssuerJwt = signedIssuerJwt(issuerKp, issuerCert,
				holderJwk, disclosureHash, Date.from(Instant.now().plus(Duration.ofDays(1))), false);
		final String privateHolderPresentation = privateHolderIssuerJwt + "~" + disclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String privateHolderKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(privateHolderPresentation));
		final SdJwtVerifiableCredential privateHolderVc = SdJwtVerifiableCredential.parse(
				privateHolderPresentation + privateHolderKbJwt);
		assertThrows(SdJwtVerificationException.class,
				() -> SdJwtVerifier.verify(privateHolderVc, trust,
						"https://verifier.example.es", "nonce-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final String paddedDisclosure = Base64.getUrlEncoder()
				.encodeToString(DISCLOSURE_JSON.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		final String paddedIssuerJwt = signedIssuerJwt(issuerKp, issuerCert, holderJwk,
				disclosureHash(paddedDisclosure));
		final String paddedPresentation = paddedIssuerJwt + "~" + paddedDisclosure + "~"; //$NON-NLS-1$ //$NON-NLS-2$
		final String paddedKbJwt = signedKeyBindingJwt(holderKp,
				"https://verifier.example.es", "nonce-1", //$NON-NLS-1$ //$NON-NLS-2$
				presentationHash(paddedPresentation));
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse(
				paddedPresentation + paddedKbJwt));

		final String badDisclosure = "not-base64url!!"; //$NON-NLS-1$
		final String badIssuerJwt = signedIssuerJwt(issuerKp, issuerCert, holderJwk,
				disclosureHash(badDisclosure));
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse(
				badIssuerJwt + "~" + badDisclosure + "~" + kbJwt)); //$NON-NLS-1$ //$NON-NLS-2$
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
		return signedIssuerJwt(issuerKp, issuerCert, holderJwk, sdHash, expirationTime, true);
	}

	private static String signedIssuerJwt(final KeyPair issuerKp,
			final X509Certificate issuerCert, final RSAKey holderJwk,
			final String sdHash, final Date expirationTime,
			final boolean publicHolderJwk) throws Exception {
		return signedIssuerJwt(issuerKp, issuerCert, holderJwk, List.of(sdHash),
				expirationTime, publicHolderJwk);
	}

	private static String signedIssuerJwt(final KeyPair issuerKp,
			final X509Certificate issuerCert, final RSAKey holderJwk,
			final List<String> sdHashes, final Date expirationTime) throws Exception {
		return signedIssuerJwt(issuerKp, issuerCert, holderJwk, sdHashes,
				expirationTime, true);
	}

	private static String signedIssuerJwt(final KeyPair issuerKp,
			final X509Certificate issuerCert, final RSAKey holderJwk,
			final List<String> sdHashes, final Date expirationTime,
			final boolean publicHolderJwk) throws Exception {
		return signedIssuerJwt(issuerKp, issuerCert, holderJwk, sdHashes,
				expirationTime, publicHolderJwk, null);
	}

	private static String signedIssuerJwt(final KeyPair issuerKp,
			final X509Certificate issuerCert, final RSAKey holderJwk,
			final String sdHash, final Date expirationTime,
			final boolean publicHolderJwk, final Date issueTime) throws Exception {
		return signedIssuerJwt(issuerKp, issuerCert, holderJwk, List.of(sdHash),
				expirationTime, publicHolderJwk, issueTime);
	}

	private static String signedIssuerJwt(final KeyPair issuerKp,
			final X509Certificate issuerCert, final RSAKey holderJwk,
			final List<String> sdHashes, final Date expirationTime,
			final boolean publicHolderJwk, final Date issueTime) throws Exception {
		return signedIssuerJwt(issuerKp, issuerCert, holderJwk, sdHashes,
				expirationTime, publicHolderJwk, issueTime, List.of(issuerCert));
	}

	private static String signedIssuerJwt(final KeyPair issuerKp,
			final X509Certificate issuerCert, final RSAKey holderJwk,
			final List<String> sdHashes, final Date expirationTime,
			final boolean publicHolderJwk, final Date issueTime,
			final List<X509Certificate> x5cChain) throws Exception {
		return signedIssuerJwt(issuerKp, issuerCert, holderJwk, sdHashes,
				expirationTime, publicHolderJwk, issueTime, x5cChain, true);
	}

	private static String signedIssuerJwt(final KeyPair issuerKp,
			final X509Certificate issuerCert, final RSAKey holderJwk,
			final List<String> sdHashes, final Date expirationTime,
			final boolean publicHolderJwk, final Date issueTime,
			final List<X509Certificate> x5cChain, final boolean typed) throws Exception {
		return signedIssuerJwt(issuerKp, issuerCert, holderJwk, sdHashes,
				expirationTime, publicHolderJwk, issueTime, x5cChain, typed,
				"https://issuer.example.es"); //$NON-NLS-1$
	}

	private static String signedIssuerJwt(final KeyPair issuerKp,
			final X509Certificate issuerCert, final RSAKey holderJwk,
			final List<String> sdHashes, final Date expirationTime,
			final boolean publicHolderJwk, final Date issueTime,
			final List<X509Certificate> x5cChain, final boolean typed,
			final String issuer) throws Exception {
		final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
				.subject("pid-1") //$NON-NLS-1$
				.claim("_sd_alg", "sha-256") //$NON-NLS-1$ //$NON-NLS-2$
				.claim("_sd", sdHashes) //$NON-NLS-1$
				.claim("cnf", Map.of("jwk", (publicHolderJwk //$NON-NLS-1$ //$NON-NLS-2$
						? holderJwk.toPublicJWK() : holderJwk).toJSONObject()));
		if (issuer != null) {
			claims.issuer(issuer);
		}
		if (expirationTime != null) {
			claims.expirationTime(expirationTime);
		}
		if (issueTime != null) {
			claims.issueTime(issueTime);
		}
		final List<com.nimbusds.jose.util.Base64> x5c = new ArrayList<>();
		for (final X509Certificate cert : x5cChain) {
			x5c.add(com.nimbusds.jose.util.Base64.encode(cert.getEncoded()));
		}
		final JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.x509CertChain(x5c);
		if (typed) {
			header.type(new JOSEObjectType("dc+sd-jwt")); //$NON-NLS-1$
		}
		final SignedJWT jwt = new SignedJWT(
				header.build(),
				claims.build());
		jwt.sign(new RSASSASigner(issuerKp.getPrivate()));
		return jwt.serialize();
	}

	private static String signedKeyBindingJwt(final KeyPair holderKp,
			final String audience, final String nonce, final String sdHash) throws Exception {
		return signedKeyBindingJwt(holderKp, audience, nonce, sdHash, true);
	}

	private static String signedKeyBindingJwt(final KeyPair holderKp,
			final List<String> audiences, final String nonce, final String sdHash) throws Exception {
		final SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.RS256)
						.type(new JOSEObjectType("kb+jwt")) //$NON-NLS-1$
						.build(),
				new JWTClaimsSet.Builder()
						.audience(audiences)
						.issueTime(new Date())
						.expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
						.claim("nonce", nonce) //$NON-NLS-1$
						.claim("sd_hash", sdHash) //$NON-NLS-1$
						.build());
		jwt.sign(new RSASSASigner(holderKp.getPrivate()));
		return jwt.serialize();
	}

	private static String signedKeyBindingJwt(final KeyPair holderKp,
			final String audience, final String nonce, final String sdHash,
			final boolean typed) throws Exception {
		return signedKeyBindingJwt(holderKp, audience, nonce, sdHash, typed,
				Date.from(Instant.now().plus(Duration.ofMinutes(5))), null);
	}

	private static String signedKeyBindingJwt(final KeyPair holderKp,
			final String audience, final String nonce, final String sdHash,
			final boolean typed, final Date expirationTime, final Date notBeforeTime)
			throws Exception {
		return signedKeyBindingJwt(holderKp, audience, nonce, sdHash, typed,
				expirationTime, notBeforeTime, new Date());
	}

	private static String signedKeyBindingJwt(final KeyPair holderKp,
			final String audience, final String nonce, final String sdHash,
			final boolean typed, final Date expirationTime, final Date notBeforeTime,
			final Date issueTime)
			throws Exception {
		return signedKeyBindingJwt(holderKp, audience, nonce, sdHash, typed,
				expirationTime, notBeforeTime, issueTime, JWSAlgorithm.RS256);
	}

	private static String signedKeyBindingJwt(final KeyPair holderKp,
			final String audience, final String nonce, final String sdHash,
			final boolean typed, final Date expirationTime, final Date notBeforeTime,
			final Date issueTime, final JWSAlgorithm algorithm)
			throws Exception {
		final JWSHeader.Builder headerBuilder = new JWSHeader.Builder(algorithm);
		if (typed) {
			headerBuilder.type(new JOSEObjectType("kb+jwt")); //$NON-NLS-1$
		}
		final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
				.audience(audience)
				.issueTime(issueTime)
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
		return selfSigned(kp, subject, now, now.plus(Duration.ofDays(365)));
	}

	private static X509Certificate selfSigned(final KeyPair kp, final String subject,
			final Instant notBefore, final Instant notAfter)
			throws Exception {
		final X500Name dn = new X500Name(subject);
		final X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
				dn, BigInteger.valueOf(System.currentTimeMillis()),
				Date.from(notBefore), Date.from(notAfter),
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
