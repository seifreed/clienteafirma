/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.sdjwt;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import es.gob.afirma.trust.tsl.TrustListService;
import es.gob.afirma.trust.tsl.TrustServiceProvider;

/** Verificador local de SD-JWT VC contra TSL y Key Binding JWT. */
public final class SdJwtVerifier {

	private static final JOSEObjectType KEY_BINDING_TYPE = new JOSEObjectType("kb+jwt"); //$NON-NLS-1$

	private SdJwtVerifier() {
		// No instanciable.
	}

	public static TrustServiceProvider verify(final SdJwtVerifiableCredential vc,
			final TrustListService trust, final String audience, final String nonce)
			throws SdJwtVerificationException {
		try {
			final X509Certificate issuerCert = issuerCertificate(vc.issuerSignedJwt());
			issuerCert.checkValidity();
			if (!vc.issuerSignedJwt().verify(verifier(issuerCert))) {
				throw new SdJwtVerificationException("Firma del issuer JWT inválida"); //$NON-NLS-1$
			}
			verifyIssuerValidity(vc.issuerSignedJwt().getJWTClaimsSet());
			final TrustServiceProvider provider = trust.findIssuer(issuerCert)
					.orElseThrow(() -> new SdJwtVerificationException(
							"Certificado emisor SD-JWT VC no encontrado en TSL")); //$NON-NLS-1$
			verifyDisclosures(vc);
			verifyKeyBinding(vc, vc.keyBindingJwt()
					.orElseThrow(() -> new SdJwtVerificationException(
							"Key Binding JWT ausente")), audience, nonce); //$NON-NLS-1$
			return provider;
		}
		catch (final SdJwtVerificationException e) {
			throw e;
		}
		catch (final Exception e) {
			throw new SdJwtVerificationException("Error verificando SD-JWT VC", e); //$NON-NLS-1$
		}
	}

	private static void verifyIssuerValidity(final JWTClaimsSet claims)
			throws SdJwtVerificationException {
		final Date now = new Date();
		final Date expirationTime = claims.getExpirationTime();
		if (expirationTime != null && !expirationTime.after(now)) {
			throw new SdJwtVerificationException("Issuer JWT caducado"); //$NON-NLS-1$
		}
		final Date notBeforeTime = claims.getNotBeforeTime();
		if (notBeforeTime != null && notBeforeTime.after(now)) {
			throw new SdJwtVerificationException("Issuer JWT no válido aún"); //$NON-NLS-1$
		}
	}

	private static X509Certificate issuerCertificate(final SignedJWT jwt)
			throws Exception {
		final List<com.nimbusds.jose.util.Base64> chain = jwt.getHeader().getX509CertChain();
		if (chain == null || chain.isEmpty()) {
			throw new SdJwtVerificationException("Issuer JWT sin cadena x5c"); //$NON-NLS-1$
		}
		final X509Certificate cert = X509CertUtils.parse(chain.get(0).decode());
		if (cert != null) {
			return cert;
		}
		return (X509Certificate) CertificateFactory.getInstance("X.509") //$NON-NLS-1$
				.generateCertificate(new ByteArrayInputStream(chain.get(0).decode()));
	}

	private static JWSVerifier verifier(final X509Certificate cert) throws Exception {
		final var publicKey = cert.getPublicKey();
		if (publicKey instanceof java.security.interfaces.RSAPublicKey rsa) {
			return new RSASSAVerifier(rsa);
		}
		if (publicKey instanceof java.security.interfaces.ECPublicKey ec) {
			return new ECDSAVerifier(ec);
		}
		throw new SdJwtVerificationException(
				"Clave pública de issuer no soportada: " + publicKey.getAlgorithm()); //$NON-NLS-1$
	}

	private static void verifyDisclosures(final SdJwtVerifiableCredential vc)
			throws Exception {
		final JWTClaimsSet claims = vc.issuerSignedJwt().getJWTClaimsSet();
		final String alg = claims.getStringClaim("_sd_alg"); //$NON-NLS-1$
		if (alg != null && !"sha-256".equalsIgnoreCase(alg)) { //$NON-NLS-1$
			throw new SdJwtVerificationException("Algoritmo _sd no soportado: " + alg); //$NON-NLS-1$
		}
		final List<String> expected = claims.getStringListClaim("_sd"); //$NON-NLS-1$
		if (expected == null) {
			throw new SdJwtVerificationException("Issuer JWT sin claim _sd"); //$NON-NLS-1$
		}
		final MessageDigest sha256 = MessageDigest.getInstance("SHA-256"); //$NON-NLS-1$
		for (final String disclosure : vc.disclosures()) {
			final byte[] decoded;
			try {
				decoded = Base64.getUrlDecoder().decode(disclosure);
			}
			catch (final IllegalArgumentException e) {
				throw new SdJwtVerificationException("Disclosure no es base64url válido", e); //$NON-NLS-1$
			}
			if (JSONArrayUtils.parse(new String(decoded, StandardCharsets.UTF_8)).size() < 2) {
				throw new SdJwtVerificationException("Disclosure SD-JWT no es array JSON válido"); //$NON-NLS-1$
			}
			final String digest = Base64.getUrlEncoder().withoutPadding().encodeToString(
					sha256.digest(disclosure.getBytes(StandardCharsets.US_ASCII)));
			if (!expected.contains(digest)) {
				throw new SdJwtVerificationException(
						"Disclosure no referenciada por _sd: " + digest); //$NON-NLS-1$
			}
		}
	}

	private static void verifyKeyBinding(final SdJwtVerifiableCredential vc, final SignedJWT kbJwt,
			final String audience, final String nonce) throws Exception {
		final SignedJWT issuerJwt = vc.issuerSignedJwt();
		final JWK holderKey = holderKey(issuerJwt);
		if (!kbJwt.verify(verifier(holderKey))) {
			throw new SdJwtVerificationException("Firma Key Binding JWT inválida"); //$NON-NLS-1$
		}
		if (!KEY_BINDING_TYPE.equals(kbJwt.getHeader().getType())) {
			throw new SdJwtVerificationException("Tipo Key Binding JWT inválido"); //$NON-NLS-1$
		}
		final JWTClaimsSet claims = kbJwt.getJWTClaimsSet();
		final Date issueTime = claims.getIssueTime();
		if (issueTime == null) {
			throw new SdJwtVerificationException("Key Binding JWT sin iat"); //$NON-NLS-1$
		}
		if (!claims.getAudience().contains(audience)) {
			throw new SdJwtVerificationException("Audience Key Binding JWT inválida"); //$NON-NLS-1$
		}
		if (!nonce.equals(claims.getStringClaim("nonce"))) { //$NON-NLS-1$
			throw new SdJwtVerificationException("Nonce Key Binding JWT inválido"); //$NON-NLS-1$
		}
		final String expectedHash = sdHash(vc);
		if (!expectedHash.equals(claims.getStringClaim("sd_hash"))) { //$NON-NLS-1$
			throw new SdJwtVerificationException("sd_hash Key Binding JWT inválido"); //$NON-NLS-1$
		}
	}

	private static String sdHash(final SdJwtVerifiableCredential vc) throws Exception {
		final JWTClaimsSet claims = vc.issuerSignedJwt().getJWTClaimsSet();
		final String alg = claims.getStringClaim("_sd_alg"); //$NON-NLS-1$
		if (alg != null && !"sha-256".equalsIgnoreCase(alg)) { //$NON-NLS-1$
			throw new SdJwtVerificationException("Algoritmo _sd no soportado: " + alg); //$NON-NLS-1$
		}
		final StringBuilder encoded = new StringBuilder(vc.issuerSignedJwt().serialize()).append('~');
		for (final String disclosure : vc.disclosures()) {
			encoded.append(disclosure).append('~');
		}
		return Base64.getUrlEncoder().withoutPadding().encodeToString(
				MessageDigest.getInstance("SHA-256").digest( //$NON-NLS-1$
						encoded.toString().getBytes(StandardCharsets.US_ASCII)));
	}

	private static JWK holderKey(final SignedJWT issuerJwt)
			throws ParseException, SdJwtVerificationException {
		final Object cnf = issuerJwt.getJWTClaimsSet().getClaim("cnf"); //$NON-NLS-1$
		if (!(cnf instanceof Map<?, ?> cnfMap)) {
			throw new SdJwtVerificationException("Issuer JWT sin cnf.jwk"); //$NON-NLS-1$
		}
		final Map<String, Object> cnfJson = new LinkedHashMap<>();
		for (final Map.Entry<?, ?> entry : cnfMap.entrySet()) {
			if (!(entry.getKey() instanceof String key)) {
				throw new SdJwtVerificationException("cnf contiene claves no textuales"); //$NON-NLS-1$
			}
			cnfJson.put(key, entry.getValue());
		}
		return JWK.parse(JSONObjectUtils.getJSONObject(cnfJson, "jwk")); //$NON-NLS-1$
	}

	private static JWSVerifier verifier(final JWK jwk) throws Exception {
		final JWSAlgorithm alg = JWSAlgorithm.parse(jwk.getAlgorithm() != null
				? jwk.getAlgorithm().getName() : JWSAlgorithm.RS256.getName());
		if (jwk instanceof RSAKey rsa) {
			return new RSASSAVerifier(rsa.toRSAPublicKey());
		}
		if (jwk instanceof ECKey ec) {
			return new ECDSAVerifier(ec.toECPublicKey());
		}
		throw new SdJwtVerificationException("cnf.jwk no soportado: " + alg); //$NON-NLS-1$
	}
}
