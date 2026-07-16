/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.oid4vp;

import java.text.ParseException;
import java.util.Date;
import java.util.Objects;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/** Respuesta OID4VP recibida mediante JARM ({@code direct_post.jwt}). */
public record JarmAuthorizationResponse(
		String vpToken,
		String state,
		String presentationSubmission) {

	/**
	 * Verifica firma, audience y state de una respuesta JARM.
	 */
	public static JarmAuthorizationResponse verify(final String responseJwt,
			final JWSVerifier verifier, final String expectedAudience,
			final String expectedState) throws ParseException, JOSEException {
		return verify(responseJwt, verifier, expectedAudience, expectedState, null);
	}

	/**
	 * Verifica firma, issuer, audience y state de una respuesta JARM.
	 */
	public static JarmAuthorizationResponse verify(final String responseJwt,
			final JWSVerifier verifier, final String expectedAudience,
			final String expectedState, final String expectedIssuer) throws ParseException, JOSEException {
		Objects.requireNonNull(responseJwt, "responseJwt"); //$NON-NLS-1$
		Objects.requireNonNull(verifier, "verifier"); //$NON-NLS-1$
		rejectBlankExpected(expectedAudience, "audience"); //$NON-NLS-1$
		rejectBlankExpected(expectedState, "state"); //$NON-NLS-1$
		rejectBlankExpected(expectedIssuer, "issuer"); //$NON-NLS-1$
		final SignedJWT jwt = SignedJWT.parse(responseJwt);
		if (!jwt.verify(verifier)) {
			throw new JOSEException("Firma JARM inválida"); //$NON-NLS-1$
		}
		final JWTClaimsSet claims = jwt.getJWTClaimsSet();
		verifyValidity(claims);
		if (expectedIssuer != null && !expectedIssuer.equals(claims.getIssuer())) {
			throw new JOSEException("Issuer JARM inválido"); //$NON-NLS-1$
		}
		if (claims.getAudience().isEmpty()) {
			throw new JOSEException("Audience JARM ausente"); //$NON-NLS-1$
		}
		if (expectedAudience != null && !claims.getAudience().contains(expectedAudience)) {
			throw new JOSEException("Audience JARM inválida"); //$NON-NLS-1$
		}
		if (expectedState != null && !expectedState.equals(claims.getStringClaim("state"))) { //$NON-NLS-1$
			throw new JOSEException("State JARM inválido"); //$NON-NLS-1$
		}
		final String vpToken = claims.getStringClaim("vp_token"); //$NON-NLS-1$
		if (vpToken == null || vpToken.isBlank()) {
			throw new JOSEException("Respuesta JARM sin vp_token"); //$NON-NLS-1$
		}
		final String presentationSubmission = claims.getStringClaim("presentation_submission"); //$NON-NLS-1$
		if (presentationSubmission != null) {
			if (presentationSubmission.isBlank()) {
				throw new JOSEException("presentation_submission JARM vacío"); //$NON-NLS-1$
			}
			try {
				JSONObjectUtils.parse(presentationSubmission);
			}
			catch (final ParseException e) {
				throw new JOSEException("presentation_submission JARM no es JSON válido", e); //$NON-NLS-1$
			}
		}
		return new JarmAuthorizationResponse(
				vpToken,
				claims.getStringClaim("state"), //$NON-NLS-1$
				presentationSubmission);
	}

	private static void verifyValidity(final JWTClaimsSet claims) throws JOSEException {
		final Date now = new Date();
		final Date expirationTime = claims.getExpirationTime();
		if (expirationTime != null && !expirationTime.after(now)) {
			throw new JOSEException("Respuesta JARM caducada"); //$NON-NLS-1$
		}
		final Date notBeforeTime = claims.getNotBeforeTime();
		if (notBeforeTime != null && notBeforeTime.after(now)) {
			throw new JOSEException("Respuesta JARM no válida aún"); //$NON-NLS-1$
		}
	}

	private static void rejectBlankExpected(final String value, final String claim)
			throws JOSEException {
		if (value != null && value.isBlank()) {
			throw new JOSEException("Valor esperado JARM vacío: " + claim); //$NON-NLS-1$
		}
	}
}
