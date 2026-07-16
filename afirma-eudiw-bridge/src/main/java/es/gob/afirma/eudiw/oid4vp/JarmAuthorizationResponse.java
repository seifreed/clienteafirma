/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.oid4vp;

import java.text.ParseException;
import java.util.Objects;

import com.nimbusds.jose.JOSEException;
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
		Objects.requireNonNull(responseJwt, "responseJwt"); //$NON-NLS-1$
		Objects.requireNonNull(verifier, "verifier"); //$NON-NLS-1$
		final SignedJWT jwt = SignedJWT.parse(responseJwt);
		if (!jwt.verify(verifier)) {
			throw new JOSEException("Firma JARM inválida"); //$NON-NLS-1$
		}
		final JWTClaimsSet claims = jwt.getJWTClaimsSet();
		if (expectedAudience != null && !claims.getAudience().contains(expectedAudience)) {
			throw new JOSEException("Audience JARM inválida"); //$NON-NLS-1$
		}
		if (expectedState != null && !expectedState.equals(claims.getStringClaim("state"))) { //$NON-NLS-1$
			throw new JOSEException("State JARM inválido"); //$NON-NLS-1$
		}
		return new JarmAuthorizationResponse(
				claims.getStringClaim("vp_token"), //$NON-NLS-1$
				claims.getStringClaim("state"), //$NON-NLS-1$
				claims.getStringClaim("presentation_submission")); //$NON-NLS-1$
	}
}
