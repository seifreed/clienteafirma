/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.oid4vp;

import java.text.ParseException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/** Respuesta OID4VP recibida mediante JARM ({@code direct_post.jwt}). */
public record JarmAuthorizationResponse(
		String vpToken,
		String state,
		String presentationSubmission) {

	private static final JOSEObjectType RESPONSE_TYPE =
			new JOSEObjectType("oauth-authz-resp+jwt"); //$NON-NLS-1$

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
		if (!RESPONSE_TYPE.equals(jwt.getHeader().getType())) {
			throw new JOSEException("Tipo JARM inválido"); //$NON-NLS-1$
		}
		final JWTClaimsSet claims = jwt.getJWTClaimsSet();
		verifyValidity(claims);
		final String issuer = claims.getIssuer();
		if (issuer == null || issuer.isBlank()) {
			throw new JOSEException("Issuer JARM ausente"); //$NON-NLS-1$
		}
		if (expectedIssuer != null && !expectedIssuer.equals(issuer)) {
			throw new JOSEException("Issuer JARM inválido"); //$NON-NLS-1$
		}
		if (claims.getAudience().isEmpty()) {
			throw new JOSEException("Audience JARM ausente"); //$NON-NLS-1$
		}
		if (expectedAudience != null && !claims.getAudience().contains(expectedAudience)) {
			throw new JOSEException("Audience JARM inválida"); //$NON-NLS-1$
		}
		final String state = claims.getStringClaim("state"); //$NON-NLS-1$
		if (state == null || state.isBlank()) {
			throw new JOSEException("State JARM ausente"); //$NON-NLS-1$
		}
		if (expectedState != null && !expectedState.equals(state)) {
			throw new JOSEException("State JARM inválido"); //$NON-NLS-1$
		}
		final String vpToken = normalizeJsonOrTextClaim(
				claims.getClaim("vp_token"), "vp_token"); //$NON-NLS-1$ //$NON-NLS-2$
		final String presentationSubmission = normalizePresentationSubmission(
				claims.getClaim("presentation_submission")); //$NON-NLS-1$
		return new JarmAuthorizationResponse(
				vpToken,
				state,
				presentationSubmission);
	}

	private static String normalizePresentationSubmission(final Object claim) throws JOSEException {
		if (claim == null) {
			return null;
		}
		return normalizeJsonObjectOrTextClaim(claim, "presentation_submission"); //$NON-NLS-1$
	}

	private static String normalizeJsonOrTextClaim(final Object claim, final String name) throws JOSEException {
		if (claim == null) {
			throw new JOSEException("Respuesta JARM sin " + name); //$NON-NLS-1$
		}
		if (claim instanceof String text) {
			if (text.isBlank()) {
				throw new JOSEException(name + " JARM vacío"); //$NON-NLS-1$
			}
			return text;
		}
		if (claim instanceof List<?> list) {
			if (list.isEmpty()) {
				throw new JOSEException(name + " JARM vacío"); //$NON-NLS-1$
			}
			return JSONArrayUtils.toJSONString(list);
		}
		if (claim instanceof Map<?, ?> map) {
			if (map.isEmpty()) {
				throw new JOSEException(name + " JARM vacío"); //$NON-NLS-1$
			}
			return JSONObjectUtils.toJSONString(stringKeyMap(map));
		}
		throw new JOSEException(name + " JARM no es JSON ni texto"); //$NON-NLS-1$
	}

	private static String normalizeJsonObjectOrTextClaim(final Object claim, final String name) throws JOSEException {
		if (claim instanceof String text) {
			if (text.isBlank()) {
				throw new JOSEException(name + " JARM vacío"); //$NON-NLS-1$
			}
			try {
				JSONObjectUtils.parse(text);
			}
			catch (final ParseException e) {
				throw new JOSEException(name + " JARM no es JSON válido", e); //$NON-NLS-1$
			}
			return text;
		}
		if (claim instanceof Map<?, ?> map) {
			return JSONObjectUtils.toJSONString(stringKeyMap(map));
		}
		throw new JOSEException(name + " JARM no es objeto JSON"); //$NON-NLS-1$
	}

	private static Map<String, Object> stringKeyMap(final Map<?, ?> map) throws JOSEException {
		final Map<String, Object> typed = new LinkedHashMap<>();
		for (final Map.Entry<?, ?> entry : map.entrySet()) {
			if (!(entry.getKey() instanceof String key)) {
				throw new JOSEException("presentation_submission JARM contiene claves no textuales"); //$NON-NLS-1$
			}
			typed.put(key, entry.getValue());
		}
		return typed;
	}

	private static void verifyValidity(final JWTClaimsSet claims) throws JOSEException {
		final Date now = new Date();
		final Date issueTime = claims.getIssueTime();
		if (issueTime != null && issueTime.after(now)) {
			throw new JOSEException("Respuesta JARM emitida en el futuro"); //$NON-NLS-1$
		}
		final Date expirationTime = claims.getExpirationTime();
		if (expirationTime == null) {
			throw new JOSEException("Respuesta JARM sin caducidad"); //$NON-NLS-1$
		}
		if (!expirationTime.after(now)) {
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
