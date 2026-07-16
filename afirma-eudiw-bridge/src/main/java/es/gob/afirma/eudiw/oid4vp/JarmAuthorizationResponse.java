/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.oid4vp;

import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
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
	private static final String SUPPORTED_FORMAT = "dc+sd-jwt"; //$NON-NLS-1$

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
		requireExpected(expectedAudience, "audience"); //$NON-NLS-1$
		requireExpected(expectedState, "state"); //$NON-NLS-1$
		rejectBlankExpected(expectedIssuer, "issuer"); //$NON-NLS-1$
		final SignedJWT jwt = SignedJWT.parse(responseJwt);
		if (!isSupportedJarmAlgorithm(jwt.getHeader().getAlgorithm())) {
			throw new JOSEException("Algoritmo JARM no soportado"); //$NON-NLS-1$
		}
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
		if (!issuer.equals(issuer.strip())) {
			throw new JOSEException("Issuer JARM no normalizado"); //$NON-NLS-1$
		}
		if (expectedIssuer != null && !expectedIssuer.equals(issuer)) {
			throw new JOSEException("Issuer JARM inválido"); //$NON-NLS-1$
		}
		if (claims.getAudience().isEmpty()) {
			throw new JOSEException("Audience JARM ausente"); //$NON-NLS-1$
		}
		for (final String audience : claims.getAudience()) {
			if (audience == null || audience.isBlank() || !audience.equals(audience.strip())) {
				throw new JOSEException("Audience JARM no normalizada"); //$NON-NLS-1$
			}
		}
		if (!claims.getAudience().contains(expectedAudience)) {
			throw new JOSEException("Audience JARM inválida"); //$NON-NLS-1$
		}
		final String state = claims.getStringClaim("state"); //$NON-NLS-1$
		if (state == null || state.isBlank()) {
			throw new JOSEException("State JARM ausente"); //$NON-NLS-1$
		}
		if (!state.equals(state.strip())) {
			throw new JOSEException("State JARM no normalizado"); //$NON-NLS-1$
		}
		if (!expectedState.equals(state)) {
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
			throw new JOSEException("Respuesta JARM sin presentation_submission"); //$NON-NLS-1$
		}
		if (claim instanceof String text) {
			if (text.isBlank()) {
				throw new JOSEException("presentation_submission JARM vacío"); //$NON-NLS-1$
			}
			if (!text.equals(text.strip())) {
				throw new JOSEException("presentation_submission JARM no normalizado"); //$NON-NLS-1$
			}
			try {
				validatePresentationSubmission(JSONObjectUtils.parse(text));
			}
			catch (final ParseException e) {
				throw new JOSEException("presentation_submission JARM no es JSON válido", e); //$NON-NLS-1$
			}
			return text;
		}
		if (claim instanceof Map<?, ?> map) {
			final Map<String, Object> typed = stringKeyMap(map);
			validatePresentationSubmission(typed);
			return JSONObjectUtils.toJSONString(typed);
		}
		throw new JOSEException("presentation_submission JARM no es objeto JSON"); //$NON-NLS-1$
	}

	private static boolean isSupportedJarmAlgorithm(final JWSAlgorithm algorithm) {
		return JWSAlgorithm.Family.RSA.contains(algorithm) || JWSAlgorithm.Family.EC.contains(algorithm);
	}

	private static String normalizeJsonOrTextClaim(final Object claim, final String name) throws JOSEException {
		if (claim == null) {
			throw new JOSEException("Respuesta JARM sin " + name); //$NON-NLS-1$
		}
		if (claim instanceof String text) {
			if (text.isBlank()) {
				throw new JOSEException(name + " JARM vacío"); //$NON-NLS-1$
			}
			if (!text.equals(text.strip())) {
				throw new JOSEException(name + " JARM no normalizado"); //$NON-NLS-1$
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

	private static void validatePresentationSubmission(final Map<String, Object> submission) throws JOSEException {
		requireNormalizedString(submission, "id"); //$NON-NLS-1$
		requireNormalizedString(submission, "definition_id"); //$NON-NLS-1$
		final Object descriptorMap = submission.get("descriptor_map"); //$NON-NLS-1$
		if (!(descriptorMap instanceof List<?> descriptors) || descriptors.isEmpty()) {
			throw new JOSEException("presentation_submission JARM sin descriptor_map"); //$NON-NLS-1$
		}
		final Set<String> descriptorIds = new HashSet<>();
		for (final Object descriptor : descriptors) {
			if (!(descriptor instanceof Map<?, ?> descriptorEntry)) {
				throw new JOSEException("presentation_submission JARM con descriptor_map inválido"); //$NON-NLS-1$
			}
			final Map<String, Object> typedDescriptor = stringKeyMap(descriptorEntry);
			if (!descriptorIds.add(requireNormalizedString(typedDescriptor, "id"))) { //$NON-NLS-1$
				throw new JOSEException("presentation_submission JARM con descriptor_map duplicado"); //$NON-NLS-1$
			}
			final String path = requireNormalizedString(typedDescriptor, "path"); //$NON-NLS-1$
			if (!path.startsWith("$")) { //$NON-NLS-1$
				throw new JOSEException("presentation_submission JARM con path inválido"); //$NON-NLS-1$
			}
			if (typedDescriptor.containsKey("format")) { //$NON-NLS-1$
				final String format = requireNormalizedString(typedDescriptor, "format"); //$NON-NLS-1$
				if (!SUPPORTED_FORMAT.equals(format)) {
					throw new JOSEException("presentation_submission JARM con format no soportado: " + format); //$NON-NLS-1$
				}
			}
		}
	}

	private static String requireNormalizedString(final Map<String, Object> map, final String name) throws JOSEException {
		final Object value = map.get(name);
		if (!(value instanceof String text) || text.isBlank() || !text.equals(text.strip())) {
			throw new JOSEException("presentation_submission JARM con " + name + " inválido"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		return text;
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
		if (value != null && !value.equals(value.strip())) {
			throw new JOSEException("Valor esperado JARM no normalizado: " + claim); //$NON-NLS-1$
		}
	}

	private static void requireExpected(final String value, final String claim)
			throws JOSEException {
		if (value == null) {
			throw new JOSEException("Valor esperado JARM ausente: " + claim); //$NON-NLS-1$
		}
		rejectBlankExpected(value, claim);
	}
}
