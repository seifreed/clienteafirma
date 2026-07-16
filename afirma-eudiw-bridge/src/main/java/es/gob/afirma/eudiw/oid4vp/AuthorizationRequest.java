/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.oid4vp;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * OpenID for Verifiable Presentations (OID4VP) — Authorization Request.
 * Modela la URI {@code openid4vp://authorize?...} (o equivalente) que el
 * Verifier (Autofirma) envía a la Wallet (móvil) para pedirle una
 * presentación de credenciales.
 *
 * <p>Implementación intencionalmente mínima — alineada con el draft
 * OID4VP-23 (mayo 2026). Los campos cubiertos son los obligatorios para
 * un flujo de presentación same-device:</p>
 *
 * <ul>
 *   <li>{@code client_id} — identificador del Verifier.</li>
 *   <li>{@code response_type} — fijo a {@code vp_token}.</li>
 *   <li>{@code response_mode} — {@code direct_post} o {@code direct_post.jwt}.</li>
 *   <li>{@code response_uri} — endpoint del Verifier que recibe la respuesta.</li>
 *   <li>{@code dcql_query} — consulta DCQL nativa.</li>
 *   <li>{@code nonce} y {@code state} — protección replay/CSRF.</li>
 * </ul>
 */
public record AuthorizationRequest(
		String clientId,
		URI responseUri,
		String responseMode,
		URI presentationDefinitionUri,
		DcqlQuery dcqlQuery,
		String nonce,
		String state) {

	private static final Duration REQUEST_OBJECT_VALIDITY = Duration.ofMinutes(5);
	private static final JOSEObjectType REQUEST_OBJECT_TYPE =
			new JOSEObjectType("oauth-authz-req+jwt"); //$NON-NLS-1$

	public AuthorizationRequest {
		Objects.requireNonNull(clientId, "clientId");
		Objects.requireNonNull(responseUri, "responseUri");
		Objects.requireNonNull(nonce, "nonce");
		if (clientId.isBlank()) {
			throw new IllegalArgumentException("OID4VP client_id vacío"); //$NON-NLS-1$
		}
		if (!clientId.equals(clientId.strip())) {
			throw new IllegalArgumentException("OID4VP client_id no normalizado"); //$NON-NLS-1$
		}
		if (containsControlChars(clientId)) {
			throw new IllegalArgumentException("OID4VP client_id contiene caracteres de control"); //$NON-NLS-1$
		}
		requireHttpsWithHost(URI.create(clientId), "client_id"); //$NON-NLS-1$
		if (nonce.isBlank()) {
			throw new IllegalArgumentException("OID4VP nonce vacío"); //$NON-NLS-1$
		}
		if (!nonce.equals(nonce.strip())) {
			throw new IllegalArgumentException("OID4VP nonce no normalizado"); //$NON-NLS-1$
		}
		if (containsControlChars(nonce)) {
			throw new IllegalArgumentException("OID4VP nonce contiene caracteres de control"); //$NON-NLS-1$
		}
		if (state != null && state.isBlank()) {
			throw new IllegalArgumentException("OID4VP state vacío"); //$NON-NLS-1$
		}
		if (state != null && !state.equals(state.strip())) {
			throw new IllegalArgumentException("OID4VP state no normalizado"); //$NON-NLS-1$
		}
		if (state != null && containsControlChars(state)) {
			throw new IllegalArgumentException("OID4VP state contiene caracteres de control"); //$NON-NLS-1$
		}
		requireHttpsWithHost(responseUri, "response_uri"); //$NON-NLS-1$
		if (presentationDefinitionUri != null) {
			requireHttpsWithHost(presentationDefinitionUri, "presentation_definition_uri"); //$NON-NLS-1$
		}
		if (presentationDefinitionUri == null && dcqlQuery == null) {
			throw new IllegalArgumentException("OID4VP sin consulta de credenciales"); //$NON-NLS-1$
		}
		if (presentationDefinitionUri != null && dcqlQuery != null) {
			throw new IllegalArgumentException("OID4VP no admite DCQL y presentation_definition_uri a la vez"); //$NON-NLS-1$
		}
		responseMode = responseMode == null ? "direct_post" : responseMode; //$NON-NLS-1$
		if (!responseMode.equals(responseMode.strip())) {
			throw new IllegalArgumentException("response_mode OID4VP no normalizado"); //$NON-NLS-1$
		}
		if (containsControlChars(responseMode)) {
			throw new IllegalArgumentException("response_mode OID4VP contiene caracteres de control"); //$NON-NLS-1$
		}
		if (!"direct_post".equals(responseMode) && !"direct_post.jwt".equals(responseMode)) { //$NON-NLS-1$ //$NON-NLS-2$
			throw new IllegalArgumentException("response_mode OID4VP no soportado: " + responseMode); //$NON-NLS-1$
		}
	}

	private static boolean containsControlChars(final String text) {
		return text.chars().anyMatch(Character::isISOControl);
	}

	private static void requireHttpsWithHost(final URI uri, final String field) {
		if (!"https".equalsIgnoreCase(uri.getScheme())) { //$NON-NLS-1$
			throw new IllegalArgumentException("OID4VP " + field + " exige HTTPS"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		if (uri.getHost() == null || uri.getHost().isBlank()) {
			throw new IllegalArgumentException("OID4VP " + field + " exige host"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		if (uri.getRawUserInfo() != null) {
			throw new IllegalArgumentException("OID4VP " + field + " no admite userinfo"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		if (uri.getRawFragment() != null) {
			throw new IllegalArgumentException("OID4VP " + field + " no admite fragmento"); //$NON-NLS-1$ //$NON-NLS-2$
		}
	}

	/** Serializa la request a una URI {@code openid4vp://authorize?...}. */
	public URI toUri() {
		return toUri(params());
	}

	/** Serializa la request usando JAR by value ({@code request=<jwt>}). */
	public URI toUriWithRequestObject(final SignedJWT requestObject, final JWSVerifier verifier) {
		Objects.requireNonNull(requestObject, "requestObject"); //$NON-NLS-1$
		Objects.requireNonNull(verifier, "verifier"); //$NON-NLS-1$
		final Map<String, String> params = new LinkedHashMap<>();
		params.put("client_id", this.clientId); //$NON-NLS-1$
		try {
			if (!REQUEST_OBJECT_TYPE.equals(requestObject.getHeader().getType())) {
				throw new IllegalArgumentException("Request Object JAR con typ inválido"); //$NON-NLS-1$
			}
			if (!isSupportedJarAlgorithm(requestObject.getHeader().getAlgorithm())) {
				throw new IllegalArgumentException("Request Object JAR con algoritmo no soportado"); //$NON-NLS-1$
			}
			if (!requestObject.verify(verifier)) {
				throw new IllegalArgumentException("Firma Request Object JAR inválida"); //$NON-NLS-1$
			}
			final JWTClaimsSet claims = requestObject.getJWTClaimsSet();
			validateRequestObjectTime(claims);
			validateRequestObjectAudience(claims);
			final String issuer = claims.getIssuer();
			if (issuer == null || issuer.isBlank() || !issuer.equals(issuer.strip())
					|| containsControlChars(issuer)) {
				throw new IllegalArgumentException("Request Object JAR con issuer no normalizado"); //$NON-NLS-1$
			}
			if (!this.clientId.equals(issuer)) {
				throw new IllegalArgumentException("Request Object JAR con issuer distinto del client_id"); //$NON-NLS-1$
			}
			for (final Map.Entry<String, String> entry : params().entrySet()) {
				if (!entry.getValue().equals(claims.getStringClaim(entry.getKey()))) {
					throw new IllegalArgumentException("Request Object JAR no coincide con " + entry.getKey()); //$NON-NLS-1$
				}
			}
			params.put("request", requestObject.serialize()); //$NON-NLS-1$
		}
		catch (final ParseException e) {
			throw new IllegalArgumentException("Request Object JAR inválido", e); //$NON-NLS-1$
		}
		catch (final JOSEException e) {
			throw new IllegalArgumentException("No se pudo verificar la firma Request Object JAR", e); //$NON-NLS-1$
		}
		catch (final IllegalStateException e) {
			throw new IllegalArgumentException("Request Object JAR sin firma", e); //$NON-NLS-1$
		}
		return toUri(params);
	}

	private static void validateRequestObjectTime(final JWTClaimsSet claims) {
		final Date now = new Date();
		final Date issueTime = claims.getIssueTime();
		if (issueTime != null && issueTime.after(now)) {
			throw new IllegalArgumentException("Request Object JAR emitido en el futuro"); //$NON-NLS-1$
		}
		final Date expirationTime = claims.getExpirationTime();
		if (expirationTime == null) {
			throw new IllegalArgumentException("Request Object JAR sin caducidad"); //$NON-NLS-1$
		}
		if (!expirationTime.after(now)) {
			throw new IllegalArgumentException("Request Object JAR caducado"); //$NON-NLS-1$
		}
		final Date notBeforeTime = claims.getNotBeforeTime();
		if (notBeforeTime != null && notBeforeTime.after(now)) {
			throw new IllegalArgumentException("Request Object JAR no válido aún"); //$NON-NLS-1$
		}
	}

	private static void validateRequestObjectAudience(final JWTClaimsSet claims) {
		if (claims.getAudience().isEmpty()) {
			throw new IllegalArgumentException("Request Object JAR sin audience"); //$NON-NLS-1$
		}
		for (final String audience : claims.getAudience()) {
			if (audience == null || audience.isBlank() || !audience.equals(audience.strip())
					|| containsControlChars(audience)) {
				throw new IllegalArgumentException("Request Object JAR con audience no normalizada"); //$NON-NLS-1$
			}
		}
	}

	/** Genera un Request Object JAR (RFC 9101) firmado. */
	public SignedJWT toSignedRequestObject(final JWSSigner signer,
			final JWSAlgorithm algorithm, final String keyId, final String audience)
			throws JOSEException {
		Objects.requireNonNull(signer, "signer"); //$NON-NLS-1$
		Objects.requireNonNull(algorithm, "algorithm"); //$NON-NLS-1$
		if (!isSupportedJarAlgorithm(algorithm)) {
			throw new IllegalArgumentException("OID4VP JAR algoritmo no soportado"); //$NON-NLS-1$
		}
		final JWSHeader.Builder header = new JWSHeader.Builder(algorithm)
				.type(REQUEST_OBJECT_TYPE);
		if (keyId != null && keyId.isBlank()) {
			throw new IllegalArgumentException("OID4VP JAR keyId vacío"); //$NON-NLS-1$
		}
		if (keyId != null && !keyId.equals(keyId.strip())) {
			throw new IllegalArgumentException("OID4VP JAR keyId no normalizado"); //$NON-NLS-1$
		}
		if (keyId != null && containsControlChars(keyId)) {
			throw new IllegalArgumentException("OID4VP JAR keyId contiene caracteres de control"); //$NON-NLS-1$
		}
		if (keyId != null) {
			header.keyID(keyId);
		}
		Objects.requireNonNull(audience, "audience"); //$NON-NLS-1$
		if (audience.isBlank()) {
			throw new IllegalArgumentException("OID4VP JAR audience vacío"); //$NON-NLS-1$
		}
		if (!audience.equals(audience.strip())) {
			throw new IllegalArgumentException("OID4VP JAR audience no normalizado"); //$NON-NLS-1$
		}
		if (containsControlChars(audience)) {
			throw new IllegalArgumentException("OID4VP JAR audience contiene caracteres de control"); //$NON-NLS-1$
		}
		final Date now = new Date();
		final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
				.issuer(this.clientId)
				.issueTime(now)
				.expirationTime(Date.from(now.toInstant().plus(REQUEST_OBJECT_VALIDITY)));
		for (final Map.Entry<String, String> entry : params().entrySet()) {
			claims.claim(entry.getKey(), entry.getValue());
		}
		claims.audience(audience);
		final SignedJWT jwt = new SignedJWT(header.build(), claims.build());
		jwt.sign(signer);
		return jwt;
	}

	private static boolean isSupportedJarAlgorithm(final JWSAlgorithm algorithm) {
		return JWSAlgorithm.Family.RSA.contains(algorithm) || JWSAlgorithm.Family.EC.contains(algorithm);
	}

	private Map<String, String> params() {
		final Map<String, String> params = new LinkedHashMap<>();
		params.put("client_id", this.clientId); //$NON-NLS-1$
		params.put("response_type", "vp_token"); //$NON-NLS-1$ //$NON-NLS-2$
		params.put("response_mode", this.responseMode); //$NON-NLS-1$
		params.put("response_uri", this.responseUri.toString()); //$NON-NLS-1$
		if (this.dcqlQuery != null) {
			params.put("dcql_query", this.dcqlQuery.json()); //$NON-NLS-1$
		}
		else if (this.presentationDefinitionUri != null) {
			params.put("presentation_definition_uri", this.presentationDefinitionUri.toString()); //$NON-NLS-1$
		}
		params.put("nonce", this.nonce); //$NON-NLS-1$
		if (this.state != null) {
			params.put("state", this.state); //$NON-NLS-1$
		}
		return params;
	}

	private static URI toUri(final Map<String, String> params) {
		final StringBuilder sb = new StringBuilder("openid4vp://authorize?"); //$NON-NLS-1$
		boolean first = true;
		for (final Map.Entry<String, String> e : params.entrySet()) {
			if (!first) {
				sb.append('&');
			}
			sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
					.append('=')
					.append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
			first = false;
		}
		return URI.create(sb.toString());
	}
}
