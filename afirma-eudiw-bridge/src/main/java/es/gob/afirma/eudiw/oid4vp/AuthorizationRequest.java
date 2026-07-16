/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.oid4vp;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
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

	public AuthorizationRequest {
		Objects.requireNonNull(clientId, "clientId");
		Objects.requireNonNull(responseUri, "responseUri");
		Objects.requireNonNull(nonce, "nonce");
		if (!"https".equalsIgnoreCase(responseUri.getScheme())) { //$NON-NLS-1$
			throw new IllegalArgumentException("OID4VP response_uri exige HTTPS"); //$NON-NLS-1$
		}
		responseMode = responseMode == null ? "direct_post" : responseMode; //$NON-NLS-1$
	}

	/** Serializa la request a una URI {@code openid4vp://authorize?...}. */
	public URI toUri() {
		return toUri(params());
	}

	/** Serializa la request usando JAR by value ({@code request=<jwt>}). */
	public URI toUriWithRequestObject(final SignedJWT requestObject) {
		Objects.requireNonNull(requestObject, "requestObject"); //$NON-NLS-1$
		final Map<String, String> params = new LinkedHashMap<>();
		params.put("client_id", this.clientId); //$NON-NLS-1$
		params.put("request", requestObject.serialize()); //$NON-NLS-1$
		return toUri(params);
	}

	/** Genera un Request Object JAR (RFC 9101) firmado. */
	public SignedJWT toSignedRequestObject(final JWSSigner signer,
			final JWSAlgorithm algorithm, final String keyId, final String audience)
			throws JOSEException {
		Objects.requireNonNull(signer, "signer"); //$NON-NLS-1$
		Objects.requireNonNull(algorithm, "algorithm"); //$NON-NLS-1$
		final JWSHeader.Builder header = new JWSHeader.Builder(algorithm)
				.type(new JOSEObjectType("oauth-authz-req+jwt")); //$NON-NLS-1$
		if (keyId != null && !keyId.isBlank()) {
			header.keyID(keyId);
		}
		final Date now = new Date();
		final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
				.issuer(this.clientId)
				.issueTime(now)
				.expirationTime(Date.from(now.toInstant().plus(REQUEST_OBJECT_VALIDITY)));
		for (final Map.Entry<String, String> entry : params().entrySet()) {
			claims.claim(entry.getKey(), entry.getValue());
		}
		if (audience != null && !audience.isBlank()) {
			claims.audience(audience);
		}
		final SignedJWT jwt = new SignedJWT(header.build(), claims.build());
		jwt.sign(signer);
		return jwt;
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
