/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.oid4vp;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

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
 *   <li>{@code response_mode} — {@code direct_post} para que la wallet POSTee la respuesta.</li>
 *   <li>{@code response_uri} — endpoint del Verifier que recibe la respuesta.</li>
 *   <li>{@code dcql_query} — consulta DCQL nativa.</li>
 *   <li>{@code nonce} y {@code state} — protección replay/CSRF.</li>
 * </ul>
 *
 * <p><strong>TODO M4.x:</strong> JAR (JWT-Signed Authorization Requests, RFC 9101)
 * para los Verifiers que requieren request object firmado; cifrado de respuesta
 * con JARM (RFC 9207).</p>
 */
public record AuthorizationRequest(
		String clientId,
		URI responseUri,
		URI presentationDefinitionUri,
		DcqlQuery dcqlQuery,
		String nonce,
		String state) {

	public AuthorizationRequest {
		Objects.requireNonNull(clientId, "clientId");
		Objects.requireNonNull(responseUri, "responseUri");
		Objects.requireNonNull(nonce, "nonce");
	}

	/** Serializa la request a una URI {@code openid4vp://authorize?...}. */
	public URI toUri() {
		final Map<String, String> params = new LinkedHashMap<>();
		params.put("client_id", this.clientId); //$NON-NLS-1$
		params.put("response_type", "vp_token"); //$NON-NLS-1$ //$NON-NLS-2$
		params.put("response_mode", "direct_post"); //$NON-NLS-1$ //$NON-NLS-2$
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
