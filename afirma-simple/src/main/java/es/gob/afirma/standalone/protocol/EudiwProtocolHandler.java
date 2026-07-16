/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital
 * This file is part of "Cliente @Firma".
 */

package es.gob.afirma.standalone.protocol;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;

import es.gob.afirma.eudiw.oid4vp.AuthorizationRequest;
import es.gob.afirma.eudiw.oid4vp.AuthorizationRequestBuilder;

/**
 * Handler para el verbo {@code afirma://eudiw-present?...}, equivalente al
 * resto de operaciones expuestas por {@link ProtocolInvocationLauncher} pero
 * orientado a la EU Digital Identity Wallet (M4).
 *
 * <p>Implementa {@link ProtocolOperationHandler} desde la Fase A del plan
 * Clean Code (2026-05-07) — primer verbo cableado a través del
 * {@link ProtocolOperationRegistry}.</p>
 *
 * <p>Forma esperada de la URI:</p>
 *
 * <pre>{@code afirma://eudiw-present?
 *     verifier=https%3A%2F%2Fverifier.example.es&
 *     responseUri=https%3A%2F%2Fverifier.example.es%2Foid4vp%2Fresponse&
 *     responseMode=direct_post.jwt&
 *     dcqlQuery=%7B%22credentials%22%3A%5B...%5D%7D&
 *     presentationDefinitionUri=https%3A%2F%2Fverifier.example.es%2Fpd%2F1&
 *     state=optional-state}</pre>
 *
 * <p>El método {@link #process(String, LaunchContext)} construye una
 * {@link AuthorizationRequest} OID4VP y devuelve la URI {@code openid4vp://}
 * canónica para su consumo por la wallet (móvil). La <em>entrega</em> a la
 * wallet (deep-link, mostrar QR, etc.) está marcada como TODO M4.x: depende
 * de coordinación con CTT y del endpoint de la wallet española de referencia.</p>
 */
public final class EudiwProtocolHandler implements ProtocolOperationHandler {

	private static final Logger LOGGER = Logger.getLogger(EudiwProtocolHandler.class.getName());

	/** El verbo (host de la URI {@code afirma://}) que activa este handler. */
	public static final String OPERATION = "eudiw-present"; //$NON-NLS-1$

	private static final String SCHEME_PREFIX = "afirma://" + OPERATION; //$NON-NLS-1$

	@Override
	public boolean handles(final String url) {
		if (url == null) {
			return false;
		}
		return url.startsWith(SCHEME_PREFIX + "?") //$NON-NLS-1$
				|| url.startsWith(SCHEME_PREFIX + "/?") //$NON-NLS-1$
				|| url.equals(SCHEME_PREFIX)
				|| url.equals(SCHEME_PREFIX + "/"); //$NON-NLS-1$
	}

	@Override
	public String process(final String url, final LaunchContext ctx) {
		Objects.requireNonNull(url, "url"); //$NON-NLS-1$
		Objects.requireNonNull(ctx, "ctx"); //$NON-NLS-1$

		final URI uri;
		try {
			uri = new URI(url);
		}
		catch (final URISyntaxException e) {
			throw new IllegalArgumentException("URL eudiw-present malformada: " + e.getMessage(), e); //$NON-NLS-1$
		}
		final Map<String, String> params = parseParameters(uri);

		final String verifier = require(params, "verifier"); //$NON-NLS-1$
		final URI responseUri = URI.create(require(params, "responseUri")); //$NON-NLS-1$
		final String responseMode = params.get("responseMode"); //$NON-NLS-1$
		final String dcqlQuery = firstNonBlank(params.get("dcqlQuery"), params.get("dcql_query")); //$NON-NLS-1$ //$NON-NLS-2$
		final String pdUri = params.get("presentationDefinitionUri"); //$NON-NLS-1$

		final AuthorizationRequestBuilder builder = new AuthorizationRequestBuilder()
				.clientId(verifier)
				.responseUri(responseUri)
				.withFreshNonce()
				.withFreshState();
		if ("direct_post.jwt".equals(responseMode)) { //$NON-NLS-1$
			builder.directPostJwtResponse();
		}
		if (dcqlQuery != null) {
			builder.dcqlQuery(dcqlQuery);
		}
		else if (pdUri != null && !pdUri.isBlank()) {
			builder.presentationDefinitionUri(URI.create(pdUri));
		}
		final AuthorizationRequest request = builder.build();
		final String openid4vpUri = request.toUri().toString();
		LOGGER.fine(() -> "OID4VP request construido para verifier=" + verifier); //$NON-NLS-1$
		// TODO M4.x: entregar la URI a la wallet (deep-link móvil, QR para
		// flujo cross-device, o POST al endpoint de la wallet de escritorio
		// cuando exista). De momento, devolvemos la URI canónica.
		return openid4vpUri;
	}

	/**
	 * Verifica si una URI {@code afirma://} apunta a este handler.
	 * Mantenido como API estática para compatibilidad con tests previos.
	 */
	public static boolean handles(final URI uri) {
		return uri != null
				&& "afirma".equalsIgnoreCase(uri.getScheme()) //$NON-NLS-1$
				&& OPERATION.equalsIgnoreCase(uri.getHost());
	}

	/**
	 * Parsea los parámetros de la URI a un mapa preservando el orden de aparición.
	 * Los valores se decodifican percent-encoded ({@link StandardCharsets#UTF_8}).
	 *
	 * <p>Como esta entrada es un <em>system boundary</em> (URLs externas), las
	 * claves duplicadas se rechazan explícitamente con {@link IllegalArgumentException}
	 * en lugar de sobreescribir silenciosamente.</p>
	 *
	 * @throws IllegalArgumentException si la URI no es {@code afirma://eudiw-present}
	 *     o si la query contiene la misma clave más de una vez.
	 */
	public static Map<String, String> parseParameters(final URI uri) {
		Objects.requireNonNull(uri, "uri"); //$NON-NLS-1$
		if (!handles(uri)) {
			throw new IllegalArgumentException(
					"URI no corresponde al verbo eudiw-present: " + uri); //$NON-NLS-1$
		}

		final String query = uri.getRawQuery();
		if (query == null || query.isBlank()) {
			return Collections.emptyMap();
		}

		final Map<String, String> params = new LinkedHashMap<>();
		for (final String pair : query.split("&")) { //$NON-NLS-1$
			final int eq = pair.indexOf('=');
			final String key;
			final String value;
			if (eq < 0) {
				key = URLDecoder.decode(pair, StandardCharsets.UTF_8);
				value = ""; //$NON-NLS-1$
			}
			else {
				key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
				value = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
			}
			if (params.containsKey(key)) {
				throw new IllegalArgumentException(
						"Parámetro duplicado en URI eudiw-present: " + key); //$NON-NLS-1$
			}
			params.put(key, value);
		}
		return Collections.unmodifiableMap(params);
	}

	private static String require(final Map<String, String> params, final String key) {
		final String v = params.get(key);
		if (v == null || v.isBlank()) {
			throw new IllegalArgumentException(
					"Parámetro requerido ausente en eudiw-present: " + key); //$NON-NLS-1$
		}
		return v;
	}

	private static String firstNonBlank(final String first, final String second) {
		if (first != null && !first.isBlank()) {
			return first;
		}
		return second != null && !second.isBlank() ? second : null;
	}
}
