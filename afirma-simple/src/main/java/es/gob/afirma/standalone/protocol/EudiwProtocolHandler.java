/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital
 * This file is part of "Cliente @Firma".
 */

package es.gob.afirma.standalone.protocol;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;

import es.gob.afirma.eudiw.EudiwClient;
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
 *     walletUri=eudiw%3A%2F%2Fpresent&
 *     walletEndpoint=https%3A%2F%2Fwallet.example.es%2Foid4vp%2Frequest&
 *     presentationDefinitionUri=https%3A%2F%2Fverifier.example.es%2Fpd%2F1&
 *     state=optional-state}</pre>
 *
 * <p>El método {@link #process(String, LaunchContext)} construye una
 * {@link AuthorizationRequest} OID4VP y la entrega por deep-link
 * ({@code walletUri}) o por POST URL-encoded ({@code walletEndpoint}). Si no
 * se declara ninguna entrega, devuelve la URI {@code openid4vp://} canónica.</p>
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
		final String normalizedUrl = url.toLowerCase(Locale.ROOT);
		return normalizedUrl.startsWith(SCHEME_PREFIX + "?") //$NON-NLS-1$
				|| normalizedUrl.startsWith(SCHEME_PREFIX + "/?") //$NON-NLS-1$
				|| normalizedUrl.equals(SCHEME_PREFIX)
				|| normalizedUrl.equals(SCHEME_PREFIX + "/"); //$NON-NLS-1$
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
		requireHttpsUri(verifier, "verifier"); //$NON-NLS-1$
		final URI responseUri = URI.create(require(params, "responseUri")); //$NON-NLS-1$
		final String responseMode = params.get("responseMode"); //$NON-NLS-1$
		final String dcqlQueryCamel = params.get("dcqlQuery"); //$NON-NLS-1$
		final String dcqlQuerySnake = params.get("dcql_query"); //$NON-NLS-1$
		final String dcqlQuery = firstNonBlank(dcqlQueryCamel, dcqlQuerySnake);
		final String pdUri = params.get("presentationDefinitionUri"); //$NON-NLS-1$
		final String walletUri = params.get("walletUri"); //$NON-NLS-1$
		final String walletEndpoint = params.get("walletEndpoint"); //$NON-NLS-1$
		final String state = params.get("state"); //$NON-NLS-1$
		rejectBlankIfPresent(responseMode, "responseMode"); //$NON-NLS-1$
		rejectBlankIfPresent(dcqlQueryCamel, "dcqlQuery"); //$NON-NLS-1$
		rejectBlankIfPresent(dcqlQuerySnake, "dcql_query"); //$NON-NLS-1$
		if (dcqlQueryCamel != null && dcqlQuerySnake != null) {
			throw new IllegalArgumentException("dcqlQuery y dcql_query no pueden combinarse"); //$NON-NLS-1$
		}
		rejectBlankIfPresent(pdUri, "presentationDefinitionUri"); //$NON-NLS-1$
		rejectBlankIfPresent(walletUri, "walletUri"); //$NON-NLS-1$
		rejectBlankIfPresent(walletEndpoint, "walletEndpoint"); //$NON-NLS-1$
		if (walletUri != null && walletEndpoint != null) {
			throw new IllegalArgumentException("walletUri y walletEndpoint no pueden combinarse"); //$NON-NLS-1$
		}
		if (walletEndpoint != null) {
			requireHttpsUri(walletEndpoint, "walletEndpoint"); //$NON-NLS-1$
		}

		final AuthorizationRequestBuilder builder = new AuthorizationRequestBuilder()
				.clientId(verifier)
				.responseUri(responseUri)
				.withFreshNonce();
		if (state != null) {
			builder.state(state);
		}
		else {
			builder.withFreshState();
		}
		if (responseMode != null && !responseMode.isBlank()) {
			if ("direct_post.jwt".equals(responseMode)) { //$NON-NLS-1$
				builder.directPostJwtResponse();
			}
			else if (!"direct_post".equals(responseMode)) { //$NON-NLS-1$
				throw new IllegalArgumentException("responseMode OID4VP no soportado: " + responseMode); //$NON-NLS-1$
			}
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
		if (walletUri != null && !walletUri.isBlank()) {
			final URI walletDeepLink = URI.create(walletUri);
			if (walletDeepLink.getScheme() == null || walletDeepLink.getScheme().isBlank()) {
				throw new IllegalArgumentException("walletUri debe declarar esquema"); //$NON-NLS-1$
			}
			if (walletDeepLink.getRawUserInfo() != null) {
				throw new IllegalArgumentException("walletUri no admite userinfo"); //$NON-NLS-1$
			}
			return appendQueryParam(walletDeepLink, "request", openid4vpUri).toString(); //$NON-NLS-1$
		}
		if (walletEndpoint != null && !walletEndpoint.isBlank()) {
			try {
				return new EudiwClient().postFormUrlencoded(URI.create(walletEndpoint),
						"request=" + URLEncoder.encode(openid4vpUri, StandardCharsets.UTF_8)); //$NON-NLS-1$
			}
			catch (final InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new IllegalStateException("Interrumpida la entrega OID4VP a la wallet", e); //$NON-NLS-1$
			}
			catch (final IOException e) {
				throw new IllegalStateException("No se pudo entregar OID4VP a la wallet: " + e.getMessage(), e); //$NON-NLS-1$
			}
		}
		return openid4vpUri;
	}

	/**
	 * Verifica si una URI {@code afirma://} apunta a este handler.
	 * Mantenido como API estática para compatibilidad con tests previos.
	 */
	public static boolean handles(final URI uri) {
		return uri != null
				&& "afirma".equalsIgnoreCase(uri.getScheme()) //$NON-NLS-1$
				&& OPERATION.equalsIgnoreCase(uri.getHost())
				&& (uri.getRawPath() == null || uri.getRawPath().isEmpty()
						|| "/".equals(uri.getRawPath())); //$NON-NLS-1$
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
		if (uri.getRawFragment() != null) {
			throw new IllegalArgumentException("URI eudiw-present no admite fragmento"); //$NON-NLS-1$
		}

		final String query = uri.getRawQuery();
		if (query == null || query.isBlank()) {
			return Collections.emptyMap();
		}

		final Map<String, String> params = new LinkedHashMap<>();
		for (final String pair : query.split("&", -1)) { //$NON-NLS-1$
			if (pair.isEmpty()) {
				throw new IllegalArgumentException("Parámetro vacío en URI eudiw-present"); //$NON-NLS-1$
			}
			final int eq = pair.indexOf('=');
			final String key;
			final String value;
			if (eq < 0) {
				key = decodeQueryComponent(pair);
				value = ""; //$NON-NLS-1$
			}
			else {
				key = decodeQueryComponent(pair.substring(0, eq));
				value = decodeQueryComponent(pair.substring(eq + 1));
			}
			if (key.isBlank()) {
				throw new IllegalArgumentException("Parámetro sin nombre en URI eudiw-present"); //$NON-NLS-1$
			}
			if (!key.equals(key.strip())) {
				throw new IllegalArgumentException("Parámetro no normalizado en URI eudiw-present: " + key); //$NON-NLS-1$
			}
			if (params.containsKey(key)) {
				throw new IllegalArgumentException(
						"Parámetro duplicado en URI eudiw-present: " + key); //$NON-NLS-1$
			}
			params.put(key, value);
		}
		return Collections.unmodifiableMap(params);
	}

	private static String decodeQueryComponent(final String value) {
		return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8); //$NON-NLS-1$ //$NON-NLS-2$
	}

	private static String require(final Map<String, String> params, final String key) {
		final String v = params.get(key);
		if (v == null || v.isBlank()) {
			throw new IllegalArgumentException(
					"Parámetro requerido ausente en eudiw-present: " + key); //$NON-NLS-1$
		}
		return v;
	}

	private static void requireHttpsUri(final String value, final String key) {
		final URI uri = URI.create(value);
		if (!"https".equalsIgnoreCase(uri.getScheme())) { //$NON-NLS-1$
			throw new IllegalArgumentException("Parámetro " + key + " debe ser HTTPS"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		if (uri.getHost() == null || uri.getHost().isBlank()) {
			throw new IllegalArgumentException("Parámetro " + key + " debe declarar host HTTPS"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		if (uri.getRawUserInfo() != null) {
			throw new IllegalArgumentException("Parámetro " + key + " no admite userinfo"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		if (uri.getRawFragment() != null) {
			throw new IllegalArgumentException("Parámetro " + key + " no admite fragmento"); //$NON-NLS-1$ //$NON-NLS-2$
		}
	}

	private static void rejectBlankIfPresent(final String value, final String key) {
		if (value != null && value.isBlank()) {
			throw new IllegalArgumentException("Parámetro vacío en eudiw-present: " + key); //$NON-NLS-1$
		}
		if (value != null && !value.equals(value.strip())) {
			throw new IllegalArgumentException("Parámetro no normalizado en eudiw-present: " + key); //$NON-NLS-1$
		}
	}

	private static String firstNonBlank(final String first, final String second) {
		if (first != null && !first.isBlank()) {
			return first;
		}
		return second != null && !second.isBlank() ? second : null;
	}

	private static URI appendQueryParam(final URI uri, final String key, final String value) {
		final String separator = uri.getRawQuery() == null ? "?" : "&"; //$NON-NLS-1$ //$NON-NLS-2$
		final String text = uri.toString();
		final int fragment = text.indexOf('#');
		final String head = fragment < 0 ? text : text.substring(0, fragment);
		final String tail = fragment < 0 ? "" : text.substring(fragment); //$NON-NLS-1$
		return URI.create(head + separator
				+ URLEncoder.encode(key, StandardCharsets.UTF_8)
				+ "=" //$NON-NLS-1$
				+ URLEncoder.encode(value, StandardCharsets.UTF_8)
				+ tail);
	}
}
