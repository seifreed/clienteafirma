/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.protocol;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Handler para el verbo {@code afirma://eudiw-present?...}, equivalente al
 * resto de operaciones expuestas por {@link ProtocolInvocationLauncher} pero
 * orientado a la EU Digital Identity Wallet (M4).
 *
 * <p>Este esqueleto solo cubre el <strong>parseo</strong> de la URI de
 * invocación. El cableado dentro del dispatcher principal —
 * {@code ProtocolInvocationLauncher.launch(url, ...)} — y la delegación a
 * {@code afirma-eudiw-bridge} para construir la {@code AuthorizationRequest}
 * correspondiente está marcado como TODO M4.x: requiere coordinación con CTT
 * y el endpoint de la wallet española de referencia.</p>
 *
 * <p>Forma esperada de la URI:</p>
 *
 * <pre>{@code afirma://eudiw-present?
 *     verifier=https%3A%2F%2Fverifier.example.es&
 *     responseUri=https%3A%2F%2Fverifier.example.es%2Foid4vp%2Fresponse&
 *     presentationDefinitionUri=https%3A%2F%2Fverifier.example.es%2Fpd%2F1&
 *     state=optional-state}</pre>
 */
public final class EudiwProtocolHandler {

	/** El verbo (host de la URI {@code afirma://}) que activa este handler. */
	public static final String OPERATION = "eudiw-present"; //$NON-NLS-1$

	private EudiwProtocolHandler() {
		// no-op
	}

	/**
	 * Verifica si una URI {@code afirma://} apunta a este handler.
	 */
	public static boolean handles(final URI uri) {
		return uri != null
				&& "afirma".equalsIgnoreCase(uri.getScheme()) //$NON-NLS-1$
				&& OPERATION.equalsIgnoreCase(uri.getHost());
	}

	/**
	 * Parsea los parámetros de la URI a un mapa simple. Los valores se decodifican
	 * percent-encoded ({@link StandardCharsets#UTF_8}). Lanza {@link IllegalArgumentException}
	 * si la URI no corresponde al verbo {@code eudiw-present}.
	 */
	public static Map<String, String> parseParameters(final URI uri) {
		Objects.requireNonNull(uri, "uri");
		if (!handles(uri)) {
			throw new IllegalArgumentException(
					"URI no corresponde al verbo eudiw-present: " + uri); //$NON-NLS-1$
		}

		final String query = uri.getRawQuery();
		if (query == null || query.isBlank()) {
			return Collections.emptyMap();
		}

		final Map<String, String> params = new HashMap<>();
		for (final String pair : query.split("&")) { //$NON-NLS-1$
			final int eq = pair.indexOf('=');
			if (eq < 0) {
				params.put(URLDecoder.decode(pair, StandardCharsets.UTF_8), ""); //$NON-NLS-1$
				continue;
			}
			final String k = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
			final String v = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
			params.put(k, v);
		}
		return Collections.unmodifiableMap(params);
	}
}
