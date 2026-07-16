/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;

/**
 * Cliente HTTP minimalista para diálogo con la Wallet (response endpoint
 * en flujo same-device) y con el endpoint del Issuer (OID4VCI). Usa el
 * cliente HTTP del JDK (java.net.http) para evitar dependencias extra.
 *
 * <p>El método principal es {@link #postFormUrlencoded(URI, String)} —
 * la wallet envía el {@code vp_token} (y opcionalmente
 * {@code presentation_submission}) por POST {@code application/x-www-form-urlencoded}
 * según OID4VP §6 «Response Mode = direct_post».</p>
 */
public final class EudiwClient {

	private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(20);

	private final HttpClient http;

	public EudiwClient() {
		this(HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(10))
				.followRedirects(HttpClient.Redirect.NORMAL)
				.build());
	}

	EudiwClient(final HttpClient http) {
		this.http = Objects.requireNonNull(http, "http");
	}

	/**
	 * POST de body URL-encoded contra una URI HTTPS de la wallet o issuer.
	 * Devuelve el cuerpo de la respuesta o lanza {@link IOException} si el
	 * status no es 2xx.
	 */
	public String postFormUrlencoded(final URI endpoint, final String formBody)
			throws IOException, InterruptedException {
		Objects.requireNonNull(endpoint, "endpoint");
		Objects.requireNonNull(formBody, "formBody");
		if (!"https".equalsIgnoreCase(endpoint.getScheme())) { //$NON-NLS-1$
			throw new IOException("OID4VP exige HTTPS, recibido: " + endpoint.getScheme()); //$NON-NLS-1$
		}
		if (endpoint.getHost() == null || endpoint.getHost().isBlank()) {
			throw new IOException("OID4VP exige endpoint HTTPS con host"); //$NON-NLS-1$
		}
		if (endpoint.getRawUserInfo() != null) {
			throw new IOException("OID4VP endpoint no admite userinfo"); //$NON-NLS-1$
		}
		if (endpoint.getRawFragment() != null) {
			throw new IOException("OID4VP endpoint no admite fragmento"); //$NON-NLS-1$
		}
		if (formBody.isBlank()) {
			throw new IOException("OID4VP form body vacío"); //$NON-NLS-1$
		}
		if (!formBody.equals(formBody.strip())) {
			throw new IOException("OID4VP form body no normalizado"); //$NON-NLS-1$
		}

		final HttpRequest request = HttpRequest.newBuilder(endpoint)
				.timeout(DEFAULT_TIMEOUT)
				.header("Content-Type", "application/x-www-form-urlencoded") //$NON-NLS-1$ //$NON-NLS-2$
				.POST(HttpRequest.BodyPublishers.ofString(formBody))
				.build();

		final HttpResponse<String> response = this.http.send(request, HttpResponse.BodyHandlers.ofString());
		if (response.statusCode() < 200 || response.statusCode() >= 300) {
			throw new IOException("EUDIW response status " + response.statusCode() //$NON-NLS-1$
					+ ": " + truncate(response.body())); //$NON-NLS-1$
		}
		return response.body();
	}

	private static String truncate(final String s) {
		if (s == null) {
			return ""; //$NON-NLS-1$
		}
		return s.length() <= 200 ? s : s.substring(0, 200) + "…"; //$NON-NLS-1$
	}
}
