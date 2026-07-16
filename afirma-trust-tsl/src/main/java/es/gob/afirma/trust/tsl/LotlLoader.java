/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Objects;

/** Descarga, verifica y cachea la LOTL europea. */
public final class LotlLoader implements TrustListService.TslLoader {

	public static final URI EU_LOTL_URI = URI.create(
			"https://ec.europa.eu/tools/lotl/eu-lotl.xml"); //$NON-NLS-1$

	private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(20);

	private final TslXmlSource source;
	private final PublicKey trustedKey;
	private final Path cachePath;
	private final TslParser parser = new TslParser();
	private final TslVerifier verifier = new TslVerifier();

	public LotlLoader(final TslXmlSource source, final PublicKey trustedKey,
			final Path cachePath) {
		this.source = Objects.requireNonNull(source, "source"); //$NON-NLS-1$
		this.trustedKey = Objects.requireNonNull(trustedKey, "trustedKey"); //$NON-NLS-1$
		this.cachePath = cachePath;
	}

	public static LotlLoader europeanCommission(final PublicKey trustedKey,
			final Path cachePath) {
		return new LotlLoader(new HttpTslXmlSource(EU_LOTL_URI), trustedKey, cachePath);
	}

	@Override
	public TslDocument load() throws TslException {
		try {
			final byte[] xml = this.source.load();
			final TslDocument doc = parseVerified(xml);
			writeCache(xml);
			return doc;
		}
		catch (final IOException | InterruptedException e) {
			if (e instanceof InterruptedException) {
				Thread.currentThread().interrupt();
			}
			return readCache(e);
		}
	}

	private TslDocument parseVerified(final byte[] xml) throws TslException {
		if (!this.verifier.verify(xml, this.trustedKey)) {
			throw new TslException("Firma LOTL no válida"); //$NON-NLS-1$
		}
		return this.parser.parse(xml);
	}

	private void writeCache(final byte[] xml) throws TslException {
		if (this.cachePath == null) {
			return;
		}
		try {
			final Path parent = this.cachePath.getParent();
			if (parent != null) {
				Files.createDirectories(parent);
			}
			Files.write(this.cachePath, xml);
		}
		catch (final IOException e) {
			throw new TslException("No se pudo escribir la cache LOTL", e); //$NON-NLS-1$
		}
	}

	private TslDocument readCache(final Exception cause) throws TslException {
		if (this.cachePath == null || !Files.isRegularFile(this.cachePath)) {
			throw new TslException("No se pudo descargar LOTL y no hay cache", cause); //$NON-NLS-1$
		}
		try {
			return parseVerified(Files.readAllBytes(this.cachePath));
		}
		catch (final IOException e) {
			throw new TslException("No se pudo leer la cache LOTL", e); //$NON-NLS-1$
		}
	}

	private static final class HttpTslXmlSource implements TslXmlSource {

		private final URI uri;
		private final HttpClient http = HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(10))
				.followRedirects(HttpClient.Redirect.NORMAL)
				.build();

		HttpTslXmlSource(final URI uri) {
			if (!"https".equalsIgnoreCase(uri.getScheme())) { //$NON-NLS-1$
				throw new IllegalArgumentException("La LOTL debe descargarse por HTTPS"); //$NON-NLS-1$
			}
			this.uri = uri;
		}

		@Override
		public byte[] load() throws IOException, InterruptedException {
			final HttpRequest request = HttpRequest.newBuilder(this.uri)
					.timeout(HTTP_TIMEOUT)
					.GET()
					.build();
			final HttpResponse<byte[]> response = this.http.send(request,
					HttpResponse.BodyHandlers.ofByteArray());
			if (response.statusCode() < 200 || response.statusCode() >= 300) {
				throw new IOException("HTTP LOTL status " + response.statusCode()); //$NON-NLS-1$
			}
			return response.body();
		}
	}
}
