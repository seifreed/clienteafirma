/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/** Descarga, verifica y cachea la LOTL europea. */
public final class LotlLoader implements TrustListService.TslLoader {

	public static final URI EU_LOTL_URI = URI.create(
			"https://ec.europa.eu/tools/lotl/eu-lotl.xml"); //$NON-NLS-1$

	private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(20);
	private static final Duration CACHE_REFRESH_INTERVAL = Duration.ofHours(24);

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
			final TslDocument cached = readFreshCache();
			if (cached != null) {
				return cached;
			}
		}
		catch (final TslException e) {
			// Cache corrupta o ilegible: se intentara refrescar desde la fuente.
		}
		try {
			final byte[] xml = this.source.load();
			final TslDocument doc = parseVerified(xml);
			writeCache(xml);
			return doc;
		}
		catch (final TslException e) {
			return readCache(e);
		}
		catch (final IOException | InterruptedException e) {
			if (e instanceof InterruptedException) {
				Thread.currentThread().interrupt();
			}
			return readCache(e);
		}
	}

	private TslDocument readFreshCache() throws TslException {
		if (this.cachePath == null || !Files.isRegularFile(this.cachePath)) {
			return null;
		}
		try {
			if (!Instant.now().isBefore(Files.getLastModifiedTime(this.cachePath)
					.toInstant().plus(CACHE_REFRESH_INTERVAL))) {
				return null;
			}
			return parseVerified(Files.readAllBytes(this.cachePath));
		}
		catch (final IOException e) {
			throw new TslException("No se pudo leer la cache LOTL", e); //$NON-NLS-1$
		}
	}

	private TslDocument parseVerified(final byte[] xml) throws TslException {
		if (!this.verifier.verify(xml, this.trustedKey)) {
			throw new TslException("Firma LOTL no válida"); //$NON-NLS-1$
		}
		final TslDocument doc = this.parser.parse(xml);
		if (doc.nextUpdate() != null && !Instant.now().isBefore(doc.nextUpdate())) {
			throw new TslException("LOTL caducada"); //$NON-NLS-1$
		}
		return doc;
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
			final Path tmp = Files.createTempFile(
					parent != null ? parent : this.cachePath.toAbsolutePath().getParent(),
					this.cachePath.getFileName().toString(), ".tmp"); //$NON-NLS-1$
			try {
				Files.write(tmp, xml);
				try {
					Files.move(tmp, this.cachePath,
							StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
				}
				catch (final AtomicMoveNotSupportedException e) {
					Files.move(tmp, this.cachePath, StandardCopyOption.REPLACE_EXISTING);
				}
			}
			finally {
				Files.deleteIfExists(tmp);
			}
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

	static final class HttpTslXmlSource implements TslXmlSource {

		private final URI uri;
		private final HttpClient http = HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(10))
				.followRedirects(HttpClient.Redirect.NORMAL)
				.build();

		HttpTslXmlSource(final URI uri) {
			if (!"https".equalsIgnoreCase(uri.getScheme())) { //$NON-NLS-1$
				throw new IllegalArgumentException("La LOTL debe descargarse por HTTPS"); //$NON-NLS-1$
			}
			if (uri.getHost() == null || uri.getHost().isBlank()) {
				throw new IllegalArgumentException("La LOTL debe descargarse desde una URI con host"); //$NON-NLS-1$
			}
			if (uri.getRawUserInfo() != null) {
				throw new IllegalArgumentException("La URI LOTL no admite userinfo"); //$NON-NLS-1$
			}
			if (uri.getRawFragment() != null) {
				throw new IllegalArgumentException("La URI LOTL no admite fragmento"); //$NON-NLS-1$
			}
			if (uri.getRawQuery() != null) {
				throw new IllegalArgumentException("La URI LOTL no admite query"); //$NON-NLS-1$
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
