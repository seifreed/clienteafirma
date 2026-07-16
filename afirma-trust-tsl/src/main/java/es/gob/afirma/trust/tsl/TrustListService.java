/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * API consultable de la TSL: «¿este certificado pertenece a un proveedor
 * calificado para servicio X?». Carga TSLs en memoria y las cachea por
 * código de territorio.
 *
 * <p>Diseñado pensando en el flujo:</p>
 *
 * <ol>
 *   <li>{@link #ingest(TslDocument)} para cada TSL nacional descargada de la LOTL.</li>
 *   <li>{@link #findIssuer(X509Certificate)} para resolver un certificado de firma
 *       hacia su TSP (responde con {@link TrustServiceProvider} o
 *       {@link Optional#empty()} si no es de un emisor cualificado).</li>
 * </ol>
 *
 * <p>El lookup comprueba que el certificado consultado fue firmado por una de
 * las identidades de servicio publicadas en la TSL; no basta con que coincida
 * el DN del issuer.</p>
 *
 * <p>La descarga HTTPS, persistencia local y verificación de la LOTL se hacen
 * en {@link LotlLoader}; aquí solo se gobierna la cache en memoria.</p>
 */
public final class TrustListService {

	private static final Duration DEFAULT_REFRESH_INTERVAL = Duration.ofHours(24);

	private final ConcurrentMap<String, TslDocument> byTerritory = new ConcurrentHashMap<>();
	private final ConcurrentMap<String, Instant> loadedAt = new ConcurrentHashMap<>();
	private final Clock clock;
	private final Duration refreshInterval;

	public TrustListService() {
		this(Clock.systemUTC(), DEFAULT_REFRESH_INTERVAL);
	}

	TrustListService(final Clock clock, final Duration refreshInterval) {
		this.clock = Objects.requireNonNull(clock, "clock"); //$NON-NLS-1$
		this.refreshInterval = Objects.requireNonNull(refreshInterval, "refreshInterval"); //$NON-NLS-1$
	}

	/** Añade o reemplaza la TSL de un territorio. */
	public void ingest(final TslDocument tsl) {
		final String key = tsl.territory().toUpperCase();
		this.byTerritory.put(key, tsl);
		this.loadedAt.put(key, Instant.now(this.clock));
	}

	/**
	 * Devuelve la TSL en cache si sigue fresca; si no, la carga con el loader
	 * indicado y la ingesta antes de devolverla.
	 */
	public TslDocument getOrRefresh(final String territory, final TslLoader loader)
			throws TslException {
		final String key = territory.toUpperCase();
		final TslDocument cached = this.byTerritory.get(key);
		if (cached != null && !isExpired(key, cached)) {
			return cached;
		}
		final TslDocument loaded = loader.load();
		if (!key.equals(loaded.territory().toUpperCase())) {
			throw new TslException("La TSL cargada no corresponde al territorio " + territory); //$NON-NLS-1$
		}
		ingest(loaded);
		return loaded;
	}

	/** Lookup directo por código ISO-3166-1 alpha-2. */
	public Optional<TslDocument> get(final String territory) {
		return Optional.ofNullable(this.byTerritory.get(territory.toUpperCase()));
	}

	/** Total de TSLs cargadas. */
	public int loadedCount() {
		return this.byTerritory.size();
	}

	/**
	 * Resuelve un certificado de firma a su {@link TrustServiceProvider}.
	 *
	 * <p>Compara el {@code issuer DN} contra los <em>service digital identities</em>
	 * y verifica criptográficamente la firma del certificado con la clave pública
	 * de la identidad candidata.</p>
	 */
	public Optional<TrustServiceProvider> findIssuer(final X509Certificate cert) {
		if (cert == null) {
			return Optional.empty();
		}
		for (final TslDocument tsl : this.byTerritory.values()) {
			for (final TrustServiceProvider tsp : tsl.providers()) {
				for (final TrustServiceProvider.TrustService svc : tsp.services()) {
					if (!svc.isGranted()) {
						continue;
					}
					for (final X509Certificate sdi : svc.serviceDigitalIdentities()) {
						if (isIssuedBy(cert, sdi)) {
							return Optional.of(tsp);
						}
					}
				}
			}
		}
		return Optional.empty();
	}

	private static boolean isIssuedBy(final X509Certificate cert, final X509Certificate issuer) {
		if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
			return false;
		}
		try {
			cert.verify(issuer.getPublicKey());
			return true;
		}
		catch (final Exception e) {
			return false;
		}
	}

	private boolean isExpired(final String territory, final TslDocument cached) {
		final Instant timestamp = this.loadedAt.get(territory);
		if (timestamp == null) {
			return true;
		}
		final Instant now = Instant.now(this.clock);
		if (!now.isBefore(timestamp.plus(this.refreshInterval))) {
			return true;
		}
		return cached.nextUpdate() != null && !now.isBefore(cached.nextUpdate());
	}

	@FunctionalInterface
	public interface TslLoader {
		TslDocument load() throws TslException;
	}
}
