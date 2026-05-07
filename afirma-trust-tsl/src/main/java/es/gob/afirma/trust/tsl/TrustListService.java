/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.security.auth.x500.X500Principal;

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
 * <p>El lookup es O(1): al ingestar una TSL se construye un índice
 * {@code issuer subject DN → TSP}. Reemplazar una TSL del mismo territorio
 * limpia las entradas previas asociadas a ella.</p>
 *
 * <p><strong>TODO M4.x:</strong> persistencia local de la cache, refresh policy
 * (24h por defecto en la AEAD-SE), feed de la LOTL europea
 * (https://ec.europa.eu/tools/lotl/eu-lotl.xml) y validación cruzada del
 * certificado firmante de la LOTL contra la lista pública de la Comisión.
 * Comparación issuer+serial (RFC 5280) en lugar de solo subject DN para evitar
 * falsos positivos por re-emisión de CA.</p>
 */
public final class TrustListService {

	private final ConcurrentMap<String, TslDocument> byTerritory = new ConcurrentHashMap<>();
	private final ConcurrentMap<X500Principal, TrustServiceProvider> byIssuerSubject = new ConcurrentHashMap<>();

	/** Añade o reemplaza la TSL de un territorio. Reconstruye el índice de issuers. */
	public void ingest(final TslDocument tsl) {
		final String key = tsl.territory().toUpperCase();
		final TslDocument previous = this.byTerritory.put(key, tsl);
		if (previous != null) {
			removeFromIssuerIndex(previous);
		}
		addToIssuerIndex(tsl);
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
	 * Resuelve un certificado de firma a su {@link TrustServiceProvider} en O(1).
	 *
	 * <p>Compara el {@code issuer DN} del certificado contra los <em>service
	 * digital identities</em> indexados al ingestar.</p>
	 */
	public Optional<TrustServiceProvider> findIssuer(final X509Certificate cert) {
		if (cert == null) {
			return Optional.empty();
		}
		return Optional.ofNullable(this.byIssuerSubject.get(cert.getIssuerX500Principal()));
	}

	private void addToIssuerIndex(final TslDocument tsl) {
		for (final TrustServiceProvider tsp : tsl.providers()) {
			for (final TrustServiceProvider.TrustService svc : tsp.services()) {
				for (final X509Certificate sdi : svc.serviceDigitalIdentities()) {
					this.byIssuerSubject.put(sdi.getSubjectX500Principal(), tsp);
				}
			}
		}
	}

	private void removeFromIssuerIndex(final TslDocument tsl) {
		for (final TrustServiceProvider tsp : tsl.providers()) {
			for (final TrustServiceProvider.TrustService svc : tsp.services()) {
				for (final X509Certificate sdi : svc.serviceDigitalIdentities()) {
					// Solo limpiamos si la entrada actual aún apunta a este TSP — otra
					// TSL del mismo territorio puede haber registrado la misma identidad.
					this.byIssuerSubject.remove(sdi.getSubjectX500Principal(), tsp);
				}
			}
		}
	}
}
