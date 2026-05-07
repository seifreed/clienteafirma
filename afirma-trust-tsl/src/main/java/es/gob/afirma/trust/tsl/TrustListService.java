/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import java.security.cert.X509Certificate;
import java.util.List;
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
 * <p><strong>TODO M4.x:</strong> persistencia local de la cache, refresh policy
 * (24h por defecto en el AEAD-SE), feed de la LOTL europea
 * (https://ec.europa.eu/tools/lotl/eu-lotl.xml) y validación cruzada del
 * certificado firmante de la LOTL contra la lista pública de la Comisión.</p>
 */
public final class TrustListService {

	private final ConcurrentMap<String, TslDocument> byTerritory = new ConcurrentHashMap<>();

	/** Añade o reemplaza la TSL de un territorio. */
	public void ingest(final TslDocument tsl) {
		this.byTerritory.put(tsl.territory().toUpperCase(), tsl);
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
	 * <p>Compara el subject del certificado contra los <em>service digital
	 * identities</em> publicados en cada {@link TrustServiceProvider.TrustService}.
	 * En la versión final esta comparación debe usar issuer + serial number
	 * (RFC 5280) para evitar falsos positivos por re-emisión.</p>
	 */
	public Optional<TrustServiceProvider> findIssuer(final X509Certificate cert) {
		if (cert == null) {
			return Optional.empty();
		}
		for (final TslDocument tsl : this.byTerritory.values()) {
			for (final TrustServiceProvider tsp : tsl.providers()) {
				if (matches(tsp, cert)) {
					return Optional.of(tsp);
				}
			}
		}
		return Optional.empty();
	}

	private static boolean matches(final TrustServiceProvider tsp, final X509Certificate cert) {
		final List<TrustServiceProvider.TrustService> services = tsp.services();
		for (final TrustServiceProvider.TrustService svc : services) {
			for (final X509Certificate sdi : svc.serviceDigitalIdentities()) {
				if (sdi.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
					return true;
				}
			}
		}
		return false;
	}
}
