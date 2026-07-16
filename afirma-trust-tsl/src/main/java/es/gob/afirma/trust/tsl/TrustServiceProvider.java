/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * Proveedor de Servicios de Confianza (TSP) extraído de una TSL nacional
 * (ETSI TS 119 612 §5.4 — {@code <TrustServiceProvider>}).
 *
 * <p>Cada nodo agrupa varios servicios cualificados (firma electrónica,
 * sello, time-stamp, etc.) ligados a una entidad jurídica concreta. El
 * pipeline de validación de Autofirma usa este modelo para responder a la
 * pregunta «¿este certificado fue emitido por un proveedor calificado para
 * el servicio X en el momento Y?».</p>
 */
public record TrustServiceProvider(
		String name,
		String tradeName,
		String countryCode,
		List<TrustService> services) {

	public TrustServiceProvider {
		Objects.requireNonNull(name, "name");
		Objects.requireNonNull(countryCode, "countryCode");
		if (name.isBlank()) {
			throw new IllegalArgumentException("Nombre TSP vacío"); //$NON-NLS-1$
		}
		if (countryCode.isBlank()) {
			throw new IllegalArgumentException("País TSP vacío"); //$NON-NLS-1$
		}
		services = services == null ? List.of() : List.copyOf(services);
	}

	/**
	 * Servicio individual ofrecido por el TSP. La granularidad (Q-CertESign,
	 * Q-CertESeal, Q-TSA, etc.) viene determinada por la URI {@code typeIdentifier}
	 * del estándar ETSI.
	 */
	public record TrustService(
			String typeIdentifier,
			String status,
			List<X509Certificate> serviceDigitalIdentities) {

		public TrustService {
			Objects.requireNonNull(typeIdentifier, "typeIdentifier");
			Objects.requireNonNull(status, "status");
			if (typeIdentifier.isBlank()) {
				throw new IllegalArgumentException("Tipo de servicio TSL vacío"); //$NON-NLS-1$
			}
			if (status.isBlank()) {
				throw new IllegalArgumentException("Estado de servicio TSL vacío"); //$NON-NLS-1$
			}
			serviceDigitalIdentities = serviceDigitalIdentities == null
					? List.of()
					: List.copyOf(serviceDigitalIdentities);
		}

		/** Heurística rápida: ¿este servicio está actualmente <em>granted</em>?
		 *  ETSI TS 119 612 §5.5.4 — el estatus URI termina en {@code /granted}. */
		public boolean isGranted() {
			return status != null && status.endsWith("/granted"); //$NON-NLS-1$
		}
	}
}
