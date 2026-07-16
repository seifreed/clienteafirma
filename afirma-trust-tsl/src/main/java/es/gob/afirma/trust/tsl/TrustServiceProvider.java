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

	private static final String SERVICE_STATUS_GRANTED =
			"http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"; //$NON-NLS-1$

	public TrustServiceProvider {
		Objects.requireNonNull(name, "name");
		Objects.requireNonNull(countryCode, "countryCode");
		if (name.isBlank()) {
			throw new IllegalArgumentException("Nombre TSP vacío"); //$NON-NLS-1$
		}
		if (!name.equals(name.strip())) {
			throw new IllegalArgumentException("Nombre TSP no normalizado"); //$NON-NLS-1$
		}
		if (containsControlChars(name)) {
			throw new IllegalArgumentException("Nombre TSP contiene caracteres de control"); //$NON-NLS-1$
		}
		if (tradeName != null && tradeName.isBlank()) {
			throw new IllegalArgumentException("Nombre comercial TSP vacío"); //$NON-NLS-1$
		}
		if (tradeName != null && !tradeName.equals(tradeName.strip())) {
			throw new IllegalArgumentException("Nombre comercial TSP no normalizado"); //$NON-NLS-1$
		}
		if (tradeName != null && containsControlChars(tradeName)) {
			throw new IllegalArgumentException("Nombre comercial TSP contiene caracteres de control"); //$NON-NLS-1$
		}
		if (countryCode.isBlank()) {
			throw new IllegalArgumentException("País TSP vacío"); //$NON-NLS-1$
		}
		if (!countryCode.equals(countryCode.strip())) {
			throw new IllegalArgumentException("País TSP no normalizado"); //$NON-NLS-1$
		}
		if (!countryCode.matches("[A-Z]{2}")) { //$NON-NLS-1$
			throw new IllegalArgumentException("País TSP no es ISO alpha-2"); //$NON-NLS-1$
		}
		if (services != null) {
			for (final TrustService service : services) {
				if (service == null) {
					throw new IllegalArgumentException("Servicio TSL vacío"); //$NON-NLS-1$
				}
			}
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
			if (!typeIdentifier.equals(typeIdentifier.strip())) {
				throw new IllegalArgumentException("Tipo de servicio TSL no normalizado"); //$NON-NLS-1$
			}
			if (!status.equals(status.strip())) {
				throw new IllegalArgumentException("Estado de servicio TSL no normalizado"); //$NON-NLS-1$
			}
			if (containsControlChars(typeIdentifier)) {
				throw new IllegalArgumentException("Tipo de servicio TSL contiene caracteres de control"); //$NON-NLS-1$
			}
			if (containsControlChars(status)) {
				throw new IllegalArgumentException("Estado de servicio TSL contiene caracteres de control"); //$NON-NLS-1$
			}
			if (serviceDigitalIdentities != null) {
				for (final X509Certificate identity : serviceDigitalIdentities) {
					if (identity == null) {
						throw new IllegalArgumentException("Identidad de servicio TSL vacía"); //$NON-NLS-1$
					}
				}
			}
			serviceDigitalIdentities = serviceDigitalIdentities == null
					? List.of()
					: List.copyOf(serviceDigitalIdentities);
		}

		/** ¿Este servicio está actualmente <em>granted</em>? */
		public boolean isGranted() {
			return SERVICE_STATUS_GRANTED.equals(status);
		}
	}

	private static boolean containsControlChars(final String text) {
		return text.chars().anyMatch(Character::isISOControl);
	}
}
