/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Documento TSL parseado (ETSI TS 119 612), a la espera de validación
 * criptográfica por {@link TslVerifier}.
 *
 * <p>El campo {@link #signed} indica únicamente que la firma XMLDSig
 * está presente y bien formada — la verificación contra el certificado
 * del firmante de la LOTL es responsabilidad del verificador.</p>
 */
public record TslDocument(
		String schemeOperatorName,
		String territory,
		Instant nextUpdate,
		List<TrustServiceProvider> providers,
		boolean signed) {

	public TslDocument {
		Objects.requireNonNull(schemeOperatorName, "schemeOperatorName");
		Objects.requireNonNull(territory, "territory");
		if (schemeOperatorName.isBlank()) {
			throw new IllegalArgumentException("Operador TSL vacío"); //$NON-NLS-1$
		}
		if (territory.isBlank()) {
			throw new IllegalArgumentException("Territorio TSL vacío"); //$NON-NLS-1$
		}
		if (!schemeOperatorName.equals(schemeOperatorName.strip())) {
			throw new IllegalArgumentException("Operador TSL no normalizado"); //$NON-NLS-1$
		}
		if (!territory.equals(territory.strip())) {
			throw new IllegalArgumentException("Territorio TSL no normalizado"); //$NON-NLS-1$
		}
		if (!territory.matches("[A-Z]{2}")) { //$NON-NLS-1$
			throw new IllegalArgumentException("Territorio TSL no es ISO alpha-2"); //$NON-NLS-1$
		}
		if (providers != null) {
			for (final TrustServiceProvider provider : providers) {
				if (provider == null) {
					throw new IllegalArgumentException("Proveedor TSL vacío"); //$NON-NLS-1$
				}
			}
		}
		providers = providers == null ? List.of() : List.copyOf(providers);
	}
}
