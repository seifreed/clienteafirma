/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.oid4vp;

import java.text.ParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.nimbusds.jose.util.JSONObjectUtils;

/** Consulta DCQL nativa para OID4VP. */
public record DcqlQuery(String json) {

	private static final String SUPPORTED_FORMAT = "dc+sd-jwt"; //$NON-NLS-1$

	public DcqlQuery {
		Objects.requireNonNull(json, "json"); //$NON-NLS-1$
		if (json.isBlank()) {
			throw new IllegalArgumentException("dcql_query vacía"); //$NON-NLS-1$
		}
		if (!json.equals(json.strip())) {
			throw new IllegalArgumentException("dcql_query no normalizada"); //$NON-NLS-1$
		}
		try {
			final var parsed = JSONObjectUtils.parse(json);
			final var credentials = JSONObjectUtils.getJSONArray(parsed, "credentials"); //$NON-NLS-1$
			if (credentials == null || credentials.isEmpty()) {
				throw new IllegalArgumentException("dcql_query debe declarar credentials"); //$NON-NLS-1$
			}
			final Set<String> ids = new HashSet<>();
			for (final Object credential : credentials) {
				if (!(credential instanceof Map<?, ?> credentialMap)) {
					throw new IllegalArgumentException("credentials DCQL debe contener objetos"); //$NON-NLS-1$
				}
				if (!ids.add(requireText(credentialMap, "id"))) { //$NON-NLS-1$
					throw new IllegalArgumentException("credential DCQL con id duplicado"); //$NON-NLS-1$
				}
				final String format = requireText(credentialMap, "format"); //$NON-NLS-1$
				if (!SUPPORTED_FORMAT.equals(format)) {
					throw new IllegalArgumentException("credential DCQL con format no soportado: " + format); //$NON-NLS-1$
				}
				final Object claims = credentialMap.get("claims"); //$NON-NLS-1$
				if (claims != null && (!(claims instanceof List<?> claimList) || claimList.isEmpty())) {
					throw new IllegalArgumentException("credential DCQL con claims inválido"); //$NON-NLS-1$
				}
				if (claims instanceof List<?> claimList) {
					for (final Object claim : claimList) {
						if (!(claim instanceof Map<?, ?>)) {
							throw new IllegalArgumentException("claims DCQL debe contener objetos"); //$NON-NLS-1$
						}
					}
				}
			}
		}
		catch (final ParseException e) {
			throw new IllegalArgumentException("dcql_query debe ser un objeto JSON válido", e); //$NON-NLS-1$
		}
	}

	private static String requireText(final Map<?, ?> json, final String key) {
		final Object value = json.get(key);
		if (!(value instanceof String text) || text.isBlank()) {
			throw new IllegalArgumentException("credential DCQL sin " + key); //$NON-NLS-1$
		}
		if (!text.equals(text.strip())) {
			throw new IllegalArgumentException("credential DCQL con " + key + " no normalizado"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		return text;
	}
}
