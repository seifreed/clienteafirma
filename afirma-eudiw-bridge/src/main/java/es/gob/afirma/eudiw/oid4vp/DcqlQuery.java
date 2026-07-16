/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.oid4vp;

import java.text.ParseException;
import java.util.Map;
import java.util.Objects;

import com.nimbusds.jose.util.JSONObjectUtils;

/** Consulta DCQL nativa para OID4VP. */
public record DcqlQuery(String json) {

	public DcqlQuery {
		Objects.requireNonNull(json, "json"); //$NON-NLS-1$
		try {
			final var parsed = JSONObjectUtils.parse(json);
			final var credentials = JSONObjectUtils.getJSONArray(parsed, "credentials"); //$NON-NLS-1$
			if (credentials == null || credentials.isEmpty()) {
				throw new IllegalArgumentException("dcql_query debe declarar credentials"); //$NON-NLS-1$
			}
			for (final Object credential : credentials) {
				if (!(credential instanceof Map<?, ?> credentialMap)) {
					throw new IllegalArgumentException("credentials DCQL debe contener objetos"); //$NON-NLS-1$
				}
				requireText(credentialMap, "id"); //$NON-NLS-1$
				requireText(credentialMap, "format"); //$NON-NLS-1$
			}
		}
		catch (final ParseException e) {
			throw new IllegalArgumentException("dcql_query debe ser un objeto JSON válido", e); //$NON-NLS-1$
		}
	}

	private static void requireText(final Map<?, ?> json, final String key) {
		final Object value = json.get(key);
		if (!(value instanceof String text) || text.isBlank()) {
			throw new IllegalArgumentException("credential DCQL sin " + key); //$NON-NLS-1$
		}
	}
}
