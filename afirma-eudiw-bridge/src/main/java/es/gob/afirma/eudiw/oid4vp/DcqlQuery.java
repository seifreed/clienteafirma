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
			validateJsonTree(parsed);
			final var credentials = JSONObjectUtils.getJSONArray(parsed, "credentials"); //$NON-NLS-1$
			if (credentials == null || credentials.isEmpty()) {
				throw new IllegalArgumentException("dcql_query debe declarar credentials"); //$NON-NLS-1$
			}
			final Set<String> ids = new HashSet<>();
			for (final Object credential : credentials) {
				if (!(credential instanceof Map<?, ?> credentialMap)) {
					throw new IllegalArgumentException("credentials DCQL debe contener objetos"); //$NON-NLS-1$
				}
				validateObjectKeys(credentialMap);
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
					final Set<String> claimIds = new HashSet<>();
					for (final Object claim : claimList) {
						if (!(claim instanceof Map<?, ?> claimMap)) {
							throw new IllegalArgumentException("claims DCQL debe contener objetos"); //$NON-NLS-1$
						}
						validateObjectKeys(claimMap);
						final Object claimId = claimMap.get("id"); //$NON-NLS-1$
						if (claimId != null) {
							if (!(claimId instanceof String text) || !isNormalizedText(text)) {
								throw new IllegalArgumentException("claim DCQL con id inválido"); //$NON-NLS-1$
							}
							if (!claimIds.add(text)) {
								throw new IllegalArgumentException("claim DCQL con id duplicado"); //$NON-NLS-1$
							}
						}
						final Object path = claimMap.get("path"); //$NON-NLS-1$
						if (path == null) {
							throw new IllegalArgumentException("claim DCQL sin path"); //$NON-NLS-1$
						}
						validateClaimPath(path);
					}
				}
			}
		}
		catch (final ParseException e) {
			throw new IllegalArgumentException("dcql_query debe ser un objeto JSON válido", e); //$NON-NLS-1$
		}
	}

	private static void validateJsonTree(final Object value) {
		if (value instanceof Map<?, ?> map) {
			validateObjectKeys(map);
			for (final Object child : map.values()) {
				validateJsonTree(child);
			}
		}
		if (value instanceof List<?> list) {
			for (final Object child : list) {
				validateJsonTree(child);
			}
		}
		if (value instanceof String text && !isNormalizedText(text)) {
			throw new IllegalArgumentException("dcql_query contiene valores no normalizados"); //$NON-NLS-1$
		}
	}

	private static void validateObjectKeys(final Map<?, ?> json) {
		for (final Object key : json.keySet()) {
			if (!(key instanceof String text) || !isNormalizedText(text)) {
				throw new IllegalArgumentException("dcql_query contiene claves no normalizadas"); //$NON-NLS-1$
			}
		}
	}

	private static void validateClaimPath(final Object path) {
		if (!(path instanceof List<?> components) || components.isEmpty()) {
			throw new IllegalArgumentException("claim DCQL con path inválido"); //$NON-NLS-1$
		}
		for (final Object component : components) {
			if (!(component instanceof String text) || !isNormalizedText(text)) {
				throw new IllegalArgumentException("claim DCQL con path inválido"); //$NON-NLS-1$
			}
		}
	}

	private static String requireText(final Map<?, ?> json, final String key) {
		final Object value = json.get(key);
		if (!(value instanceof String text) || text.isBlank()) {
			throw new IllegalArgumentException("credential DCQL sin " + key); //$NON-NLS-1$
		}
		if (!isNormalizedText(text)) {
			throw new IllegalArgumentException("credential DCQL con " + key + " no normalizado"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		return text;
	}

	private static boolean isNormalizedText(final String text) {
		return !text.isBlank()
				&& text.equals(text.strip())
				&& text.chars().noneMatch(Character::isISOControl);
	}
}
