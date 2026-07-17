/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.oid4vp;

import java.text.ParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

import com.nimbusds.jose.util.JSONObjectUtils;

/** Consulta DCQL nativa para OID4VP. */
public record DcqlQuery(String json) {

	private static final String SUPPORTED_FORMAT = "dc+sd-jwt"; //$NON-NLS-1$
	private static final String SUPPORTED_TRUSTED_AUTHORITY_TYPE = "etsi_tl"; //$NON-NLS-1$
	private static final Pattern ID_PATTERN = Pattern.compile("[A-Za-z0-9_-]+"); //$NON-NLS-1$

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
				if (!ids.add(requireId(credentialMap, "id"))) { //$NON-NLS-1$
					throw new IllegalArgumentException("credential DCQL con id duplicado"); //$NON-NLS-1$
				}
				final String format = requireText(credentialMap, "format"); //$NON-NLS-1$
				if (!SUPPORTED_FORMAT.equals(format)) {
					throw new IllegalArgumentException("credential DCQL con format no soportado: " + format); //$NON-NLS-1$
				}
				validateOptionalBoolean(credentialMap.get("multiple"), "multiple"); //$NON-NLS-1$ //$NON-NLS-2$
				validateOptionalBoolean(credentialMap.get("require_cryptographic_holder_binding"), //$NON-NLS-1$
						"require_cryptographic_holder_binding"); //$NON-NLS-1$
				validateMeta(credentialMap.get("meta")); //$NON-NLS-1$
				validateTrustedAuthorities(credentialMap.get("trusted_authorities")); //$NON-NLS-1$
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
							if (!(claimId instanceof String text) || !isId(text)) {
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
						validateClaimValues(claimMap.get("values")); //$NON-NLS-1$
					}
					validateClaimSets(credentialMap.get("claim_sets"), claimIds); //$NON-NLS-1$
				}
				else if (credentialMap.containsKey("claim_sets")) { //$NON-NLS-1$
					throw new IllegalArgumentException("credential DCQL con claim_sets sin claims"); //$NON-NLS-1$
				}
			}
			validateCredentialSets(parsed.get("credential_sets"), ids); //$NON-NLS-1$
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

	private static void validateMeta(final Object value) {
		if (value != null && !(value instanceof Map<?, ?>)) {
			throw new IllegalArgumentException("credential DCQL con meta inválido"); //$NON-NLS-1$
		}
	}

	private static void validateOptionalBoolean(final Object value, final String key) {
		if (value != null && !(value instanceof Boolean)) {
			throw new IllegalArgumentException("credential DCQL con " + key + " inválido"); //$NON-NLS-1$ //$NON-NLS-2$
		}
	}

	private static void validateTrustedAuthorities(final Object value) {
		if (value == null) {
			return;
		}
		if (!(value instanceof List<?> authorities) || authorities.isEmpty()) {
			throw new IllegalArgumentException("trusted_authorities DCQL inválido"); //$NON-NLS-1$
		}
		for (final Object authority : authorities) {
			if (!(authority instanceof Map<?, ?> authorityMap)) {
				throw new IllegalArgumentException("trusted_authorities DCQL debe contener objetos"); //$NON-NLS-1$
			}
			final String type = requireText(authorityMap, "type"); //$NON-NLS-1$
			if (!SUPPORTED_TRUSTED_AUTHORITY_TYPE.equals(type)) {
				throw new IllegalArgumentException(
						"trusted_authorities DCQL con type no soportado: " + type); //$NON-NLS-1$
			}
			final Object values = authorityMap.get("values"); //$NON-NLS-1$
			if (!(values instanceof List<?> valueList) || valueList.isEmpty()) {
				throw new IllegalArgumentException("trusted_authorities DCQL sin values"); //$NON-NLS-1$
			}
			final Set<String> seenValues = new HashSet<>();
			for (final Object authorityValue : valueList) {
				if (!(authorityValue instanceof String text) || !isNormalizedText(text)
						|| !seenValues.add(text)) {
					throw new IllegalArgumentException("trusted_authorities DCQL con value inválido"); //$NON-NLS-1$
				}
			}
		}
	}

	private static void validateClaimValues(final Object value) {
		if (value == null) {
			return;
		}
		if (!(value instanceof List<?> values) || values.isEmpty()) {
			throw new IllegalArgumentException("claim DCQL con values inválido"); //$NON-NLS-1$
		}
		for (final Object item : values) {
			if (!(item instanceof String || item instanceof Boolean || isInteger(item))) {
				throw new IllegalArgumentException("claim DCQL con values inválido"); //$NON-NLS-1$
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

	private static String requireId(final Map<?, ?> json, final String key) {
		final String text = requireText(json, key);
		if (!isId(text)) {
			throw new IllegalArgumentException("credential DCQL con " + key + " inválido"); //$NON-NLS-1$ //$NON-NLS-2$
		}
		return text;
	}

	private static void validateClaimSets(final Object value, final Set<String> claimIds) {
		if (value == null) {
			return;
		}
		if (!(value instanceof List<?> sets) || sets.isEmpty()) {
			throw new IllegalArgumentException("claim_sets DCQL inválido"); //$NON-NLS-1$
		}
		for (final Object option : sets) {
			validateIdList(option, claimIds, "claim_sets DCQL referencia claim inexistente"); //$NON-NLS-1$
		}
	}

	private static void validateCredentialSets(final Object value, final Set<String> credentialIds) {
		if (value == null) {
			return;
		}
		if (!(value instanceof List<?> sets) || sets.isEmpty()) {
			throw new IllegalArgumentException("credential_sets DCQL inválido"); //$NON-NLS-1$
		}
		for (final Object set : sets) {
			if (!(set instanceof Map<?, ?> setMap)) {
				throw new IllegalArgumentException("credential_sets DCQL debe contener objetos"); //$NON-NLS-1$
			}
			final Object options = setMap.get("options"); //$NON-NLS-1$
			if (!(options instanceof List<?> optionList) || optionList.isEmpty()) {
				throw new IllegalArgumentException("credential_sets DCQL sin options"); //$NON-NLS-1$
			}
			if (setMap.containsKey("required") && !(setMap.get("required") instanceof Boolean)) { //$NON-NLS-1$ //$NON-NLS-2$
				throw new IllegalArgumentException("credential_sets DCQL con required inválido"); //$NON-NLS-1$
			}
			for (final Object option : optionList) {
				validateIdList(option, credentialIds, "credential_sets DCQL referencia credential inexistente"); //$NON-NLS-1$
			}
		}
	}

	private static void validateIdList(final Object option, final Set<String> validIds,
			final String error) {
		if (!(option instanceof List<?> ids) || ids.isEmpty()) {
			throw new IllegalArgumentException(error);
		}
		final Set<String> seen = new HashSet<>();
		for (final Object id : ids) {
			if (!(id instanceof String text) || !isId(text) || !validIds.contains(text) || !seen.add(text)) {
				throw new IllegalArgumentException(error);
			}
		}
	}

	private static boolean isNormalizedText(final String text) {
		return !text.isBlank()
				&& text.equals(text.strip())
				&& text.chars().noneMatch(Character::isISOControl);
	}

	private static boolean isId(final String text) {
		return isNormalizedText(text) && ID_PATTERN.matcher(text).matches();
	}

	private static boolean isInteger(final Object value) {
		return value instanceof Byte || value instanceof Short || value instanceof Integer
				|| value instanceof Long || value instanceof java.math.BigInteger;
	}
}
