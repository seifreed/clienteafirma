/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.configurator.common;

/**
 * Catálogo de claves de preferencias relacionadas con el almacén de
 * certificados (keystore) de la aplicación.
 *
 * <p>Reexporta las 5 constantes {@code public static final String} que
 * estaban dispersas en {@link PreferencesManager} bajo nombres más
 * cortos (sin el prefijo {@code PREFERENCE_}). Los valores apuntan a
 * las constantes existentes; cero callsites cambian.</p>
 *
 * <p>Primera fase del split temático: la fuente de verdad sigue siendo
 * {@link PreferencesManager}. Sesiones futuras pueden invertir la
 * dependencia.</p>
 */
public final class KeyStorePreferenceKeys {

	private KeyStorePreferenceKeys() {
		// No permitimos la instanciacion
	}

	/** Almacén de certificados por defecto. */
	public static final String DEFAULT_STORE = PreferencesManager.PREFERENCE_KEYSTORE_DEFAULT_STORE;

	/** Filtrar certificados que solo permitan firma. */
	public static final String SIGN_ONLY_CERTS = PreferencesManager.PREFERENCE_KEYSTORE_SIGN_ONLY_CERTS;

	/** Mostrar certificados expirados en la lista de selección. */
	public static final String SHOW_EXPIRED_CERTS = PreferencesManager.PREFERENCE_KEYSTORE_SHOWEXPIREDCERTS;

	/** Filtrar certificados por alias. */
	public static final String ALIAS_ONLY_CERTS = PreferencesManager.PREFERENCE_KEYSTORE_ALIAS_ONLY_CERTS;

	/** Saltar el certificado de autenticación del DNIe (usar solo el de firma). */
	public static final String SKIP_AUTH_CERT_DNIE = PreferencesManager.PREFERENCE_KEYSTORE_SKIP_AUTH_CERT_DNIE;
}
