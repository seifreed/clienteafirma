/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.configurator.common;

/**
 * Catálogo de claves de preferencias relacionadas con la configuración
 * de proxy HTTP/HTTPS.
 *
 * <p>Reexporta las 7 constantes {@code public static final String} que
 * estaban en {@link PreferencesManager} con el prefijo
 * {@code PREFERENCE_GENERAL_PROXY_*}. Bajo el catálogo de proxy estos
 * valores son cohesivos y merecen su propia clase, aunque originalmente
 * pertenecían al dominio "General" de {@link PreferencesManager}.</p>
 *
 * <p>Primera fase del split temático: la fuente de verdad sigue siendo
 * {@link PreferencesManager}. Sesiones futuras pueden invertir la
 * dependencia.</p>
 */
public final class ProxyPreferenceKeys {

	private ProxyPreferenceKeys() {
		// No permitimos la instanciacion
	}

	/** Flag que indica si el usuario ha seleccionado configuración manual de proxy. */
	public static final String PROXY_SELECTED = PreferencesManager.PREFERENCE_GENERAL_PROXY_SELECTED;

	/** Tipo de proxy (HTTP, HTTPS, SOCKS). */
	public static final String PROXY_TYPE = PreferencesManager.PREFERENCE_GENERAL_PROXY_TYPE;

	/** Host del proxy. */
	public static final String PROXY_HOST = PreferencesManager.PREFERENCE_GENERAL_PROXY_HOST;

	/** Puerto del proxy. */
	public static final String PROXY_PORT = PreferencesManager.PREFERENCE_GENERAL_PROXY_PORT;

	/** Usuario para autenticación del proxy (puede estar vacío). */
	public static final String PROXY_USERNAME = PreferencesManager.PREFERENCE_GENERAL_PROXY_USERNAME;

	/** Contraseña para autenticación del proxy (almacenada en preferencias). */
	public static final String PROXY_PASSWORD = PreferencesManager.PREFERENCE_GENERAL_PROXY_PASSWORD;

	/** Lista de URLs que no deben pasar por el proxy. */
	public static final String PROXY_EXCLUDED_URLS = PreferencesManager.PREFERENCE_GENERAL_PROXY_EXCLUDED_URLS;
}
