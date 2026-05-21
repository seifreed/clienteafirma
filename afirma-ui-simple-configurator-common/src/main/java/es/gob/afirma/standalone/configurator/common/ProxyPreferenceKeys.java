/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.configurator.common;

/**
 * Catálogo de claves de preferencias relacionadas con la configuración
 * de proxy HTTP/HTTPS.
 *
 * <p>Esta clase es la <strong>fuente de verdad</strong> de las 7 claves
 * del dominio proxy: aquí residen los valores literales.
 * {@link PreferencesManager} mantiene sus constantes
 * {@code PREFERENCE_GENERAL_PROXY_*} como aliases que apuntan aquí.
 * Bajo el catálogo de proxy estos valores son cohesivos y merecen su
 * propia clase, aunque originalmente pertenecían al dominio "General"
 * de {@link PreferencesManager}.</p>
 */
public final class ProxyPreferenceKeys {

	private ProxyPreferenceKeys() {
		// No permitimos la instanciacion
	}

	/** Flag que indica si el usuario ha seleccionado configuración manual de proxy. */
	public static final String PROXY_SELECTED = "proxySelected"; //$NON-NLS-1$

	/** Tipo de proxy (HTTP, HTTPS, SOCKS). */
	public static final String PROXY_TYPE = "proxyType"; //$NON-NLS-1$

	/** Host del proxy. */
	public static final String PROXY_HOST = "proxyHost"; //$NON-NLS-1$

	/** Puerto del proxy. */
	public static final String PROXY_PORT = "proxyPort"; //$NON-NLS-1$

	/** Usuario para autenticación del proxy (puede estar vacío). */
	public static final String PROXY_USERNAME = "proxyUsername"; //$NON-NLS-1$

	/** Contraseña para autenticación del proxy (almacenada en preferencias). */
	public static final String PROXY_PASSWORD = "proxyPassword"; //$NON-NLS-1$

	/** Lista de URLs que no deben pasar por el proxy. */
	public static final String PROXY_EXCLUDED_URLS = "proxyExcludedUrls"; //$NON-NLS-1$
}
