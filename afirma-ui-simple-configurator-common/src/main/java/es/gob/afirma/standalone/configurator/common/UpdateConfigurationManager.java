/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.configurator.common;

/**
 * Fachada del dominio "Actualización automática de configuración" de
 * {@link PreferencesManager}.
 *
 * <p>Agrupa los métodos públicos y las claves de preferencias internas
 * relacionados con la actualización automática de configuración del
 * sistema. Sus claves se almacenan en un nodo dedicado de
 * {@link java.util.prefs.Preferences} ({@code /es/gob/afirma/standalone/ui/internalpreferences})
 * separado del nodo de preferencias de usuario y sistema.</p>
 *
 * <p>Esta clase es la primera fase del split temático de
 * {@link PreferencesManager}: expone una API estable al dominio de
 * actualización de configuración mientras la implementación sigue
 * residiendo en {@link PreferencesManager}. Sesiones futuras moverán el
 * estado ({@code INTERNAL_PREFERENCES}, {@code INTERNAL_PREFERENCES_DATA})
 * y los métodos privados ({@code loadInternalPreferencesData},
 * {@code isAutommaticUpdateConfigAllowed}) a esta clase.</p>
 *
 * <p>Las 4 constantes públicas son las mismas que estaban en
 * {@link PreferencesManager} como {@code private}; ahora son accesibles
 * como punto de referencia estable para consumidores que necesiten
 * referenciar las claves internas (p. ej. los tests).</p>
 */
public final class UpdateConfigurationManager {

	/** Clave de la URL del fichero de configuración remoto. */
	public static final String CONFIG_FILE_URL = "configFileUrl"; //$NON-NLS-1$

	/** Clave del hash SHA-256 del último fichero de configuración aplicado. */
	public static final String CONFIG_FILE_SHA256 = "configFileSHA256"; //$NON-NLS-1$

	/** Clave del flag que habilita la actualización automática de configuración. */
	public static final String ALLOW_UPDATE_CONFIG = "allowUpdateConfig"; //$NON-NLS-1$

	/** Clave de la fecha del último chequeo de actualización de configuración. */
	public static final String CONFIGURATION_DATE = "configDate"; //$NON-NLS-1$

	private UpdateConfigurationManager() {
		// No permitimos la instanciacion
	}

	/**
	 * Actualiza la información de los datos de configuración usados, pero ni la ruta
	 * ni si configura la actualización automática.
	 * @param configDataInfo Información del fichero de configuración.
	 */
	public static void setConfigFileInfo(final ConfigDataInfo configDataInfo) {
		PreferencesManager.setConfigFileInfo(configDataInfo);
	}

	/**
	 * Establece la información completa del fichero de configuración remoto.
	 * @param url URL del fichero (puede ser null).
	 * @param allowUpdates {@code true} para habilitar la actualización automática.
	 * @param configDataInfo Información del fichero (hash, etc.).
	 */
	public static void setConfigFileInfo(final String url, final boolean allowUpdates,
			final ConfigDataInfo configDataInfo) {
		PreferencesManager.setConfigFileInfo(url, allowUpdates, configDataInfo);
	}

	/** Registra la fecha actual como último chequeo de actualización de configuración. */
	public static void setConfigCheckDate() {
		PreferencesManager.setConfigCheckDate();
	}

	/** @return La URL del fichero de configuración remoto, o {@code null} si no hay. */
	public static String getConfigFileUrl() {
		return PreferencesManager.getConfigFileUrl();
	}

	/** @return {@code true} si toca chequear si hay una nueva configuración
	 *          remota disponible (según el flag {@link #ALLOW_UPDATE_CONFIG},
	 *          la URL configurada y la fecha del último chequeo). */
	public static boolean needCheckConfigUpdates() {
		return PreferencesManager.needCheckConfigUpdates();
	}

	/** @param updatedConfigData Datos del fichero de configuración remoto descargado.
	 *  @return {@code true} si el fichero remoto difiere del que se aplicó
	 *          la última vez (comparando hashes SHA-256). */
	public static boolean isNewConfigFile(final ConfigDataInfo updatedConfigData) {
		return PreferencesManager.isNewConfigFile(updatedConfigData);
	}
}
