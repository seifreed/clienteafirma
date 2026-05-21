/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.configurator.common;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

/**
 * Sub-manager del dominio "Actualización automática de configuración".
 *
 * <p>Gestiona las preferencias internas del sistema relacionadas con la
 * actualización automática de la configuración: la URL del fichero de
 * configuración remoto, su hash SHA-256, el indicador de si la
 * actualización automática está habilitada y la fecha del último chequeo.
 * Estas claves se almacenan en un nodo dedicado de
 * {@link Preferences} ({@code /es/gob/afirma/standalone/ui/internalpreferences})
 * separado de los nodos de preferencias de usuario y de sistema.</p>
 *
 * <p>Estado propio: {@code INTERNAL_PREFERENCES} (el nodo de
 * {@link Preferences}) e {@code INTERNAL_PREFERENCES_DATA} (la caché de sus
 * valores, cargada en {@link #init()}). El acceso al árbol de
 * {@link Preferences} se hace a través del <em>seam</em> compartido de
 * {@link PreferencesManager} ({@code systemNode}/{@code userNode}/...), de
 * modo que los tests pueden aislar ambas clases con los mismos suppliers.</p>
 *
 * <p>{@code init()} lo invoca {@link PreferencesManager#init()}.</p>
 */
public final class UpdateConfigurationManager {

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	/** Clave de la URL del fichero de configuración remoto. */
	public static final String CONFIG_FILE_URL = "configFileUrl"; //$NON-NLS-1$

	/** Clave del hash SHA-256 del último fichero de configuración aplicado. */
	public static final String CONFIG_FILE_SHA256 = "configFileSHA256"; //$NON-NLS-1$

	/** Clave del flag que habilita la actualización automática de configuración. */
	public static final String ALLOW_UPDATE_CONFIG = "allowUpdateConfig"; //$NON-NLS-1$

	/** Clave de la fecha del último chequeo de actualización de configuración. */
	public static final String CONFIGURATION_DATE = "configDate"; //$NON-NLS-1$

	/** Nodo de {@link Preferences} donde residen las preferencias internas. */
	private static final String INTERNAL_SYSTEM_PREFERENCE_NODE = "/es/gob/afirma/standalone/ui/internalpreferences"; //$NON-NLS-1$

	private static final String CONFIGURATION_DATE_FORMAT = "YYYYMMdd"; //$NON-NLS-1$

	private static final String PREFIX_HTTPS = "https://"; //$NON-NLS-1$

	/** Claves exclusivas de sistema: el usuario nunca puede sobreescribirlas. */
	private static final String[] SYSTEM_EXCLUSIVE_PREFERENCES = {
			CONFIG_FILE_URL,
			ALLOW_UPDATE_CONFIG,
	};

	/** Nodo de preferencias internas de configuración. */
	private static Preferences INTERNAL_PREFERENCES;

	/**
	 * Caché con la configuración interna activa: las preferencias internas del
	 * sistema combinadas con las del usuario (sin pisar las exclusivas de
	 * sistema). Se carga en {@link #init()}.
	 */
	private static Properties INTERNAL_PREFERENCES_DATA;

	private UpdateConfigurationManager() {
		// No permitimos la instanciacion
	}

	/**
	 * Inicializa el estado del sub-manager. Lo invoca {@link PreferencesManager#init()};
	 * no debe llamarse de forma independiente.
	 */
	static void init() {
		INTERNAL_PREFERENCES = PreferencesManager.systemNode(INTERNAL_SYSTEM_PREFERENCE_NODE);
		try {
			INTERNAL_PREFERENCES_DATA = loadInternalPreferencesData();
		}
		catch (final Exception e) {
			LOGGER.log(Level.WARNING, "Error al cargar las propiedades internas de configuracion del sistema", e); //$NON-NLS-1$
			INTERNAL_PREFERENCES_DATA = null;
		}
	}

	/**
	 * Indica si la actualización automática de configuración está permitida a
	 * nivel de sistema. No depende de {@link #init()}: consulta directamente el
	 * nodo de sistema, por lo que {@link PreferencesManager#init()} puede
	 * invocarlo antes de inicializar el estado interno.
	 * @return {@code true} si el flag {@link #ALLOW_UPDATE_CONFIG} está activo.
	 */
	static boolean isAutommaticUpdateConfigAllowed() {
		try {
			return PreferencesManager.systemNodeExists(INTERNAL_SYSTEM_PREFERENCE_NODE)
					&& PreferencesManager.systemNode(INTERNAL_SYSTEM_PREFERENCE_NODE).getBoolean(ALLOW_UPDATE_CONFIG, false);
		}
		catch (final Exception e) {
			LOGGER.log(Level.WARNING, "No se ha podido comprobar si esta activa la actualizacion automatica de la configuracion", e); //$NON-NLS-1$
			return false;
		}
	}

	/**
	 * Carga las preferencias internas activas: las del sistema combinadas con
	 * las del usuario (sin pisar las claves exclusivas de sistema).
	 * @return Las preferencias internas, o {@code null} si el nodo no existe.
	 * @throws BackingStoreException Cuando falla la carga de los datos.
	 */
	private static Properties loadInternalPreferencesData() throws BackingStoreException {

		Properties preferencesData = null;

		// Cargamos las preferencias internas establecidas a nivel de sistema
		if (PreferencesManager.systemNodeExists(INTERNAL_SYSTEM_PREFERENCE_NODE)) {
			preferencesData = new Properties();
			final Preferences internalSystemNode = PreferencesManager.systemNode(INTERNAL_SYSTEM_PREFERENCE_NODE);
			try {
				for (final String key : internalSystemNode.keys()) {
					preferencesData.setProperty(key, internalSystemNode.get(key, null));
				}
			}
			catch (final Exception e) {
				// A veces el nodo de preferencias no existe y aun asi pasa la prueba de nodeExists
				// y luego falla al intentar recuperar sus claves. Ignoramos este error
				return null;
			}

			// Cargamos las preferencias cargadas a nivel de usuario, con cuidado de no pisar
			// aquellas exclusivas de sistema
			if (PreferencesManager.userNodeExists(INTERNAL_SYSTEM_PREFERENCE_NODE)) {
				final Preferences internalUserNode = PreferencesManager.userNode(INTERNAL_SYSTEM_PREFERENCE_NODE);
				for (final String key : internalUserNode.keys()) {
					if (!isSystemConfigPreference(key)) {
						preferencesData.setProperty(key, internalUserNode.get(key, null));
					}
				}
			}
		}
		return preferencesData;
	}

	/**
	 * Indica si una preferencia es exclusiva de sistema (el usuario no puede
	 * sobreescribirla).
	 * @param key Nombre de la preferencia.
	 * @return {@code true} si es exclusiva de sistema.
	 */
	private static boolean isSystemConfigPreference(final String key) {
		for (final String k : SYSTEM_EXCLUSIVE_PREFERENCES) {
			if (k.equalsIgnoreCase(key)) {
				return true;
			}
		}
		return false;
	}

	private static boolean hasHttpsSchema(final String url) {
		return url != null && url.toLowerCase(Locale.US).startsWith(PREFIX_HTTPS);
	}

	/**
	 * Recupera el valor de una preferencia interna desde la caché.
	 * Lo consume el caso {@code SYSTEM_INTERNAL} de
	 * {@link PreferencesManager#get(String, PreferencesManager.PreferencesSource)}.
	 * @param key Clave de la preferencia interna.
	 * @return El valor, o {@code null} si no existe.
	 */
	static String getInternalProperty(final String key) {
		return INTERNAL_PREFERENCES_DATA != null ? INTERNAL_PREFERENCES_DATA.getProperty(key, null) : null;
	}

	/**
	 * Recupera el valor booleano de una preferencia interna desde la caché.
	 * @param key Clave de la preferencia interna.
	 * @return El valor booleano, o {@code false} si no existe.
	 */
	static boolean getInternalBoolean(final String key) {
		return INTERNAL_PREFERENCES_DATA != null
				? Boolean.parseBoolean(INTERNAL_PREFERENCES_DATA.getProperty(key, Boolean.FALSE.toString()))
				: false;
	}

	/**
	 * Redirige el nodo de preferencias internas al almacén de usuario. Lo
	 * invoca {@link PreferencesManager} cuando el almacén de sistema es de
	 * solo lectura para el usuario actual.
	 */
	static void unlockToUserNode() {
		INTERNAL_PREFERENCES = PreferencesManager.userNode(INTERNAL_SYSTEM_PREFERENCE_NODE);
	}

	/**
	 * Elimina el nodo de preferencias internas del sistema. Lo invoca
	 * {@link PreferencesManager#removeSystemPrefs()} durante la desinstalación.
	 * @throws BackingStoreException Cuando no se puede eliminar el nodo.
	 */
	static void removeInternalNode() throws BackingStoreException {
		if (PreferencesManager.systemNodeExists(INTERNAL_SYSTEM_PREFERENCE_NODE)) {
			final Preferences parent = PreferencesManager.systemNode(INTERNAL_SYSTEM_PREFERENCE_NODE).parent();
			PreferencesManager.systemNode(INTERNAL_SYSTEM_PREFERENCE_NODE).removeNode();
			PreferencesManager.removeEmptyTree(parent);
		}
	}

	/**
	 * Actualiza la información del fichero de configuración usado, sin tocar
	 * la ruta ni la configuración de actualización automática.
	 * @param configDataInfo Información del fichero de configuración.
	 */
	public static void setConfigFileInfo(final ConfigDataInfo configDataInfo) {
		setConfigFileInfo(null, false, configDataInfo);
	}

	/**
	 * Establece la información completa del fichero de configuración remoto.
	 * @param url URL del fichero (puede ser {@code null}).
	 * @param allowUpdates {@code true} para habilitar la actualización automática.
	 * @param configDataInfo Información del fichero (hash, etc.).
	 */
	public static void setConfigFileInfo(final String url, final boolean allowUpdates,
			final ConfigDataInfo configDataInfo) {

		PreferencesManager.init();

		try {
			if (url != null) {
				INTERNAL_PREFERENCES.put(CONFIG_FILE_URL, url);
			}
			if (allowUpdates && hasHttpsSchema(url)) {
				INTERNAL_PREFERENCES.putBoolean(ALLOW_UPDATE_CONFIG, true);
			}
			else {
				INTERNAL_PREFERENCES.remove(ALLOW_UPDATE_CONFIG);
			}
			INTERNAL_PREFERENCES.put(CONFIG_FILE_SHA256, configDataInfo.getHash());

			loadInternalPreferencesData();
		}
		catch (final Exception e) {
			if (!INTERNAL_PREFERENCES.isUserNode()) {
				INTERNAL_PREFERENCES = PreferencesManager.userNode(INTERNAL_SYSTEM_PREFERENCE_NODE);
				setConfigFileInfo(url, allowUpdates, configDataInfo);
				return;
			}
			LOGGER.log(Level.WARNING, "No se ha podido establecer la informacion de configuracion interna del sistema", e); //$NON-NLS-1$
		}
	}

	/** Registra la fecha actual como último chequeo de actualización de configuración. */
	public static void setConfigCheckDate() {

		PreferencesManager.init();

		final String formatedDate = new SimpleDateFormat(CONFIGURATION_DATE_FORMAT).format(new Date());
		try {
			INTERNAL_PREFERENCES.put(CONFIGURATION_DATE, formatedDate);

			loadInternalPreferencesData();
		}
		catch (final Exception e) {
			if (!INTERNAL_PREFERENCES.isUserNode()) {
				INTERNAL_PREFERENCES = PreferencesManager.userNode(INTERNAL_SYSTEM_PREFERENCE_NODE);
				setConfigCheckDate();
				return;
			}
			LOGGER.log(Level.WARNING, "No se ha podido establecer la fecha de configuracion interna del sistema", e); //$NON-NLS-1$
		}
	}

	/** @return La URL del fichero de configuración remoto, o {@code null} si no hay. */
	public static String getConfigFileUrl() {
		PreferencesManager.init();
		return getInternalProperty(CONFIG_FILE_URL);
	}

	/**
	 * @return {@code true} si toca chequear si hay una nueva configuración
	 *         remota disponible (según el flag {@link #ALLOW_UPDATE_CONFIG},
	 *         la URL configurada y la fecha del último chequeo).
	 */
	public static boolean needCheckConfigUpdates() {

		final boolean updateConfigAllowed = isAutommaticUpdateConfigAllowed();
		if (!updateConfigAllowed) {
			return false;
		}

		final String configUrl = getConfigFileUrl();
		if (!hasHttpsSchema(configUrl)) {
			return false;
		}

		final String configurationDate = getInternalProperty(CONFIGURATION_DATE);
		final String currentDate = new SimpleDateFormat(CONFIGURATION_DATE_FORMAT).format(new Date());
		return configurationDate == null || currentDate.compareTo(configurationDate) > 0;
	}

	/**
	 * @param updatedConfigData Datos del fichero de configuración remoto descargado.
	 * @return {@code true} si el fichero remoto difiere del que se aplicó la
	 *         última vez (comparando hashes SHA-256).
	 */
	public static boolean isNewConfigFile(final ConfigDataInfo updatedConfigData) {
		PreferencesManager.init();
		final String currentConfigFileHash = getInternalProperty(CONFIG_FILE_SHA256);
		return currentConfigFileHash == null || !currentConfigFileHash.equals(updatedConfigData.getHash());
	}
}
