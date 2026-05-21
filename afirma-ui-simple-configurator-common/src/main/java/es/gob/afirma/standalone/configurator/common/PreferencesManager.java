/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.standalone.configurator.common;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

/**
 * Clase para la obtencion de las preferencias de configuraci&oacute;n del programa.
 * Se distingue entre preferencias de usuario, preferencias de sistema y preferencias por defecto:
 * <ul>
 * <li>Preferencias de usuario: Aquellas que ha establecido el usuario.</li>
 * <li>Preferencias de sistema: Aquellas que se han establecido a nivel de sistema y afectan a todos los usuarios.</li>
 * <li>Preferencias por defecto: Valores por defecto de la aplicaci&oacute;n.</li>
 * </ul>
 * <p>
 * La aplicacion utilizar&aacute; las preferencias configuradas por el usuario. Si el usuario no estableci&oacute; un
 * valor para una preferencia, se usar&aacute; el valor establecido a nivel de sistema. Si no se estableci&oacute; un
 * valor a nivel de sistema, se usar&aacute;a el valor por defecto.
 * </p>
 * <p>
 * Las preferencias del sistema nunca las establece el usuario y s&oacute;lo pueden establecerse de dos formas:
 * </p>
 * <ol>
 * <li>De forma ajena a la aplicaci&oacute;n: Esto puede ser, por ejemplo, mediante software de despliegue masivo que
 * pueda establecer la configuraci&oacute;n o mediante las opciones de los instaladores de la aplicaci&oacute;n.</li>
 * <li>Con la actualizacion autom&aacute;tica: Se puede establecer a nivel de sistema que la aplicaci&oacute;n compruebe
 * diariamente en una URL si hay configuraci&oacute;n actualizada. En caso de encontrarla, se actualiza
 * autom&aacute;ticamente en segundo plano al arrancar la aplicaci&oacute;n.</li>
 * </ol>
 * <p>
 * Sobre la actualizaci&oacute;n autom&aacute;tica de la configuraci&oacute;n, hay que tener en cuenta que es probable
 * que la aplicaci&oacute;n no pueda establecerla a nivel de sistema a causa de los permisos. En ese caso, se guarda en
 * un apartado propio del usuario sobre el que s&iacute; tiene permisos, pero a nivel l&oacute;gico estas ser&aacute;n
 * las nuevas preferencias del sistema.
 * </p>
 * <p>
 * Hay un tipo especial de preferencias llamadas preferencias internas. Estas son la URL de actualizaci&oacute;n, la
 * indicaci&oacute;n de si la aplicaci&oacute;n debe actualizarse autom&aacute;ticamente, el hash del fichero de
 * actualizaci&oacute;n y la fecha de comprobaci&oacute;n. Estas preferencias no se exportan. Adem&aacute;s, entre ellas
 * se marcan algunas (la URL y el indicador de si se debe actualizar la configuracion a diario) como exclusivas del
 * sistema. Estas son propiedades que siempre se tomar&acute;n del sistema y no se pueden sobreescribir con preferencias
 * del usuario, ya que s&oacute;lo una administrador deber&iacute; poder modificarlas.
 * </p>
 *
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 * @author Carlos Gamuci
 */
public final class PreferencesManager {

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	private static final String PREFERENCE_NODE = "/es/gob/afirma/standalone/ui/preferences"; //$NON-NLS-1$

	private static final String UPDATED_SYSTEM_PREFERENCE_NODE = "/es/gob/afirma/standalone/ui/systempreferences"; //$NON-NLS-1$

	/** Preferencias con la configuraci&oacute;n de la aplicaci&oacute;n aplicada por el usuario. */
	private static Preferences USER_PREFERENCES;

	/**
	 * Preferencias con la configuraci&oacute;n de la aplicaci&oacute;n establecida a nivel de sistema, que puede ser
	 * la original del sistema o configuraci&oacute;n actualizada.
	 */
	private static Preferences SYSTEM_PREFERENCES;

	/**Valores por defecto de las propiedades de configuraci&oacute;n de la aplicaci&oacute;n. */
	private static  Properties DEFAULT_PREFERENCES;

	/**
	 * Preferencias del sistema que siempre apuntar&aacute; a las preferencias
	 * del sistema reales (si existen), aunque se haya encontrado una versi&oacute;n actualizada
	 * en las preferencias del usuario.
	 */
	private static Preferences REAL_SYSTEM_PREFERENCES;

	// =================================================================
	// Seam testable (Oleada 9 Fase A, 2026-05-20). Dos suppliers
	// package-private sustituyen los accesos directos a
	// Preferences.{user,system}Root() y permiten que los tests aislen
	// el árbol de preferencias bajo un subnodo único por test.
	//
	// Los path constants del código original empiezan por '/'
	// (absolutos). Como un path absoluto pasado a Preferences.node()
	// *ignora* el receptor, los helpers eliminan la barra inicial para
	// convertirlo en relativo: así un supplier que devuelva un subnodo
	// produce aislamiento real, en lugar de aterrizar siempre en el
	// root global.
	//
	// En producción la conversión es no-op: cuando el receptor *es*
	// userRoot(), `userRoot().node("/x/y")` y `userRoot().node("x/y")`
	// resuelven al mismo nodo. Por eso este cambio preserva el
	// comportamiento original byte-a-byte sin ningún flag adicional.
	//
	// El split estructural a sub-managers temáticos es trabajo de una
	// sesión futura; esto es solo la red de tests para hacerlo seguro.
	// =================================================================
	/** Suministrador del nodo raíz de usuario. Sustituible solo en tests. */
	static volatile java.util.function.Supplier<Preferences> USER_ROOT_SUPPLIER = Preferences::userRoot;
	/** Suministrador del nodo raíz de sistema. Sustituible solo en tests. */
	static volatile java.util.function.Supplier<Preferences> SYSTEM_ROOT_SUPPLIER = Preferences::systemRoot;

	// Helpers package-private para que UpdateConfigurationManager (mismo
	// paquete) comparta el seam sin duplicar suppliers ni lógica.
	static String relativize(final String absolutePath) {
		return absolutePath.startsWith("/") ? absolutePath.substring(1) : absolutePath; //$NON-NLS-1$
	}

	static Preferences userNode(final String absolutePath) {
		return USER_ROOT_SUPPLIER.get().node(relativize(absolutePath));
	}

	static Preferences systemNode(final String absolutePath) {
		return SYSTEM_ROOT_SUPPLIER.get().node(relativize(absolutePath));
	}

	static boolean userNodeExists(final String absolutePath) throws BackingStoreException {
		return USER_ROOT_SUPPLIER.get().nodeExists(relativize(absolutePath));
	}

	static boolean systemNodeExists(final String absolutePath) throws BackingStoreException {
		return SYSTEM_ROOT_SUPPLIER.get().nodeExists(relativize(absolutePath));
	}

	private static final String TRUE_VALUE = "true"; //$NON-NLS-1$
	private static final String FALSE_VALUE = "false"; //$NON-NLS-1$

	/** Origen del valor de las preferencias. */
	public enum PreferencesSource {
		/** Preferencias establecidas por el usuario. */
		USER,
		/** Preferencias establecidas a nivel de sistema. */
		SYSTEM,
		/** Preferencias no exportables establecidas a nivel de sistema. */
		SYSTEM_INTERNAL,
		/** Valor por defecto de las preferencias. */
		DEFAULT
	}

	private static boolean initialized = false;

	private PreferencesManager() {
		// No permitimos la instanciacion
	}

	//**************************************************************************************************************************
	//**************** VALORES GENERALES ***************************************************************************************

	/** Realizar cofirma en multifirmas. */
	public static final String VALUE_MULTISIGN_COSIGN = "cosign";  //$NON-NLS-1$

	/** Realizar contrafirma en hojas en multifirmas. */
	public static final String VALUE_MULTISIGN_COUNTERSIGN_LEAFS = "countersignLeafs";  //$NON-NLS-1$

	/** Realizar contrafirma en arbol en multifirmas. */
	public static final String VALUE_MULTISIGN_COUNTERSIGN_TREE = "countersignTree";  //$NON-NLS-1$

	//**************************************************************************************************************************

	//**************************************************************************************************************************
	//**************** PREFERENCIAS GENERALES **********************************************************************************

    /** Idioma por defecto. */
    public static final String PREFERENCES_LOCALE = "default.locale"; //$NON-NLS-1$

	/** Proteger cambios en preferencias.
	 * Un valor de <code>true</code> en esta preferencia indica que deben limitarse las opciones de configuraci&oacute;n
	 * mediante interfaz gr&aacute;fico, apareciendo de forma deshabilitada (solo para consulta).
	 * Un valor de <code>false</code> habilitar&aacute; que cualquier opci&oacute;n de configuraci&oacute;n pueda ser
	 * alterada por parte del usuario mediante el interfaz gr&aacute;fico. */
	public static final String PREFERENCE_GENERAL_BLOCKED = "preferencesBlocked"; //$NON-NLS-1$

	/** Comprobar que la versi&oacute;n actual de Java est&aacute; soportada.
	 * Un valor de <code>true</code> en esta preferencia hace que, al arrancar, la aplicaci&oacute;n compruebe autom&aacute;ticamente
	 * si la versi&oacute;n de Java con la que se ejecuta la aplicaci&oacute;n est&aacute; entre las versiones soportadas. Un valor de
	 * <code>false</code> har&aacute; que no se haga esta comprobaci&oacute;n. */
	public static final String PREFERENCE_GENERAL_CHECK_JAVA_VERSION = "checkJavaVersion"; //$NON-NLS-1$

	/** Evitar la confirmaci&oacute;n al cerrar la aplicaci&oacute;n o no.
	 * Un valor de <code>true</code> en esta preferencia permitir&aacute; cerrar la aplicaci&oacute;n sin ning&uacute;n di&aacute;logo
	 * de advertencia. Un valor de <code>false</code> har&aacute; que se muestre un di&aacute;logo para que el usuario confirme que
	 * realmente desea cerrar la aplicaci&oacute;n. */
	public static final String PREFERENCE_GENERAL_OMIT_ASKONCLOSE = "omitAskOnClose"; //$NON-NLS-1$

	/** Buscar actualizaciones al arrancar.
	 * Un valor de <code>true</code> en esta preferencia hace que, al arrancar, la aplicaci&oacute;n compruebe autom&aacute;ticamente
	 * si hay publicadas versiones m&aacute;s actuales del aplicativo. Un valor de <code>false</code> har&aacute; que no se haga
	 * esta comprobaci&oacute;n. */
	public static final String PREFERENCE_GENERAL_UPDATECHECK = "checkForUpdates"; //$NON-NLS-1$

	/** Mantiene habilitado el funcionamiento de JMultiCard.
	 * Un valor de <code>true</code> en esta preferencia hace que la aplicacion deje el comportamiento
	 * por defecto de JMulticard, que usaria las tarjetas DNIe y CERES. Un valor de <code>false</code>
	 * har&aacute; que no se desactive el uso de JMulticard para estas tarjetas. */
	public static final String PREFERENCE_GENERAL_ENABLED_JMULTICARD = "enabledJmulticard"; //$NON-NLS-1$

	/**
	 * Configura una propiedad que indica a la biblioteca WebSocket para la comunicaci&oacute;n con el
	 * navegador que aplique un peque&ntilde;o retardo en las comunicaciones para as&iacute; evitar que
	 * se bloquee el canal. Esto relantizar&aacute; las comunicaciones, lo cual es muy evidente conforme
	 * se trabaje con ficheros m&aacute;s grandes. S&oacute;lo se recomienda el su uso de esta propiedad
	 * cuando se use el cliente sobre VDI para evitar un mal mayor.
	 */
	public static final String PREFERENCE_GENERAL_VDI_OPTIMIZATION = "vdiOptimization"; //$NON-NLS-1$

	/**
	 * Configura una propiedad para habilitar un di&aacute;logo de espera que indica la tarea que este ejecutando
	 * Autofirma en ese mismo instante.
	 */
	public static final String PREFERENCE_GENERAL_ENABLE_PROGRESS_DIALOG = "enableProgressDialog"; //$NON-NLS-1$

	/** Algoritmo de huella para firma.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>SHA1</li>
	 *  <li>SHA256</li>
	 *  <li>SHA384</li>
	 *  <li>SHA512</li>
	 * </ul> */
	public static final String PREFERENCE_GENERAL_SIGNATURE_ALGORITHM = "signatureHashAlgorithm"; //$NON-NLS-1$

	/** Formato de firma por defecto para documentos PDF.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>PAdes</li>
	 *  <li>CAdes</li>
	 *  <li>XAdes</li>
	 * </ul> */
	public static final String PREFERENCE_GENERAL_DEFAULT_FORMAT_PDF = "defaultSignatureFormatPdf"; //$NON-NLS-1$

	/** Formato de firma por defecto para documentos OOXML de Microsoft Office.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>OOXML (Office Open XML)</li>
	 *  <li>CAdES</li>
	 *  <li>XAdES</li>
	 * </ul> */
	public static final String PREFERENCE_GENERAL_DEFAULT_FORMAT_OOXML = "defaultSignatureFormatOoxml"; //$NON-NLS-1$

	/** Formato de firma por defecto para Facturas Electr&oacute;nicas.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>FacturaE</li>
	 *  <li>CAdES</li>
	 *  <li>XAdES</li>
	 * </ul> */
	public static final String PREFERENCE_GENERAL_DEFAULT_FORMAT_FACTURAE = "defaultSignatureFormatFacturae"; //$NON-NLS-1$

	/** Formato de firma por defecto para documentos ODF de LibreOffice / OpenOffice.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>ODF (Open Document Format)</li>
	 *  <li>CAdES</li>
	 *  <li>XAdES</li>
	 * </ul> */
	public static final String PREFERENCE_GENERAL_DEFAULT_FORMAT_ODF = "defaultSignatureFormatOdf"; //$NON-NLS-1$

	/** Formato de firma por defecto para documentos XML.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>CAdES</li>
	 *  <li>XAdES</li>
	 * </ul> */
	public static final String PREFERENCE_GENERAL_DEFAULT_FORMAT_XML = "defaultSignatureFormatXml"; //$NON-NLS-1$

	/** Formato de firma por defecto para ficheros binarios que no se adec&uacute;en a ninguna otra categor&iacute;a.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>CAdES</li>
	 *  <li>XAdES</li>
	 * </ul> */
	public static final String PREFERENCE_GENERAL_DEFAULT_FORMAT_BIN = "defaultSignatureFormatBin"; //$NON-NLS-1$

	/** Solicitar confirmaci&oacute;n antes de firmar.
	 * Un valor de <code>true</code> en esta preferencia hace que se muestre un di&aacute;logo de
	 * confirmaci&oacute;n con las implicaciones de firma al iniciar una firma desde la interfaz
	 * de escritorio. */
	public static final String PREFERENCE_GENERAL_CONFIRMTOSIGN = "confirmToSign"; //$NON-NLS-1$

	/** Permitir la multifirma de firmas inv&aacute;lidas.
	 * Un valor de <code>true</code> en esta preferencia hace que se puedan multifirmar firmas a pesar
	 * de haberse detectado que no son v&aacute;lidas. */
	public static final String PREFERENCE_GENERAL_ALLOW_INVALID_SIGNATURES = "allowInvalidSignatures"; //$NON-NLS-1$

	/** Indica si en los procesos de firma masiva se deben sobreescribir o no los ficheros que
	 * se encuentren en el directorio de salida. */
	public static final String PREFERENCE_GENERAL_MASSIVE_OVERWRITE = "massiveOverride"; //$NON-NLS-1$


	/** Indica si debe validarse el certificado SSL en las conexiones de red. */
	public static final String PREFERENCE_GENERAL_SECURE_CONNECTIONS = "secureConnections"; //$NON-NLS-1$

	/** Lista de dominios seguros donde realizar conexiones SSL. */
	public static final String PREFERENCE_GENERAL_SECURE_DOMAINS_LIST = "secureDomainsList"; //$NON-NLS-1$

	//**************** FIN PREFERENCIAS GENERALES ******************************************************************************
	//**************************************************************************************************************************

	//**************************************************************************************************************************
	//**************** PREFERENCIAS DE ALMACENES DE CLAVES *********************************************************************

	/** Valor default para indicar que se desea seleccionar el almac&eacute;n de claves del sistema. */
	public static final String VALUE_KEYSTORE_DEFAULT = "default"; //$NON-NLS-1$

	/** Ruta del almac&eacute;n de claves local seleccionado por defecto. */
	public static final String PREFERENCE_LOCAL_KEYSTORE_PATH = "defaultLocalKeystorePath"; //$NON-NLS-1$

	/** Indica si se usa o no el certificado por defecto configurado en llamadas desde el navegador. */
	public static final String PREFERENCE_USE_DEFAULT_STORE_IN_BROWSER_CALLS = "useDefaultStoreInBrowserCalls"; //$NON-NLS-1$

	/** No mostrar la pantalla inicial de uso de DNIe.
	 * Un valor de <code>true</code> en esta preferencia hace que nunca se muestre la pantalla inicial que sugiere al usuario
	 * el uso directo del DNIe como almac&eacute;n de claves. Un valor de <code>false</code> har&aacute; que se muestre esta pantalla
	 * al inicio siempre que se detecte un lector de tarjetas en el sistema. */
	public static final String PREFERENCE_GENERAL_HIDE_DNIE_START_SCREEN = "hideDnieStartScreen"; //$NON-NLS-1$

	//**************** FIN PREFERENCIAS DE ALMACENES DE CLAVES *****************************************************************
	//**************************************************************************************************************************


	//**************** FIN PREFERENCIAS UNICAMENTE DE SISTEMA ******************************************************************
	//**************************************************************************************************************************

	//**************************************************************************************************************************
	//**************** PREFERENCIAS PARA ADMINISTRADORES ***********************************************************************

	/** Indica si se permite la importaci&oacute;n de ficheros de preferencias sin firmar. */
	public static final String ADMIN_PREFERENCE_REQUIRE_SIGNED_PREFERENCES = "requireSignedPrerefences"; //$NON-NLS-1$

	/** Indica si hash en base 64 del certificado de firma de los ficheros de preferencias. */
	public static final String ADMIN_PREFERENCE_CERT_HASH_TO_SIGNED_PREFERENCES = "certHashToSignedPrerefences"; //$NON-NLS-1$

	/** Indica si cargar el almacen con los certificados de confianza importados en Autofirma. */
	public static final String  ADMIN_PREFERENCE_ALLOW_PERSONAL_TRUSTSTORE = "allowPersonalTruststore"; //$NON-NLS-1$

	/** Permite o no la importacion automatica de certificados durante conexiones al servidor. */
	public static final String ADMIN_PREFERENCE_ALLOW_AUTO_IMPORT_TRUSTED_CERTS = "allowAutoImportTrustedCerts"; //$NON-NLS-1$


	//**************** FIN PREFERENCIAS PARA ADMINISTRADORES *******************************************************************
	//**************************************************************************************************************************

	static void init() {

		// No hacemos nada si ya estaban inicializados los objetos
		if (initialized) {
			return;
		}

		LOGGER.info("Cargamos los objetos de acceso a las preferencias del sistema"); //$NON-NLS-1$

		// Cargamos las preferencias de usuario
		USER_PREFERENCES = userNode(PREFERENCE_NODE);

		// Si existen preferencias del sistema actualizadas, seran las que usemos. Si no,
		// cargaremos las del sistema por defecto. Si no, no cargaremos ninguna
		Preferences configSystemPreferences;
		Preferences configUpdatedSystemPreferences;
		try {
			// Cargamos las preferencias del sistema
			configSystemPreferences = systemNodeExists(PREFERENCE_NODE)
					? systemNode(PREFERENCE_NODE)
					: null;

			// Si hay preferencias del sistema y se permiten actualizar, comprobamos si hay alguna version actualizada
			configUpdatedSystemPreferences = configSystemPreferences != null
					&& UpdateConfigurationManager.isAutommaticUpdateConfigAllowed()
					&& userNodeExists(UPDATED_SYSTEM_PREFERENCE_NODE)
					? userNode(UPDATED_SYSTEM_PREFERENCE_NODE)
					: null;
		}
		catch (final Exception e) {
			LOGGER.warning("No se pueden cargar las preferencias establecidas a nivel de sistema: " + e); //$NON-NLS-1$
			configSystemPreferences = null;
			configUpdatedSystemPreferences = null;
		}

		// Configuramos el origen de las preferencias de sistema
		if (configUpdatedSystemPreferences != null) {
			SYSTEM_PREFERENCES = configUpdatedSystemPreferences;
			REAL_SYSTEM_PREFERENCES = configSystemPreferences;
		} else {
			SYSTEM_PREFERENCES = configSystemPreferences;
			REAL_SYSTEM_PREFERENCES = SYSTEM_PREFERENCES;
		}

		// Inicializa el estado del sub-manager de actualización de configuración.
		UpdateConfigurationManager.init();

		// Cargamos los valores por defecto de la aplicacion
		DEFAULT_PREFERENCES = new Properties();
		try {
			DEFAULT_PREFERENCES.load(PreferencesManager.class.getResourceAsStream("/properties/preferences.properties")); //$NON-NLS-1$
		}
		catch (final Exception e) {
			LOGGER.severe(
				"No han podido cargarse los valores por defecto del fichero de configuracion de preferencias, se usaran los valores por defecto: " //$NON-NLS-1$
					+ e
			);
		}

		// Marcamos la clase como inicializada
		initialized = true;
	}

	/** Recupera la cadena con el valor de una propiedad de configuraci&oacute;n. La propiedad se
	 * buscar&aacute;, por orden, en las preferencia del usuario, del sistema o en la configuraci&oacute;n
	 * por defecto.
	 * @param key Clave del valor que queremos recuperar.
	 * @return El valor almacenado de la propiedad o su valor por defecto si no se encontr&oacute;. */
	public static String get(final String key) {

		init();

		final String userValue = USER_PREFERENCES.get(key, null);
		final String systemValue = SYSTEM_PREFERENCES != null ? SYSTEM_PREFERENCES.get(key, null) : null;
		final String defaultValue = DEFAULT_PREFERENCES.getProperty(key);

		return userValue != null
				? userValue
				: systemValue != null
					? systemValue
					: defaultValue;
	}

	/**
	 * Recupera la cadena con el valor de una propiedad de configuraci&oacute;n. Si se indica un
	 * conjunto de preferencias nulo, se obtendr&aacute; por orden el valor indicado en las
	 * preferencias de usuario, del sistema o el por defecto.
	 * @param key Clave del valor que queremos recuperar.
	 * @param src Conjunto de preferencias entre el que buscar la propiedad.
	 * @return El valor almacenado de la propiedad o su valor por defecto si no se encontr&oacute;.
	 */
	public static String get(final String key, final PreferencesSource src) {

		init();

		if (src == null) {
			return get(key);
		}

		switch(src) {
		case USER:
			return USER_PREFERENCES.get(key, null);
		case SYSTEM:
			return SYSTEM_PREFERENCES != null ? SYSTEM_PREFERENCES.get(key, null) : null;
		case SYSTEM_INTERNAL:
			return UpdateConfigurationManager.getInternalProperty(key);
		default:
		case DEFAULT:
			return DEFAULT_PREFERENCES.getProperty(key);
		}
	}

	/** Recupera el valor {@code true} o {@code false} almacenado entre las preferencias de la
	 * aplicaci&oacute;n.
	 * @param key Clave del valor que queremos recuperar.
	 * @return La preferencia almacenada o la configurada en el sistema si no se encontr&oacute;. */
	public static boolean getBoolean(final String key) {

		init();

		final boolean defaultValue = Boolean.parseBoolean(DEFAULT_PREFERENCES.getProperty(key));
		return USER_PREFERENCES.getBoolean(key,
				SYSTEM_PREFERENCES != null
					?	SYSTEM_PREFERENCES.getBoolean(key, defaultValue)
					: defaultValue);
	}

	/**
	 * Recupera el valor {@code true} o {@code false} almacenado en el tipo de preferencia
	 * indicado de la aplicaci&oacute;n. Si se indica un conjunto de preferencias nulo, se
	 * obtendr&aacute; por orden el valor indicado en las preferencias de usuario, del sistema o el
	 * por defecto.
	 * @param key Clave del valor que queremos recuperar.
	 * @param src Conjunto de preferencias entre el que buscar la propiedad.
	 * @return El valor almacenado de la propiedad o {@code false} si no estaba declarado.
	 */
	public static boolean getBoolean(final String key, final PreferencesSource src) {

		init();

		if (src == null) {
			return getBoolean(key);
		}

		switch(src) {
		case USER:
			return USER_PREFERENCES.getBoolean(key, false);
		case SYSTEM:
			return SYSTEM_PREFERENCES != null ? SYSTEM_PREFERENCES.getBoolean(key, false) : false;
		case SYSTEM_INTERNAL:
			return UpdateConfigurationManager.getInternalBoolean(key);
		default:
		case DEFAULT:
			return Boolean.parseBoolean(DEFAULT_PREFERENCES.getProperty(key));
		}
	}

	/** Establece una cadena de texto en la configuraci&oacute;n de la aplicaci&oacute;n
	 * identific&aacute;ndola con una clave. Si el valor que se le va a asignar a la propiedad es
	 * el que ya indico un administrador (propiedad del sistema) o el valor por defecto, si no
	 * existiese aquel, no se guarda para no ofuscar esos valores. Para realizar el guardado
	 * completo, es necesario ejecutar el m&eacute;todo {@code flush()}.
	 * @param key Clave con la que identificaremos el valor.
	 * @param value Valor que se desea almacenar. */
	public static void put(final String key, final String value) {

		init();

		final String defaultValue = DEFAULT_PREFERENCES.getProperty(key);
		final String systemValue = SYSTEM_PREFERENCES != null
				? SYSTEM_PREFERENCES.get(key, defaultValue)
				: defaultValue;

		// Si el nuevo valor que se establece en el sistema o por defecto, se elimina la clave
		// para dar visibilidad al valor establecido en el sistema o por defecto
		if (value.equals(systemValue)) {
			USER_PREFERENCES.remove(key);
		} else if (!value.equals(get(key))) {
			USER_PREFERENCES.put(key, value);
		}
	}

	/** Establece un {@code true} o {@code false} en la configuraci&oacute;n de la aplicaci&oacute;n
	 * identific&aacute;ndolo con una clave. Si el valor que se le va a asignar a la propiedad es
	 * el que ya indico un administrador (propiedad del sistema) o el valor por defecto, si no
	 * existiese aquel, no se guarda para no ofuscar esos valores. Para realizar el guardado completo, es
	 * necesario ejecutar el m&eacute;todo {@code flush()}.
	 * @param key Clave con la que identificaremos el valor.
	 * @param value Valor que se desea almacenar. */
	public static void putBoolean(final String key, final boolean value) {

		init();

		final boolean systemValue = SYSTEM_PREFERENCES != null
				? SYSTEM_PREFERENCES.getBoolean(key, Boolean.parseBoolean(DEFAULT_PREFERENCES.getProperty(key)))
				: Boolean.parseBoolean(DEFAULT_PREFERENCES.getProperty(key));

		// Si el nuevo valor que se establece en el sistema o por defecto, se elimina la clave
		// para dar visibilidad al valor establecido en el sistema o por defecto
		if (value == systemValue) {
			USER_PREFERENCES.remove(key);
		} else if (value != getBoolean(key)) {
			// Si la propiedad ha cambiado con respecto a la configurada en el sistema o por defecto, se guardara
			USER_PREFERENCES.putBoolean(key, value);
		}
	}

	/**
	 * Establece una cadena con clave y valor en las preferencias del sistema. Para realizar el guardado completo, es
	 * necesario ejecutar el m&eacute;todo {@code flush()}.
	 * @param key Clave con la que identificaremos el valor.
	 * @param value Valor que se desea almacenar.
	 */
	public static void putSystemPref(final String key, final String value) {
		init();
		putSystemPreferenceWithUnlockFallback(() -> SYSTEM_PREFERENCES.put(key, value));
	}

	private static void createSystemPrefs() {
		try {
			SYSTEM_PREFERENCES = systemNode(PREFERENCE_NODE);
			REAL_SYSTEM_PREFERENCES = SYSTEM_PREFERENCES;
		}
		catch (final Exception e) {
			SYSTEM_PREFERENCES = userNode(UPDATED_SYSTEM_PREFERENCE_NODE);
			REAL_SYSTEM_PREFERENCES = null;
		}
	}

	/**
	 * Cambia el registro de preferencias del sistema por la alternativa en las
	 * preferencias del usuario para que el usuario pueda "editar" esas preferencias.
	 */
	private static void unlockSystemPreferences() {
		if (SYSTEM_PREFERENCES != null && !SYSTEM_PREFERENCES.isUserNode()) {
			REAL_SYSTEM_PREFERENCES = SYSTEM_PREFERENCES;
		}
		SYSTEM_PREFERENCES = userNode(UPDATED_SYSTEM_PREFERENCE_NODE);
		UpdateConfigurationManager.unlockToUserNode();
	}

	/**
	 * Establece una preferencia del sistema exportable con el valor {@code true} o {@code false}.
	 * Para realizar el guardado completo, es necesario ejecutar el m&eacute;todo {@code flush()}.
	 * @param key Clave con la que identificaremos el valor.
	 * @param value Valor que se desea almacenar.
	 */
	public static void putBooleanSystemPref(final String key, final boolean value) {
		init();
		putSystemPreferenceWithUnlockFallback(() -> SYSTEM_PREFERENCES.putBoolean(key, value));
	}

	/**
	 * Ejecuta una escritura sobre el almac&eacute;n de preferencias del sistema con
	 * fallback al almac&eacute;n de usuario cuando la primera escritura falla (caso
	 * t&iacute;pico: el almac&eacute;n del sistema est&aacute; en una rama de
	 * Preferences solo lectura para el usuario actual). Centraliza el patr&oacute;n
	 * try-catch-retry usado por {@link #putSystemPref(String, String)} y
	 * {@link #putBooleanSystemPref(String, boolean)}.
	 *
	 * @param putAction Acci&oacute;n que escribe sobre {@code SYSTEM_PREFERENCES}.
	 *                  Se ejecuta primero contra el almac&eacute;n del sistema y, si
	 *                  lanza, una segunda vez tras invocar {@link #unlockSystemPreferences()}.
	 */
	private static void putSystemPreferenceWithUnlockFallback(final Runnable putAction) {
		if (SYSTEM_PREFERENCES == null) {
			createSystemPrefs();
		}
		try {
			putAction.run();
		}
		catch (final Exception e) {
			unlockSystemPreferences();
			putAction.run();
		}
	}

	/**
	 * Elimina una clave de entre la configuraci&oacute;n de la aplicaci&oacute;n.
	 * @param key Clave que eliminar.
	 */
	public static void remove(final String key) {

		init();

		USER_PREFERENCES.remove(key);
	}

	/**
	 * Elimina una clave de entre la configuraci&oacute;n de la aplicaci&oacute;n a nivel de sistema.
	 * @param key Clave que eliminar.
	 */
	public static void removeSystemPrefs(final String key) {

		init();

		if (SYSTEM_PREFERENCES != null) {
			SYSTEM_PREFERENCES.remove(key);
		}
	}

	/**
	 * Elimina todas las preferencias del usuario de la aplicaci&oacute;n.
	 * @throws BackingStoreException Si ocurre un error eliminando las preferencias.
	 */
	public static void clearAll() throws BackingStoreException {

		init();

		USER_PREFERENCES.clear();
	}

	/**
	 * Elimina todas las preferencias del sistema de la aplicaci&oacute;n.
	 * @throws BackingStoreException Si ocurre un error eliminando las preferencias.
	 */
	public static void clearAllSystemPrefs() throws BackingStoreException {

		init();

		if (SYSTEM_PREFERENCES != null) {
			try {
				SYSTEM_PREFERENCES.clear();
			}
			catch (final Exception e) {
				if (!SYSTEM_PREFERENCES.isUserNode()) {
					unlockSystemPreferences();
					clearAllSystemPrefs();
					return;
				}
				throw e;
			}
		}
	}

	/**
	 * Almacena en las preferencias del usuario de la aplicaci&oacute;n todos los valores
	 * establecidos hasta el momento.
	 * @throws BackingStoreException Cuando ocurre un error durante el guardado.
	 */
	public static void flush() throws BackingStoreException {

		init();

		USER_PREFERENCES.flush();
	}

	/**
	 * Almacena en las preferencias del sistema de la aplicaci&oacute;n todos los valores
	 * establecidos hasta el momento.
	 * @throws BackingStoreException Cuando ocurre un error durante el guardado.
	 */
	public static void flushSystemPrefs() throws BackingStoreException {

		init();

		if (SYSTEM_PREFERENCES == null) {
			return;
		}

		try {
			SYSTEM_PREFERENCES.flush();
		}
		catch (final Exception e) {

			// Si se trato de guardar en preferencias del sistema, cambiamos a un nodo del usuario
			// en el que poder guardarlas sin pisar la propia configuracion del usuario

			if (SYSTEM_PREFERENCES.isUserNode()) {
				LOGGER.warning("No se pudieron guardar las preferencias en el apartado de configuracion actualizada del usuario: " + e); //$NON-NLS-1$
				return;
			}

			// Hacemos copia de las entradas
			final Map<String, Object> nodes = new HashMap<>();
			for (final String k : SYSTEM_PREFERENCES.childrenNames()) {
				nodes.put(k, SYSTEM_PREFERENCES.get(k, null));
			}

			// Desbloqueamos las nuevas preferencias
			unlockSystemPreferences();

			// Guardamos de vuelta las entradas
			for (final String k : nodes.keySet().toArray(new String[0])) {
				SYSTEM_PREFERENCES.put(k, (String) nodes.get(k));
			}
		}
	}

	/**
	 * Comprueba si la preferencia se puede bloquear
	 * @param key Clave de la preferencia
	 * @return {@code true} Si es una preferencia bloqueable, {@code false} en caso contrario
	 */
	public static boolean isProtectedPreference(final String key) {
		return key.equals(PREFERENCE_GENERAL_UPDATECHECK)
				|| key.equals(PREFERENCE_GENERAL_ENABLED_JMULTICARD)
				|| key.equals(PREFERENCE_GENERAL_SIGNATURE_ALGORITHM)
				|| key.equals(PREFERENCE_GENERAL_DEFAULT_FORMAT_PDF)
				|| key.equals(PREFERENCE_GENERAL_DEFAULT_FORMAT_OOXML)
				|| key.equals(PREFERENCE_GENERAL_DEFAULT_FORMAT_FACTURAE)
				|| key.equals(PREFERENCE_GENERAL_DEFAULT_FORMAT_ODF)
				|| key.equals(PREFERENCE_GENERAL_DEFAULT_FORMAT_XML)
				|| key.equals(PREFERENCE_GENERAL_DEFAULT_FORMAT_BIN)
				|| key.equals(PREFERENCE_GENERAL_ALLOW_INVALID_SIGNATURES)
				|| key.equals(PREFERENCE_GENERAL_SECURE_CONNECTIONS)
				|| key.equals(SignatureFormatPreferenceKeys.XADES_POLICY_IDENTIFIER)
				|| key.equals(SignatureFormatPreferenceKeys.XADES_POLICY_HASH)
				|| key.equals(SignatureFormatPreferenceKeys.XADES_POLICY_HASH_ALGORITHM)
				|| key.equals(SignatureFormatPreferenceKeys.XADES_POLICY_QUALIFIER)
				|| key.equals(SignatureFormatPreferenceKeys.XADES_SIGN_FORMAT)
				|| key.equals(SignatureFormatPreferenceKeys.PADES_FORMAT)
				|| key.equals(SignatureFormatPreferenceKeys.PADES_POLICY_IDENTIFIER)
				|| key.equals(SignatureFormatPreferenceKeys.PADES_POLICY_HASH)
				|| key.equals(SignatureFormatPreferenceKeys.PADES_POLICY_HASH_ALGORITHM)
				|| key.equals(SignatureFormatPreferenceKeys.PADES_POLICY_QUALIFIER)
				|| key.equals(SignatureFormatPreferenceKeys.PADES_CHECK_SHADOW_ATTACK)
				|| key.equals(SignatureFormatPreferenceKeys.CADES_POLICY_IDENTIFIER)
				|| key.equals(SignatureFormatPreferenceKeys.CADES_POLICY_HASH)
				|| key.equals(SignatureFormatPreferenceKeys.CADES_POLICY_HASH_ALGORITHM)
				|| key.equals(SignatureFormatPreferenceKeys.CADES_POLICY_QUALIFIER)
				|| key.equals(SignatureFormatPreferenceKeys.CADES_IMPLICIT)
				|| key.equals(SignatureFormatPreferenceKeys.FACTURAE_POLICY)
				|| key.equals(KeyStorePreferenceKeys.SHOW_EXPIRED_CERTS);
	}

	/**
	 * Se obtienen las preferencias a exportar que se hayan registrado en el sistema y en el usuario.
	 * Si la preferencia existe en usuario y sistema, tendr&aacute; prioridad la del usuario.
	 * @return Mapa con las claves y valores del sistema.
	 */
	public static Map<String, Object> getPrefsToExport() {

		init();

		final Map<String, Object> result = new HashMap<>();
		try {
			if (SYSTEM_PREFERENCES != null) {
				final String[] systemKeys = SYSTEM_PREFERENCES.keys();
				for (int i = 0 ; i < systemKeys.length ; i++) {
					final String value = SYSTEM_PREFERENCES.get(systemKeys[i], null);
					if (value != null && (value.equals(TRUE_VALUE) || value.equals(FALSE_VALUE))) {
						result.put(systemKeys[i], Boolean.valueOf(value));
					} else {
						result.put(systemKeys[i], value);
					}
				}
			}
			final String[] userKeys = USER_PREFERENCES.keys();
			for (int i = 0 ; i < userKeys.length ; i++) {
				final String value = USER_PREFERENCES.get(userKeys[i], null);
				if (value != null && (value.equals(TRUE_VALUE) || value.equals(FALSE_VALUE))) {
					result.put(userKeys[i], Boolean.valueOf(value));
				} else {
					result.put(userKeys[i], value);
				}
			}
		} catch (final BackingStoreException e) {
			LOGGER.severe(
					"Error al obtener preferencias configuradas por el usuario" //$NON-NLS-1$
						+ e
				);
		}
		return result;
	}

	static boolean isNewConfigFile(final ConfigDataInfo updatedConfigData) {
		return UpdateConfigurationManager.isNewConfigFile(updatedConfigData);
	}

	/**
	 * Actualiza la informaci&oacute;n de los datos de configuraci&oacute;n usados, pero ni la ruta
	 * ni si configura la actualizaci&oacute;n autom&aacute;tica.
	 * @param configDataInfo Informaci&oacute;n del fichero de configuraci&oacute;n.
	 */
	static void setConfigFileInfo(final ConfigDataInfo configDataInfo) {
		UpdateConfigurationManager.setConfigFileInfo(configDataInfo);
	}

	/**
	 * Establece la informaci&oacute;n completa del fichero de configuraci&oacute;n remoto.
	 * @param url URL del fichero (puede ser {@code null}).
	 * @param allowUpdates {@code true} para habilitar la actualizaci&oacute;n autom&aacute;tica.
	 * @param configDataInfo Informaci&oacute;n del fichero (hash, etc.).
	 */
	public static void setConfigFileInfo(final String url, final boolean allowUpdates, final ConfigDataInfo configDataInfo) {
		UpdateConfigurationManager.setConfigFileInfo(url, allowUpdates, configDataInfo);
	}

	static void setConfigCheckDate() {
		UpdateConfigurationManager.setConfigCheckDate();
	}

	static boolean needCheckConfigUpdates() {
		return UpdateConfigurationManager.needCheckConfigUpdates();
	}

	static String getConfigFileUrl() {
		return UpdateConfigurationManager.getConfigFileUrl();
	}

	/**
	 * Elimina todas las preferencias del sistema originales. Esto s&oacute;lo ser&aacute; posible si se tienen
	 * los permisos necesarios y no deber&acute;a usarse m&acute;s que durante la desinstalaci&oacute;n de la
	 * aplicaci&oacute;n.
	 * @throws BackingStoreException Cuando no se pueden eliminar las preferencias.
	 */
	public static void removeSystemPrefs() throws BackingStoreException {
		init();

		if (REAL_SYSTEM_PREFERENCES != null) {
			final Preferences parent = REAL_SYSTEM_PREFERENCES.parent();
			REAL_SYSTEM_PREFERENCES.removeNode();
			removeEmptyTree(parent);
		}
		UpdateConfigurationManager.removeInternalNode();
	}

	static void removeEmptyTree(final Preferences node) throws BackingStoreException {

		init();

		Preferences parent = node;
		while (!parent.name().isEmpty() && parent.childrenNames().length == 0 && parent.keys().length == 0) {
			final Preferences newParent = parent.parent();
			parent.removeNode();
			parent = newParent;
		}
	}
}

