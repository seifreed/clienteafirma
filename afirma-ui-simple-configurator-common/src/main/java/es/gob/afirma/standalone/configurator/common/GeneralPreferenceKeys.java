/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.configurator.common;

/**
 * Catálogo de claves de preferencias generales de la aplicación: comportamiento
 * de arranque, formatos de firma por defecto, conexiones seguras y almacén de
 * claves local.
 *
 * <p>Esta clase es la <strong>fuente de verdad</strong> de las 22 claves del
 * dominio "General": aquí residen los valores literales. Es la cuarta y última
 * clase temática del <em>split</em> de {@link PreferencesManager}, que tras la
 * migración conserva únicamente los métodos de acceso, el <em>seam</em> de
 * test y el estado USER/SYSTEM/REAL_SYSTEM/DEFAULT.</p>
 */
public final class GeneralPreferenceKeys {

	private GeneralPreferenceKeys() {
		// No permitimos la instanciacion
	}

	// =====================================================================
	// Comportamiento general (8 claves)
	// =====================================================================

	/** Proteger cambios en preferencias.
	 * Un valor de <code>true</code> en esta preferencia indica que deben limitarse las opciones de configuraci&oacute;n
	 * mediante interfaz gr&aacute;fico, apareciendo de forma deshabilitada (solo para consulta).
	 * Un valor de <code>false</code> habilitar&aacute; que cualquier opci&oacute;n de configuraci&oacute;n pueda ser
	 * alterada por parte del usuario mediante el interfaz gr&aacute;fico. */
	public static final String BLOCKED = "preferencesBlocked"; //$NON-NLS-1$

	/** Comprobar que la versi&oacute;n actual de Java est&aacute; soportada.
	 * Un valor de <code>true</code> en esta preferencia hace que, al arrancar, la aplicaci&oacute;n compruebe autom&aacute;ticamente
	 * si la versi&oacute;n de Java con la que se ejecuta la aplicaci&oacute;n est&aacute; entre las versiones soportadas. Un valor de
	 * <code>false</code> har&aacute; que no se haga esta comprobaci&oacute;n. */
	public static final String CHECK_JAVA_VERSION = "checkJavaVersion"; //$NON-NLS-1$

	/** Evitar la confirmaci&oacute;n al cerrar la aplicaci&oacute;n o no.
	 * Un valor de <code>true</code> en esta preferencia permitir&aacute; cerrar la aplicaci&oacute;n sin ning&uacute;n di&aacute;logo
	 * de advertencia. Un valor de <code>false</code> har&aacute; que se muestre un di&aacute;logo para que el usuario confirme que
	 * realmente desea cerrar la aplicaci&oacute;n. */
	public static final String OMIT_ASKONCLOSE = "omitAskOnClose"; //$NON-NLS-1$

	/** Buscar actualizaciones al arrancar.
	 * Un valor de <code>true</code> en esta preferencia hace que, al arrancar, la aplicaci&oacute;n compruebe autom&aacute;ticamente
	 * si hay publicadas versiones m&aacute;s actuales del aplicativo. Un valor de <code>false</code> har&aacute; que no se haga
	 * esta comprobaci&oacute;n. */
	public static final String UPDATECHECK = "checkForUpdates"; //$NON-NLS-1$

	/** Mantiene habilitado el funcionamiento de JMultiCard.
	 * Un valor de <code>true</code> en esta preferencia hace que la aplicacion deje el comportamiento
	 * por defecto de JMulticard, que usaria las tarjetas DNIe y CERES. Un valor de <code>false</code>
	 * har&aacute; que no se desactive el uso de JMulticard para estas tarjetas. */
	public static final String ENABLED_JMULTICARD = "enabledJmulticard"; //$NON-NLS-1$

	/**
	 * Configura una propiedad que indica a la biblioteca WebSocket para la comunicaci&oacute;n con el
	 * navegador que aplique un peque&ntilde;o retardo en las comunicaciones para as&iacute; evitar que
	 * se bloquee el canal. Esto relantizar&aacute; las comunicaciones, lo cual es muy evidente conforme
	 * se trabaje con ficheros m&aacute;s grandes. S&oacute;lo se recomienda el su uso de esta propiedad
	 * cuando se use el cliente sobre VDI para evitar un mal mayor.
	 */
	public static final String VDI_OPTIMIZATION = "vdiOptimization"; //$NON-NLS-1$

	/**
	 * Configura una propiedad para habilitar un di&aacute;logo de espera que indica la tarea que este ejecutando
	 * Autofirma en ese mismo instante.
	 */
	public static final String ENABLE_PROGRESS_DIALOG = "enableProgressDialog"; //$NON-NLS-1$

	/** Solicitar confirmaci&oacute;n antes de firmar.
	 * Un valor de <code>true</code> en esta preferencia hace que se muestre un di&aacute;logo de
	 * confirmaci&oacute;n con las implicaciones de firma al iniciar una firma desde la interfaz
	 * de escritorio. */
	public static final String CONFIRMTOSIGN = "confirmToSign"; //$NON-NLS-1$

	// =====================================================================
	// Algoritmo y formatos de firma por defecto (7 claves)
	// =====================================================================

	/** Algoritmo de huella para firma.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>SHA1</li>
	 *  <li>SHA256</li>
	 *  <li>SHA384</li>
	 *  <li>SHA512</li>
	 * </ul> */
	public static final String SIGNATURE_ALGORITHM = "signatureHashAlgorithm"; //$NON-NLS-1$

	/** Formato de firma por defecto para documentos PDF.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>PAdes</li>
	 *  <li>CAdes</li>
	 *  <li>XAdes</li>
	 * </ul> */
	public static final String DEFAULT_FORMAT_PDF = "defaultSignatureFormatPdf"; //$NON-NLS-1$

	/** Formato de firma por defecto para documentos OOXML de Microsoft Office.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>OOXML (Office Open XML)</li>
	 *  <li>CAdES</li>
	 *  <li>XAdES</li>
	 * </ul> */
	public static final String DEFAULT_FORMAT_OOXML = "defaultSignatureFormatOoxml"; //$NON-NLS-1$

	/** Formato de firma por defecto para Facturas Electr&oacute;nicas.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>FacturaE</li>
	 *  <li>CAdES</li>
	 *  <li>XAdES</li>
	 * </ul> */
	public static final String DEFAULT_FORMAT_FACTURAE = "defaultSignatureFormatFacturae"; //$NON-NLS-1$

	/** Formato de firma por defecto para documentos ODF de LibreOffice / OpenOffice.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>ODF (Open Document Format)</li>
	 *  <li>CAdES</li>
	 *  <li>XAdES</li>
	 * </ul> */
	public static final String DEFAULT_FORMAT_ODF = "defaultSignatureFormatOdf"; //$NON-NLS-1$

	/** Formato de firma por defecto para documentos XML.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>CAdES</li>
	 *  <li>XAdES</li>
	 * </ul> */
	public static final String DEFAULT_FORMAT_XML = "defaultSignatureFormatXml"; //$NON-NLS-1$

	/** Formato de firma por defecto para ficheros binarios que no se adec&uacute;en a ninguna otra categor&iacute;a.
	 * Esta preferencia debe tener uno de estos valores:
	 * <ul>
	 *  <li>CAdES</li>
	 *  <li>XAdES</li>
	 * </ul> */
	public static final String DEFAULT_FORMAT_BIN = "defaultSignatureFormatBin"; //$NON-NLS-1$

	// =====================================================================
	// Conexiones seguras y multifirma masiva (4 claves)
	// =====================================================================

	/** Permitir la multifirma de firmas inv&aacute;lidas.
	 * Un valor de <code>true</code> en esta preferencia hace que se puedan multifirmar firmas a pesar
	 * de haberse detectado que no son v&aacute;lidas. */
	public static final String ALLOW_INVALID_SIGNATURES = "allowInvalidSignatures"; //$NON-NLS-1$

	/** Indica si en los procesos de firma masiva se deben sobreescribir o no los ficheros que
	 * se encuentren en el directorio de salida. */
	public static final String MASSIVE_OVERWRITE = "massiveOverride"; //$NON-NLS-1$

	/** Indica si debe validarse el certificado SSL en las conexiones de red. */
	public static final String SECURE_CONNECTIONS = "secureConnections"; //$NON-NLS-1$

	/** Lista de dominios seguros donde realizar conexiones SSL. */
	public static final String SECURE_DOMAINS_LIST = "secureDomainsList"; //$NON-NLS-1$

	// =====================================================================
	// Almacén de claves local y arranque DNIe (3 claves)
	// =====================================================================

	/** Ruta del almac&eacute;n de claves local seleccionado por defecto. */
	public static final String LOCAL_KEYSTORE_PATH = "defaultLocalKeystorePath"; //$NON-NLS-1$

	/** Indica si se usa o no el certificado por defecto configurado en llamadas desde el navegador. */
	public static final String USE_DEFAULT_STORE_IN_BROWSER_CALLS = "useDefaultStoreInBrowserCalls"; //$NON-NLS-1$

	/** No mostrar la pantalla inicial de uso de DNIe.
	 * Un valor de <code>true</code> en esta preferencia hace que nunca se muestre la pantalla inicial que sugiere al usuario
	 * el uso directo del DNIe como almac&eacute;n de claves. Un valor de <code>false</code> har&aacute; que se muestre esta pantalla
	 * al inicio siempre que se detecte un lector de tarjetas en el sistema. */
	public static final String HIDE_DNIE_START_SCREEN = "hideDnieStartScreen"; //$NON-NLS-1$
}
