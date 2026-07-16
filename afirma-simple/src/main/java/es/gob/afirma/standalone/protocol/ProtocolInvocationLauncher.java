/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.standalone.protocol;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.EventObject;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLHandshakeException;
import javax.swing.JOptionPane;

import es.gob.afirma.core.AOCancelledOperationException;
import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.core.InvalidDomainSSLCertificateException;
import es.gob.afirma.core.misc.LoggerUtil;
import es.gob.afirma.core.misc.Platform;
import es.gob.afirma.core.misc.protocol.ParameterException;
import es.gob.afirma.core.misc.protocol.ParameterLocalAccessRequestedException;
import es.gob.afirma.core.misc.protocol.ProtocolInvocationUriParser;
import es.gob.afirma.core.misc.protocol.ProtocolInvocationUriParserUtil;
import es.gob.afirma.core.misc.protocol.ProtocolVersion;
import es.gob.afirma.core.misc.protocol.UrlParameters;
import es.gob.afirma.core.misc.protocol.UrlParametersForBatch;
import es.gob.afirma.core.misc.protocol.UrlParametersToLoad;
import es.gob.afirma.core.misc.protocol.UrlParametersToSave;
import es.gob.afirma.core.misc.protocol.UrlParametersToSelectCert;
import es.gob.afirma.core.misc.protocol.UrlParametersToSign;
import es.gob.afirma.core.misc.protocol.UrlParametersToSignAndSave;
import es.gob.afirma.signers.batch.client.TriphaseDataParser;
import es.gob.afirma.standalone.JMulticardUtilities;
import es.gob.afirma.standalone.SimpleAfirma;
import es.gob.afirma.standalone.SimpleErrorCode;
import es.gob.afirma.standalone.configurator.common.PreferencesManager;
import es.gob.afirma.standalone.configurator.common.GeneralPreferenceKeys;
import es.gob.afirma.standalone.protocol.ProtocolInvocationLauncherUtil.DecryptionException;
import es.gob.afirma.standalone.ui.AboutDialog;
import es.gob.afirma.standalone.ui.OSXHandler;
import es.gob.afirma.standalone.ui.tasks.LoadKeystoreTask;

/**
 * Gestiona la ejecuci&oacute;n de Autofirma en una invocaci&oacute;n por
 * protocolo y bajo un entorno compatible <code>Swing</code>.
 *
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s
 */
public final class ProtocolInvocationLauncher {

    private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

    private static final String OK_RESPONSE = "OK"; //$NON-NLS-1$

    private static final ProtocolVersion[] SUPPORTED_PROTOCOLS = {
    		ProtocolVersion.getInstance(ProtocolVersion.VERSION_4_1),
    		ProtocolVersion.getInstance(ProtocolVersion.VERSION_3),
    		ProtocolVersion.getInstance(ProtocolVersion.VERSION_2),
    		ProtocolVersion.getInstance(ProtocolVersion.VERSION_1)
    };

    private static final int MIN_JAVASCRIPT_VERSION_CODE_NEEDED = 1;

    private static final int DEFAULT_JAVASCRIPT_VERSION_CODE = 1;

    /** Par&aacute;metro de entrada con el identificador de sesi&oacute;. */
	private static final String IDSESSION_PARAM = "idsession"; //$NON-NLS-1$

	/** Par&aacute;metro de entrada con los puertos en los que se puede intentar abrir el socket. */
	private static final String PORTS_PARAM = "ports"; //$NON-NLS-1$

	/** Par&aacute;metro de entrada con la versi&oacute;n del protocolo que se va a utilizar. */
	private static final String PROTOCOL_VERSION_PARAM = "v"; //$NON-NLS-1$

	/** Par&aacute;metro de entrada con la versi&oacute;n del JavaScript de invocaci&oacute;n. */
	private static final String JAVASCRIPT_VERSION_CODE_PARAM = "jvc"; //$NON-NLS-1$

	/** Par&aacute;metro de entrada con la versi&oacute;n m&iacute;nima de aplicaci&oacute;n cliente solicitada. */
	static final String MIN_REQUESTED_VERSION_PARAM = "mcv"; //$NON-NLS-1$

	/**
	 * Puerto a trav&eacute;s del que se realizar&aacute; la comunicaci&oacute;n por WebSocket
	 * cuando no se indique ninguno.
	 */
	private static final int DEFAULT_WEBSOCKET_PORT = 63117;

    /**
     * Estado session-level (sticky key, hilo de espera, tarea de carga del keystore).
     * Extra&iacute;do a {@link ProtocolSessionState} en la Fase A.1 del plan
     * Clean Code (2026-05-07): los tres campos eran static mutables en esta
     * clase; ahora viven en un singleton thread-safe con accesores expl&iacute;citos.
     * Los m&eacute;todos est&aacute;ticos p&uacute;blicos de abajo conservan la
     * fachada por compatibilidad con los ~25 call sites externos.
     */
    private static final ProtocolSessionState SESSION = ProtocolSessionState.INSTANCE;

    /**
     * Registro de handlers Strategy para verbos del protocolo {@code afirma://}.
     * Introducido en la Fase A del plan Clean Code (2026-05-07): los verbos
     * nuevos se enchufan aquí en lugar de añadir un {@code else if} más al
     * dispatch legacy de {@link #launch(String, ProtocolVersion, boolean)}.
     *
     * <p>Estado de la migración:</p>
     * <ul>
     *   <li>Fase A: {@link EudiwProtocolHandler} (M4 verbo nuevo).</li>
     *   <li>Fase A.3: websocket, service, load.</li>
     *   <li>Fase A.4: batch, selectcert, save, signandsave,
     *       sign|cosign|countersign.</li>
     * </ul>
     */
    private static final ProtocolOperationRegistry OPERATION_REGISTRY = new ProtocolOperationRegistry()
    		.register(new EudiwProtocolHandler())
    		.register(verbHandler(
    				url -> url.startsWith("afirma://websocket?") || url.startsWith("afirma://websocket/?"), //$NON-NLS-1$ //$NON-NLS-2$
    				ProtocolInvocationLauncher::handleWebSocket))
    		.register(verbHandler(
    				url -> url.startsWith("afirma://service?") || url.startsWith("afirma://service/?"), //$NON-NLS-1$ //$NON-NLS-2$
    				ProtocolInvocationLauncher::handleService))
    		.register(verbHandler(
    				url -> url.startsWith("afirma://batch?") || url.startsWith("afirma://batch/?"), //$NON-NLS-1$ //$NON-NLS-2$
    				ProtocolInvocationLauncher::handleBatch))
    		.register(verbHandler(
    				url -> url.startsWith("afirma://selectcert?") || url.startsWith("afirma://selectcert/?"), //$NON-NLS-1$ //$NON-NLS-2$
    				ProtocolInvocationLauncher::handleSelectCert))
    		.register(verbHandler(
    				url -> url.startsWith("afirma://save?") || url.startsWith("afirma://save/?"), //$NON-NLS-1$ //$NON-NLS-2$
    				ProtocolInvocationLauncher::handleSave))
    		.register(verbHandler(
    				url -> url.startsWith("afirma://signandsave?") || url.startsWith("afirma://signandsave/?"), //$NON-NLS-1$ //$NON-NLS-2$
    				ProtocolInvocationLauncher::handleSignAndSave))
    		.register(verbHandler(
    				url -> url.startsWith("afirma://sign?") || url.startsWith("afirma://sign/?") //$NON-NLS-1$ //$NON-NLS-2$
    						|| url.startsWith("afirma://cosign?") || url.startsWith("afirma://cosign/?") //$NON-NLS-1$ //$NON-NLS-2$
    						|| url.startsWith("afirma://countersign?") || url.startsWith("afirma://countersign/?"), //$NON-NLS-1$ //$NON-NLS-2$
    				ProtocolInvocationLauncher::handleSign))
    		.register(verbHandler(
    				url -> url.startsWith("afirma://load?") || url.startsWith("afirma://load/?"), //$NON-NLS-1$ //$NON-NLS-2$
    				ProtocolInvocationLauncher::handleLoad));

    /** Adapta una pareja (predicado, función) a un {@link ProtocolOperationHandler}. */
    private static ProtocolOperationHandler verbHandler(
    		final java.util.function.Predicate<String> matches,
    		final java.util.function.BiFunction<String, LaunchContext, String> body) {
    	return new ProtocolOperationHandler() {
    		@Override
    		public boolean handles(final String url) {
    			return url != null && matches.test(url);
    		}
    		@Override
    		public String process(final String url, final LaunchContext ctx) {
    			return body.apply(url, ctx);
    		}
    	};
    }

	/**
	 * Recupera la entrada con la clave y certificado prefijados para las
	 * operaciones con certificados.
	 *
	 * @return Entrada con el certificado y la clave prefijados.
	 */
	public static PrivateKeyEntry getStickyKeyEntry() {
		return SESSION.stickyKeyEntry();
	}

	/**
	 * Establece una clave y certificado prefijados para las operaciones con
	 * certificados.
	 *
	 * @param stickyKeyEntry Entrada con el certificado y la clave prefijados.
	 */
	public static void setStickyKeyEntry(final PrivateKeyEntry stickyKeyEntry) {
		SESSION.stickyKeyEntry(stickyKeyEntry);
	}

    /** Invocado por reflexi&oacute;n (v&eacute;ase {@link Class#getDeclaredMethod(String, Class[])} m&aacute;s abajo)
     * cuando se solicita el di&aacute;logo "Acerca de" desde el integrador del SO.
     * @param event Evento que dispar&oacute; la invocaci&oacute;n; no se usa, solo cumple la firma esperada
     *              por el delegado de menu de aplicaci&oacute;n. */
	void showAbout(final EventObject event) {
    	AboutDialog.showAbout(null);
    }

	/**
	 * Lanza la aplicaci&oacute;n y realiza las acciones indicadas en la URL. Este
	 * m&eacute;todo usa siempre comunicaci&oacute;n mediante servidor intermedio,
	 * nunca localmente.
	 *
     * @param urlString URL de invocaci&oacute;n por protocolo.
	 * @return Resultado de la operaci&oacute;n.
	 */
    public static String launch(final String urlString)  {
        return launch(urlString, null, false);
    }

    /**
     * Calcula la versi&oacute;n de protocolo efectiva combinando la declarada
     * con el c&oacute;digo de versi&oacute;n del script invocador. Funci&oacute;n
     * pura — devuelve la versi&oacute;n nueva en lugar de mutar estado.
     *
     * <p>Hist&oacute;rico: Autoscript 1.10 introdujo mejoras compatibles con
     * Autofirma 1.9, pero declarar protocolo 4 obligar&iacute;a a los usuarios a
     * actualizar a 1.10. Por compatibilidad, cuando llega protocolo 4 con
     * c&oacute;digo de script > 3 promovemos a la versi&oacute;n interna 4.1
     * que habilita esas mejoras sin romper a clientes 1.9. Cuando todos los
     * clientes soporten {@code MinorVersion} este c&oacute;digo se puede
     * eliminar.</p>
     *
     * @param protocolVersion Versi&oacute;n declarada por el cliente.
     * @param scriptVersionCode Versi&oacute;n del script de invocaci&oacute;n.
     * @return La misma versi&oacute;n recibida o {@code 4.1} si aplica el ajuste.
     */
    private static ProtocolVersion reviewProtocolVersion(final ProtocolVersion protocolVersion, final int scriptVersionCode) {
		if (protocolVersion != null
				&& protocolVersion.getMajorVersion() == 4
				&& scriptVersionCode > 3) {
			return ProtocolVersion.getInstance(ProtocolVersion.VERSION_4_1);
		}
		return protocolVersion;
    }

	/**
	 * Lanza la aplicaci&oacute;n y realiza las acciones indicadas en la URL.
	 *
     * @param urlString URL de invocaci&oacute;n por protocolo.
	 * @param protocolVersion Versi&oacute;n del protocolo de comunicaci&oacute;n
	 *                        utilizada por el solicitante.
	 * @param bySocket        Si se establece a <code>true</code> se usa una
	 *                        comuicaci&oacute;n de vuelta mediante conexi&oacute;n
	 *                        HTTP local (a <code>localhost</code>), si se establece
	 *                        a <code>false</code> se usa un servidor intermedio
     *                 para esta comunicaci&oacute;n de vuelta.
	 * @return Resultado de la operaci&oacute;n.
	 */
    public static String launch(final String urlString, final ProtocolVersion protocolVersion, final boolean bySocket)  {

    	LOGGER.info("Se recibe una llamada de operacion"); //$NON-NLS-1$

        // En macOS sobrecargamos el "Acerca de..." del sistema operativo, que tambien
        // aparece en la invocacion por protocolo
        if (Platform.OS.MACOSX.equals(Platform.getOS())) {
	    	try {
				final Method aboutMethod = ProtocolInvocationLauncher.class.getDeclaredMethod("showAbout", //$NON-NLS-1$
						EventObject.class);
	    		OSXHandler.setAboutHandler(null, aboutMethod);
			} catch (final Exception e) {
	    		LOGGER.warning("No ha sido posible establecer el menu 'Acerca de...' de OS X: " + e); //$NON-NLS-1$
			}
        }

        if (urlString == null) {
            LOGGER.severe("No se ha proporcionado una URL para la invocacion"); //$NON-NLS-1$
            final ErrorCode error = SimpleErrorCode.Request.REQUEST_URI_NOT_FOUND;
            ProtocolInvocationLauncherErrorManager.showError(protocolVersion, error);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(protocolVersion, error);
        }
        if (!urlString.startsWith("afirma://") && !urlString.startsWith("getresult?")) { //$NON-NLS-1$ //$NON-NLS-2$
            LOGGER.severe("La URL de invocacion no comienza por 'afirma://'"); //$NON-NLS-1$
            final ErrorCode error = SimpleErrorCode.Request.UNSUPPORTED_REQUEST_SCHEME;
            ProtocolInvocationLauncherErrorManager.showError(protocolVersion, error);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(protocolVersion, error);
        }

		// Configuramos el uso de JMulticard segun lo establecido en el dialogo de
		// preferencias
		final boolean jMulticardEnabled = PreferencesManager
				.getBoolean(GeneralPreferenceKeys.ENABLED_JMULTICARD);
        JMulticardUtilities.configureJMulticard(jMulticardEnabled);

        // Por defecto, usaremos la version de protocolo proporcionada para la operacion,
        // aunque se extraera de la URL de llamada en caso de se una peticion de apertura de
        // servicio de sockets o websockets. Variable local desde Fase A.2 — antes era
        // un campo static mutable.
        ProtocolVersion requestedProtocolVersion = protocolVersion;

        // Extraemos los parametros de la URL
        final Map<String, String> urlParams = extractParams(urlString);

        // Comprobamos la version de codigo declarada por el JavaScript y establecemos una
        // por defecto si no la declara o no es valida
        int jvc = DEFAULT_JAVASCRIPT_VERSION_CODE;
        if (urlParams.containsKey(JAVASCRIPT_VERSION_CODE_PARAM)) {
        	try {
        	jvc = Integer.parseInt(urlParams.get(JAVASCRIPT_VERSION_CODE_PARAM));
        	}
        	catch (final Exception e) {
        		jvc = DEFAULT_JAVASCRIPT_VERSION_CODE;
			}
        }

        // Si la version de codigo JavaScript es menor de la exigida, mostramos
        // una advertencia
        if (jvc < MIN_JAVASCRIPT_VERSION_CODE_NEEDED) {
        	JOptionPane.showMessageDialog(
        			null,												// Componente padre
        			ProtocolMessages.getString("ProtocolLauncher.51"),	// Mensaje //$NON-NLS-1$
        			ProtocolMessages.getString("ProtocolLauncher.52"),	// Titulo //$NON-NLS-1$
        			JOptionPane.WARNING_MESSAGE);						// Tipo de mensaje
        }

        //TODO: Mejorar toda la logica de comunicacion:
        // - La comunicacion por sockets/websockets no deberia utilizar URLs.
        // - Se utiliza la excepcion SocketOperationException para gestionar los errores
        //   cuando la comunicacion NO es por sockets (contrariamente a lo indicado en el
        //   javadoc de los metodos y la excepcion.
        // - Los errores en el proceso siempre deberian lanzar una excepcion y no devolver
        //   una cadena con el mensaje del error.

        // M4 / Plan Clean Code Fase A: dispatch de verbos a través de
        // ProtocolOperationRegistry. Si ningún handler reconoce la URL,
        // cae al legacy if-chain. Cada nuevo verbo se enchufa en el registry
        // — no aquí.
        final var registeredHandler = OPERATION_REGISTRY.resolve(urlString);
        if (registeredHandler.isPresent()) {
        	final LaunchContext ctx = new LaunchContext(
        			requestedProtocolVersion, bySocket, urlParams, jvc);
        	try {
        		return registeredHandler.get().process(urlString, ctx);
        	}
        	catch (final IllegalArgumentException e) {
        		LOGGER.log(Level.SEVERE, "Parámetros inválidos en URL " + LoggerUtil.getCleanUserHomePath(urlString) + ": " + e.getMessage(), e); //$NON-NLS-1$ //$NON-NLS-2$
        		final ErrorCode errorCode = SimpleErrorCode.Request.UNSUPPORTED_OPERATION;
        		ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, errorCode);
        		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, errorCode);
        	}
        	catch (final Exception e) {
        		LOGGER.log(Level.SEVERE, "Error procesando handler de protocolo: " + e, e); //$NON-NLS-1$
        		// Reutilizamos UNSUPPORTED_OPERATION para no introducir un nuevo
        		// ErrorCode externo sin coordinación con CTT. Ver Fase A.1 del plan
        		// Clean Code: cuando los 7 verbos legacy migren al registry,
        		// se añadirá un código genérico UNKNOWN_OPERATION_ERROR.
        		final ErrorCode errorCode = SimpleErrorCode.Request.UNSUPPORTED_OPERATION;
        		ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, errorCode);
        		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, errorCode);
        	}
        }

        // Los 9 verbos del protocolo afirma:// están registrados en
        // OPERATION_REGISTRY (Fases A + A.3 + A.4 del plan Clean Code,
        // 2026-05-07): eudiw-present, websocket, service, batch, selectcert,
        // save, signandsave, sign|cosign|countersign, load. Si llegamos aquí
        // es que la URL tiene un verbo desconocido.
		LOGGER.severe("La operacion indicada en la URL no esta soportada: " + //$NON-NLS-1$
    				urlString.substring(0, Math.min(30, urlString.length())) + "..." //$NON-NLS-1$
		);

		final ErrorCode errorCode = SimpleErrorCode.Request.UNSUPPORTED_OPERATION;
		ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, errorCode);
		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, errorCode);
    }

    /**
     * Envia un error al servidor intermedio o, si no proporcionan los datos necesarios, se muestra al usuario.
     * @param msg Mensaje de error que enviar.
     * @param errorCode C&oacute;digo de error.
     * @param storageServerUrl URL del servicio de guardado del servidor intermedio.
     * @param id Identificador para el guardado en el servidor intermedio.
     * @param protocolVersion Versi&oacute;n del protocolo activa para la invocaci&oacute;n actual.
     */
    private static void processIntermediateServiceError(final String msg, final ErrorCode errorCode,
    		final URL storageServerUrl, final String id, final ProtocolVersion protocolVersion) {
    	if (storageServerUrl != null && id != null) {
    		sendDataToServer(msg, storageServerUrl.toString(), id, protocolVersion);
    	} else {
    		ProtocolInvocationLauncherErrorManager.showError(protocolVersion, errorCode);
    	}
    }

    /**
	 * Inicia el proceso de solicitud de espera activa a trav&eacute;s del servidor
	 * intermedio.
	 *
	 * @param storageServletUrl URL del servicio de guardado en el servidor
	 *                          intermedio.
	 * @param id                Identificador de la transacci&oacute;n para la que
	 *                          se le solicita la espera.
     */
    private static void requestWait(final URL storageServletUrl, final String id) {
    	try {
	    	final Thread thread = new ActiveWaitingThread(storageServletUrl.toString(), id);
	    	SESSION.activeWaitingThread(thread);
	    	thread.start();
		} catch (final Exception e) {
			LOGGER.warning("Se ha interrumpido la espera activa para la conexion con servidor intermedio: " + e); //$NON-NLS-1$
		}
	}

	/**
	 * Si la comunicaci&oacute;n con el cliente JS NO es por socket y los par&aacute;metros piden
	 * espera activa, lanza el {@link ActiveWaitingThread} que mantiene viva la conexi&oacute;n
	 * con el servidor intermedio. Patr&oacute;n compartido por los 5 verbos que devuelven
	 * resultado v&iacute;a servidor intermedio (batch/selectcert/save/signandsave/sign).
	 *
	 * @param params Par&aacute;metros de la operaci&oacute;n con la URL y el id de almac&eacute;n.
	 * @param bySocket {@code true} si la conversaci&oacute;n vuelve por socket; en ese caso no
	 *                 hace nada porque no existe ese punto de retorno intermedio.
	 */
	private static void startActiveWaitingIfNeeded(final UrlParameters params, final boolean bySocket) {
		if (!bySocket && params.isActiveWaiting()) {
			requestWait(params.getStorageServletUrl(), params.getId());
		}
	}

	/** Env&iacute;a datos al servidor intermedio e interrumpe la espera declarada en
	 * este servidor.
     * @param data Cadena de texto.
     * @param serviceUrl URL del servicio de env&iacute;o de datos.
	 * @param id         Identificador del mensaje en el servidor.
	 * @param protocolVersion Versi&oacute;n del protocolo activa para la invocaci&oacute;n actual.
	 */
	private static void sendDataToServer(final String data, final String serviceUrl, final String id,
			final ProtocolVersion protocolVersion) {
		// Detenemos la espera activa
		final Thread waitingThread = getActiveWaitingThread();
		if (waitingThread != null) {
			waitingThread.interrupt();
		}
		// Esperamos a que termine cualquier otro envio al servidor para que no se pisen
		synchronized (IntermediateServerUtil.getUniqueSemaphoreInstance()) {
			try {
				SimpleAfirma.getSSLContextConfigurationTask().join();
			} catch (final InterruptedException e) {
				LOGGER.warning("No se ha podido configurar correctamente el contexto SSL: " + e); //$NON-NLS-1$
			}
			try {
				IntermediateServerUtil.sendData(data, serviceUrl, id);
			} catch (final SocketTimeoutException e) {
				LOGGER.log(Level.SEVERE, "Se excedio el tiempo de espera maximo en la llamada al servicio de guardado del servidor intermedio", e); //$NON-NLS-1$
				ProtocolInvocationLauncherErrorManager.showError(protocolVersion, SimpleErrorCode.Communication.SENDING_RESULT_TIMEOUT);
			}
			catch (final InvalidDomainSSLCertificateException e) {
				LOGGER.log(Level.SEVERE, "El certificado SSL no esta expedido para el dominio al que pertenece el servidor: " + e, e); //$NON-NLS-1$
				ProtocolInvocationLauncherErrorManager.showError(protocolVersion, ErrorCode.Communication.INVALID_DOMAIN_SSL_CERTIFICATE_ERROR, e.getHost());
			}catch (final Exception e) {
				LOGGER.log(Level.SEVERE, "Error al enviar los datos al servidor intermedio: " + e, e); //$NON-NLS-1$
				ProtocolInvocationLauncherErrorManager.showError(protocolVersion, SimpleErrorCode.Communication.SENDING_RESULT_OPERATION);
			}
		}
	}

	/**
	 * Obtiene el hilo encargado de solicitar a trav&eacute;s del servidor
	 * intermedio que se realice una espera activa del resultado de la
	 * operaci&oacute;n actual.
	 *
	 * @return Hilo que solicita reiteradamente la espera o {@code null} si no se
	 *         inici&oacute; la espera activa.
	 */
	public static Thread getActiveWaitingThread() {
		return SESSION.activeWaitingThread();
	}

	/**
	 * Parsea la cadena con la versi&oacute;n del protocolo de comunicacion
	 * solicitada.
	 *
	 * @param version Declarada del protocolo.
	 * @return Version de protocolo o {@code 1} si no era una cadena v&aacute;lida.
	 */
	private static ProtocolVersion parseProtocolVersion(final String version) {

		ProtocolVersion protocolVersion;
		if (version != null) {
			try {
				protocolVersion = ProtocolVersion.getInstance(version);
			} catch (final Exception e) {
				LOGGER.warning("Se ha proporcionado en la llamada un identificador de version del protocolo con formato no soportado: " + e); //$NON-NLS-1$
				protocolVersion = ProtocolVersion.getInstance(ProtocolVersion.VERSION_0);
			}
		}
		else {
			protocolVersion = ProtocolVersion.getInstance(ProtocolVersion.VERSION_0);
		}
    	return protocolVersion;
	}

	/**
	 * Obtiene el valor asignado al par&aacute;metro de versi&oacute;n de una URL.
	 * @param params Par&acute;metros declarados en una URL.
	 * @return Valor del par&aacute;metro de versi&oacute;n ('v') o el valor '1' si no est&aacute; definido.
	 */
	private static ProtocolVersion getVersion(final Map<String, String> params) {

		// Si se encuentra el parametro con la version, se devuelve. Si no, se devuelve
		// 1.
		ProtocolVersion protocolVersion;
		final String protocolId = params.get(PROTOCOL_VERSION_PARAM);
		if (protocolId != null) {
			try {
				protocolVersion = ProtocolVersion.getInstance(protocolId.trim());
			} catch (final Exception e) {
				LOGGER.log(Level.WARNING, "El ID de protocolo indicado no es valido (" //$NON-NLS-1$
						+ LoggerUtil.getTrimStr(protocolId) + ")", e); //$NON-NLS-1$
				protocolVersion = ProtocolVersion.getInstance(ProtocolVersion.VERSION_0);
			}
		}
		else {
			protocolVersion = ProtocolVersion.getInstance(ProtocolVersion.VERSION_0);
		}

		return protocolVersion;
	}

	/**
	 * Extrae los parametros declarados en una URL con sus valores asignados.
	 * @param url URL de la que extraer los par&aacute;metros.
	 * @return Conjunto de par&aacute;metros con sus valores.
	 */
	private static Map<String, String> extractParams(final String url) {

		final Map<String, String> params = new HashMap<>();

		final int initPos = url.indexOf('?') + 1;
		final String[] urlParams = url.substring(initPos).split("&"); //$NON-NLS-1$
		for (final String param : urlParams) {
			final int equalsPos = param.indexOf('=');
			if (equalsPos > 0) {
				try {
					params.put(
							param.substring(0, equalsPos),
							URLDecoder.decode(param.substring(equalsPos + 1), StandardCharsets.UTF_8.toString()));
				} catch (final UnsupportedEncodingException e) {
					LOGGER.warning("No se pudo decodificar el valor del parametro '" + param.substring(0, equalsPos) + "': " + e); //$NON-NLS-1$ //$NON-NLS-2$
				}
			}
		}

		return params;
	}


	/** Obtiene los puertos que se deben probar para la conexi&oacute;n externa.
	 * Asigna cual es la clave.
	 * @param urlParams Par&aacute;metros de la URL de entre los que obtener los puertos.
	 * @return Listados de puertos. */
	private static ChannelInfo getChannelInfo(final Map<String, String> urlParams) {

		int[] ports = null;
		final String ps = urlParams.get(PORTS_PARAM);
		if (ps != null) {
			final String[] portsText = ps.split(","); //$NON-NLS-1$
			ports = new int[portsText.length];
			for (int i = 0; i < portsText.length; i++) {
				try {
					ports[i] = Math.abs(Integer.parseInt(portsText[i]));
				}
				catch(final Exception e) {
					throw new IllegalArgumentException(
						"El parametro 'ports' de la URI de invocacion contiene valores no numericos: " + e //$NON-NLS-1$
					, e);
				}
			}
		}

		String idSession = urlParams.get(IDSESSION_PARAM);
		if (idSession != null && !idSession.isEmpty()){
		    LOGGER.info("Se ha recibido un id de sesion: " + idSession); //$NON-NLS-1$
		    // El ID de sesion solo puede estar conformado por numeros. Usar otra cadena nos expondria
		    // a una injeccion de codigo en los AppleScripts que se ejecuten con el
		    boolean valid = true;
		    for (final char c : idSession.toCharArray()) {
		    	if (!Character.isLetterOrDigit(c)) {
		    		valid = false;
		    		break;
		    	}
		    }
		    if (!valid) {
		    	LOGGER.info("No se ha proporcionado un id de sesion valido"); //$NON-NLS-1$
		    	idSession = null;
		    }
		}
		else {
            LOGGER.info("No se utilizara id para la sesion"); //$NON-NLS-1$
        }

		return new ChannelInfo(idSession, ports);
	}

	/**
	 * Cierra la aplicaci&oacute;n.
	 *
     * @param exitCode C&oacute;digo de cierre de la aplicaci&oacute;n (negativo
	 *                 indica error y cero indica salida normal.
	 */
    public static void forceCloseApplication(final int exitCode) {
       	Runtime.getRuntime().halt(exitCode);
    }

    /**
     * Comprueba si la aplicaci&oacute;n es compatible con la versi&oacute;n de protocolo
     * solicitada.
     * @param protocolVersion Versi&oacute;n de protocolo.
     * @return {@code true} si se es compatible con la versi&oacute;n indicada, {@code false}
     * en caso contrario.
     */
	public static boolean isCompatibleWith(final ProtocolVersion protocolVersion) {
		for (final ProtocolVersion supportedVersion : SUPPORTED_PROTOCOLS) {
			if (supportedVersion.isCompatibleWith(protocolVersion)) {
				return true;
			}
		}
		return false;
	}


	/**
	 * Inicia en segundo plano la tarea para cargar del almac&eacute;n de claves por defecto
	 * si no se hab&iacute;a hecho antes. El almac&eacute;n cargado puede ser el del sistema
	 * o el configurado en Autofirma para la invocaci&oacute;n por protocolo, siempre que
	 * no sea un almac&eacute;n en fichero o tarjeta.
	 */
	public static void initLoadKeyStoreTask() {
		SESSION.initLoadKeyStoreTask();
	}

	/**
	 * Devuelve la tarea de carga del almac&eacute;n de claves en segundo plano.
	 * @return Tarea de carga del almac&eacute;n o {@code null} si no se defini&oacute;.
	 */
	public static LoadKeystoreTask getLoadKeyStoreTask() {
		return SESSION.loadKeyStoreTask();
	}

	// =========================================================================
	// Handlers de verbos del protocolo afirma://
	// =========================================================================
	//
	// Cada método handleXxx contiene la orquestación verbatim del verbo
	// correspondiente extraída del antiguo if-chain de launch(). Se invocan
	// vía OPERATION_REGISTRY (Fase A.3 del plan Clean Code, 2026-05-07).
	//
	// La regla es preservar comportamiento exacto:
	//   - Mismo orden de operaciones
	//   - Mismas excepciones capturadas
	//   - Mismos códigos de error
	//   - `requestedProtocolVersion` empieza en ctx.version() y puede
	//     reasignarse desde la URL (websocket, service) o desde los params
	//     (resto), igual que antes.
	// =========================================================================

	/**
	 * Verbo {@code afirma://websocket?...} — apertura del canal WebSocket
	 * (modo asíncrono desde Autoscript 1.10 cuando jvc &gt; 3).
	 */
	private static String handleWebSocket(final String urlString, final LaunchContext ctx) {
    	LOGGER.info("Se inicia el modo de comunicacion por websockets"); //$NON-NLS-1$

    	ProtocolVersion requestedProtocolVersion = getVersion(ctx.urlParams());
    	requestedProtocolVersion = reviewProtocolVersion(requestedProtocolVersion, ctx.javascriptVersionCode());

    	final ChannelInfo channelInfo = getChannelInfo(ctx.urlParams());

    	// Si no se indica ningun puerto, es que usamos el protocolo v3, segun el cual el puerto
    	// a traves del que se establecera la conexion sera el
    	if (channelInfo.getPorts() == null) {
    		LOGGER.severe("Usando puerto por defecto para la comunicacion WebSocket"); //$NON-NLS-1$
    		channelInfo.setPorts(new int[] { DEFAULT_WEBSOCKET_PORT });
    	}

    	try {
    		// A partir de Autoscript 1.10 se admite la llamada asincrona a traves de Websockets
    		final boolean asynchronous = ctx.javascriptVersionCode() > 3;
    		AfirmaWebSocketServerManager.startService(channelInfo, requestedProtocolVersion, asynchronous);
    	} catch (final UnsupportedProtocolException e) {
    		LOGGER.log(Level.SEVERE, "La version del protocolo no esta soportada (" + e.getVersion() + "). Se cerrara la aplicacion" , e); //$NON-NLS-1$ //$NON-NLS-2$
    		ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
    		forceCloseApplication(0);
    	}
    	catch (final SocketOperationException e) {
    		LOGGER.log(Level.SEVERE, "No se pudo abrir ninguno de los puertos proporcionados. Se cerrara la aplicacion", e); //$NON-NLS-1$
    		ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, SimpleErrorCode.Internal.SOCKET_INITIALIZING_ERROR);
    		forceCloseApplication(0);
    	} catch (final SllKeyStoreException e) {
    		LOGGER.log(Level.SEVERE, "No se ha encontrado o no ha podido cargarse el almacen del certificado SSL. Se cerrara la aplicacion", e); //$NON-NLS-1$
    		ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, SimpleErrorCode.Internal.LOADING_SSL_KEYSTORE_ERROR);
    		forceCloseApplication(0);
		}

    	return OK_RESPONSE;
	}

	/**
	 * Verbo {@code afirma://service?...} — apertura del canal por sockets
	 * (legacy; los puertos son obligatorios aquí).
	 */
	private static String handleService(final String urlString, final LaunchContext ctx) {
    	LOGGER.info("Se inicia el modo de comunicacion por sockets"); //$NON-NLS-1$

    	ProtocolVersion requestedProtocolVersion = getVersion(ctx.urlParams());
    	requestedProtocolVersion = reviewProtocolVersion(requestedProtocolVersion, ctx.javascriptVersionCode());

    	final ChannelInfo channelInfo = getChannelInfo(ctx.urlParams());

    	// El listado de puertos de entre los que seleccionar uno es obligatorio
    	// en esta opcion
    	if (channelInfo.getPorts() == null) {
    		LOGGER.log(Level.SEVERE, "No se ha proporcionado el listado de puertos para la conexion"); //$NON-NLS-1$
    		final ErrorCode errorCode = SimpleErrorCode.Request.PORTS_NOT_FOUND;
    		ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, errorCode);
    		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, errorCode);
    	}

    	try {
    		ServiceInvocationManager.startService(channelInfo, requestedProtocolVersion);
    	} catch (final UnsupportedProtocolException e) {
    		LOGGER.severe("La version del protocolo no esta soportada (" + e.getVersion() + "): " + e); //$NON-NLS-1$ //$NON-NLS-2$
    		ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
    		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
    	} catch (final SllKeyStoreException e) {
    		LOGGER.log(Level.SEVERE, "No se ha encontrado o no ha podido cargarse el almacen del certificado SSL. Se cerrara la aplicacion", e); //$NON-NLS-1$
    		ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, SimpleErrorCode.Internal.LOADING_SSL_KEYSTORE_ERROR);
    		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final IOException e) {
    		LOGGER.log(Level.SEVERE, "No se ha podido abrir el socket o se ha cerrado durante la operacion. Se cierra la aplicacion", e); //$NON-NLS-1$
    		ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, SimpleErrorCode.Internal.SOCKET_INITIALIZING_ERROR);
    		forceCloseApplication(0);
		}

    	return OK_RESPONSE;
	}

	/**
	 * Verbo {@code afirma://batch?...} — procesado de un lote de firma.
	 * Soporta file_id download para definición remota del batch (XML o JSON).
	 */
	private static String handleBatch(final String urlString, final LaunchContext ctx) {
    	LOGGER.info("Se invoca a la aplicacion para el procesado de un lote de firma"); //$NON-NLS-1$

    	ProtocolVersion requestedProtocolVersion = ctx.version();
    	try {
            UrlParametersForBatch params =
            		ProtocolInvocationUriParserUtil.getParametersToBatch(ctx.urlParams(), !ctx.bySocket());

			// Si se indica un identificador de fichero, es que el JSON o XML de definicion de lote
			// se tiene que descargar desde el servidor intermedio
            if (params.getFileId() != null) {
            	try {
            		final byte[] batchDefinition;
            		try {
            			batchDefinition = ProtocolInvocationLauncherUtil.getDataFromRetrieveServlet(params);
            		} catch (final DecryptionException e) {
            			throw new IntermediateServerErrorSendedException("Error al descifrar los datos obtenidos", e); //$NON-NLS-1$
            		} catch (final SocketTimeoutException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Se excedio el tiempo de espera de la llamada al servico de recuperacion del servidor intermedio cuando se trataron de obtener los datos para la firma de lote", e, //$NON-NLS-1$
            					SimpleErrorCode.Communication.RECIVING_DATA_OF_BATCH_TIMEOUT);
            		} catch (final IOException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Error al recuperar los datos enviados por el cliente a traves del servidor intermedio", e, //$NON-NLS-1$
            					SimpleErrorCode.Communication.RECIVING_DATA_OF_BATCH_OPERATION);
            		}

            		final Map<String, String> paramsMap;
            		if (params.isJsonBatch()) {
            			paramsMap = TriphaseDataParser.parseParamsListJson(batchDefinition);
            		} else {
            			paramsMap = ProtocolInvocationUriParserUtil.parseXml(batchDefinition);
            		}
            		params = ProtocolInvocationUriParserUtil.getParametersToBatch(paramsMap, !ctx.bySocket());
            	} catch (final IntermediateServerErrorSendedException e) {
            		LOGGER.log(Level.SEVERE, "Se obtuvo un error al descargar los datos del servidor intermedio", e); //$NON-NLS-1$
            		processIntermediateServiceError(e.getMessage(), e.getErrorCode(), params.getStorageServletUrl(), params.getId(), requestedProtocolVersion);
            		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            	}
            }

            // Si la peticion no se hizo a traves de socket/websocket, la version de protocolo se indica en la propia operacion
            if (requestedProtocolVersion == null) {
           		requestedProtocolVersion = parseProtocolVersion(params.getMinimumProtocolVersion());
            	requestedProtocolVersion = reviewProtocolVersion(requestedProtocolVersion, ctx.javascriptVersionCode());
            }

            // En caso de comunicacion por servidor intermedio, solicitamos, si corresponde,
            // que se espere activamente hasta el fin de la tarea
            startActiveWaitingIfNeeded(params, ctx.bySocket());

			LOGGER.info(
					"Se inicia la operacion de firma de lote. Version de protocolo: " + requestedProtocolVersion); //$NON-NLS-1$

			String msg;
            try {
                msg = ProtocolInvocationLauncherBatch.processBatch(params, requestedProtocolVersion);
			}
            catch(final AOCancelledOperationException e) {
            	LOGGER.severe("Operacion de firma por lotes cancelada por el usuario"); //$NON-NLS-1$
                msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            }
			// solo entra en la excepcion en el caso de que haya que devolver errores a
			// traves del servidor intermedio
            catch (final SocketOperationException e) {
                LOGGER.log(Level.SEVERE, "Error durante la operacion de firma por lotes", e); //$NON-NLS-1$
                msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            }

            // Si no es por sockets, se devuelve el resultado al servidor y detenemos la
            // espera activa si se encontraba vigente
            if (!ctx.bySocket()) {
            	LOGGER.info("Enviamos el resultado de la operacion de firma por lotes al servidor intermedio"); //$NON-NLS-1$
            	sendDataToServer(msg, params.getStorageServletUrl().toString(), params.getId(), requestedProtocolVersion);
            }

            return msg;
    	} catch (final ParameterException e) {
            LOGGER.log(Level.SEVERE, "Error en los parametros de firma por lotes: " + e, e); //$NON-NLS-1$
			ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final Exception e) {
            LOGGER.log(Level.SEVERE, "Error en la operacion de firma por lotes: " + e, e); //$NON-NLS-1$
			final ErrorCode errorCode = SimpleErrorCode.Internal.UNKNOWN_BATCH_ERROR;
            ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, errorCode);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, errorCode);
        }
	}

	/**
	 * Verbo {@code afirma://selectcert?...} — selección de certificado por el usuario.
	 * Soporta file_id download y conexión SSL al servidor intermedio.
	 */
	private static String handleSelectCert(final String urlString, final LaunchContext ctx) {
    	LOGGER.info("Se invoca a la aplicacion para la seleccion de un certificado"); //$NON-NLS-1$

    	ProtocolVersion requestedProtocolVersion = ctx.version();
    	try {
    		UrlParametersToSelectCert params =
    				ProtocolInvocationUriParserUtil.getParametersToSelectCert(ctx.urlParams(), !ctx.bySocket());

    		// Si se indica un identificador de fichero, es que la configuracion de la operacion
    		// se tiene que descargar desde el servidor intermedio
    		if (params.getFileId() != null) {
    			try {
    				final byte[] xmlData;
    				try {
    					xmlData = ProtocolInvocationLauncherUtil.getDataFromRetrieveServlet(params);
    				} catch (final DecryptionException e) {
    					throw new IntermediateServerErrorSendedException(
    							"Error al descifrar los datos obtenidos", e); //$NON-NLS-1$
    				} catch (final SocketTimeoutException e) {
    					throw new IntermediateServerErrorSendedException(
    							"Se excedio el tiempo de espera de la llamada al servico de recuperacion del servidor intermedio cuando se trataron de obtener los datos para la seleccion de certificado", e, //$NON-NLS-1$
    							SimpleErrorCode.Communication.RECIVING_DATA_OF_CERT_TIMEOUT);
    				} catch (final IOException e) {
    					throw new IntermediateServerErrorSendedException(
    							"Error al recuperar los datos enviados por el cliente a traves del servidor intermedio", e, //$NON-NLS-1$
    							SimpleErrorCode.Communication.RECIVING_DATA_OF_CERT_OPERATION);
    				}

    				params = ProtocolInvocationUriParser.getParametersToSelectCert(xmlData, true);
    			} catch (final IntermediateServerErrorSendedException e) {
    				LOGGER.log(Level.SEVERE, "Se obtuvo un error al descargar los datos del servidor intermedio", e); //$NON-NLS-1$
    				processIntermediateServiceError(e.getMessage(), e.getErrorCode(), params.getStorageServletUrl(), params.getId(), requestedProtocolVersion);
    				return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
    			}
    		}

    		// Si la peticion no se hizo a traves de socket/websocket, la version de protocolo se indica en la propia operacion
    		if (requestedProtocolVersion == null) {
    			requestedProtocolVersion = parseProtocolVersion(params.getMinimumProtocolVersion());
    			requestedProtocolVersion = reviewProtocolVersion(requestedProtocolVersion, ctx.javascriptVersionCode());
    		}

    		// En caso de comunicacion por servidor intermedio, solicitamos, si corresponde,
    		// que se espere activamente hasta el fin de la tarea
    		startActiveWaitingIfNeeded(params, ctx.bySocket());

    		LOGGER.info("Se inicia la operacion de seleccion de certificado. Version de protocolo: " //$NON-NLS-1$
    				+ requestedProtocolVersion);

    		String msg;
    		boolean errorConnectingServer = false;
    		try {
    			msg = ProtocolInvocationLauncherSelectCert.processSelectCert(params, requestedProtocolVersion);
    		}
    		catch (final SSLHandshakeException e) {
				LOGGER.log(Level.SEVERE, "Error al realizar una conexion segura con el servidor", e); //$NON-NLS-1$
				final ErrorCode errorCode = SimpleErrorCode.Communication.SENDING_RESULT_OPERATION;
				ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, errorCode);
				msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, errorCode);
				errorConnectingServer = true;
			}
    		catch(final AOCancelledOperationException e) {
    			LOGGER.severe("Operacion de seleccion de certificado cancelada por el usuario"); //$NON-NLS-1$
    			msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
    		}
    		// solo entra en la excepcion en el caso de que haya que devolver errores a
    		// traves del servidor intermedio
    		catch (final SocketOperationException e) {
    			LOGGER.log(Level.SEVERE, "Error durante la operacion de seleccion de certificado", e); //$NON-NLS-1$
    			msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
    		}

    		// Si no es por sockets, y si no hay errores de conexion con el servidor,
    		// se devuelve el resultado al servidor y detenemos la espera activa si se encontraba vigente
    		if (!ctx.bySocket() && !errorConnectingServer) {
    			LOGGER.info("Enviamos el resultado de la operacion de seleccion de certificado al servidor intermedio"); //$NON-NLS-1$
    			sendDataToServer(msg, params.getStorageServletUrl().toString(), params.getId(), requestedProtocolVersion);
    		}

    		return msg;
    	} catch (final ParameterException e) {
    		LOGGER.log(Level.SEVERE, "Error en los parametros de seleccion de certificados: " + e, e); //$NON-NLS-1$
    		ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
    		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
    	} catch (final Exception e) {
    		LOGGER.log(Level.SEVERE, "Error en los parametros de seleccion de certificados: " + e, e); //$NON-NLS-1$
    		final ErrorCode errorCode = SimpleErrorCode.Internal.UNKNOWN_SELECTING_CERT_ERROR;
    		ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, errorCode);
    		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, errorCode);
    	}
	}

	/**
	 * Verbo {@code afirma://save?...} — guardado de datos en el sistema de ficheros del usuario.
	 */
	private static String handleSave(final String urlString, final LaunchContext ctx) {
        LOGGER.info("Se invoca a la aplicacion para el guardado de datos"); //$NON-NLS-1$

        ProtocolVersion requestedProtocolVersion = ctx.version();
        try {
            UrlParametersToSave params =
            		ProtocolInvocationUriParserUtil.getParametersToSave(ctx.urlParams(), !ctx.bySocket());

            LOGGER.info("Cantidad de datos a guardar: " + (params.getData() == null ? 0 : params.getData().length)); //$NON-NLS-1$

			// Si se indica un identificador de fichero, es que la configuracion de la operacion
            // se tiene que descargar desde el servidor intermedio
            if (params.getFileId() != null) {
            	try {
            		final byte[] xmlData;
            		try {
            			xmlData = ProtocolInvocationLauncherUtil.getDataFromRetrieveServlet(params);
            		} catch (final DecryptionException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Error al descifrar los datos obtenidos", e); //$NON-NLS-1$
            		} catch (final SocketTimeoutException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Se excedio el tiempo de espera de la llamada al servico de recuperacion del servidor intermedio cuando se trataron de obtener los datos para el guardado de datos", e, //$NON-NLS-1$
            					SimpleErrorCode.Communication.RECIVING_DATA_OF_SAVE_TIMEOUT);
            		} catch (final IOException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Error al recuperar los datos enviados por el cliente a traves del servidor intermedio", e, //$NON-NLS-1$
            					SimpleErrorCode.Communication.RECIVING_DATA_OF_SAVE_OPERATION);
            		}

            		params = ProtocolInvocationUriParser.getParametersToSave(xmlData, true);
            	} catch (final IntermediateServerErrorSendedException e) {
            		LOGGER.log(Level.SEVERE, "Se obtuvo un error al descargar los datos del servidor intermedio", e); //$NON-NLS-1$
            		processIntermediateServiceError(e.getMessage(), e.getErrorCode(), params.getStorageServletUrl(), params.getId(), requestedProtocolVersion);
            		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            	}
            }

    		// Si la peticion no se hizo a traves de socket/websocket, la version de protocolo se indica en la propia operacion
    		if (requestedProtocolVersion == null) {
    			requestedProtocolVersion = parseProtocolVersion(params.getMinimumProtocolVersion());
    			requestedProtocolVersion = reviewProtocolVersion(requestedProtocolVersion, ctx.javascriptVersionCode());
    		}

            // En caso de comunicacion por servidor intermedio, solicitamos, si corresponde,
            // que se espere activamente hasta el fin de la tarea
            startActiveWaitingIfNeeded(params, ctx.bySocket());

            LOGGER.info("Se inicia la operacion de guardado. Version de protocolo: " + requestedProtocolVersion); //$NON-NLS-1$

            String msg;
            try {
            	msg = ProtocolInvocationLauncherSave.processSave(params, requestedProtocolVersion);
            }
            catch(final AOCancelledOperationException e) {
                LOGGER.severe("Operacion de guardado de datos cancelada por el usuario"); //$NON-NLS-1$
                msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            }
			// solo entra en la excepcion en el caso de que haya que devolver errores a
			// traves del servidor intermedio
            catch (final SocketOperationException e) {
            	LOGGER.log(Level.SEVERE, "Error en la operacion de guardado: " + e, e); //$NON-NLS-1$
            	msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            }

            // Si no es por sockets, se devuelve el resultado al servidor y detenemos la
            // espera activa si se encontraba vigente
            if (!ctx.bySocket()) {
            	LOGGER.info("Enviamos el resultado de la operacion de guardado al servidor intermedio"); //$NON-NLS-1$
            	sendDataToServer(msg, params.getStorageServletUrl().toString(), params.getId(), requestedProtocolVersion);
            }

            return msg;

		} catch (final NeedsUpdatedVersionException e) {
            LOGGER.severe("Se necesita una version mas moderna de Autofirma para procesar la peticion: " + e); //$NON-NLS-1$
			ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final ParameterLocalAccessRequestedException e) {
            LOGGER.severe("Se ha pedido un acceso a una direccion local (localhost o 127.0.0.1): " + e); //$NON-NLS-1$
			ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final ParameterException e) {
        	LOGGER.log(Level.SEVERE, "Error en los parametros de guardado", e); //$NON-NLS-1$
        	ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final Exception e) {
        	LOGGER.log(Level.SEVERE, "Error en los parametros de guardado", e); //$NON-NLS-1$
			final ErrorCode errorCode = SimpleErrorCode.Internal.UNKNOWN_SAVING_DATA_ERROR;
            ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, errorCode);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, errorCode);
        }
	}

	/**
	 * Verbo {@code afirma://signandsave?...} — firma/multifirma seguida de guardado en local.
	 */
	private static String handleSignAndSave(final String urlString, final LaunchContext ctx) {
        LOGGER.info("Se invoca a la aplicacion para la firma/multifirma y el guardado del resultado"); //$NON-NLS-1$

        ProtocolVersion requestedProtocolVersion = ctx.version();
        try {
            UrlParametersToSignAndSave params =
            		ProtocolInvocationUriParserUtil.getParametersToSignAndSave(ctx.urlParams(), !ctx.bySocket());

			LOGGER.info("Cantidad de datos a firmar y guardar: " //$NON-NLS-1$
					+ (params.getData() == null ? 0 : params.getData().length));

			// Si se indica un identificador de fichero, es que la configuracion de la operacion
            // se tiene que descargar desde el servidor intermedio
            if (params.getFileId() != null) {
            	try {
            		final byte[] xmlData;
            		try {
            			xmlData = ProtocolInvocationLauncherUtil.getDataFromRetrieveServlet(params);
            		} catch (final DecryptionException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Error al descifrar los datos obtenidos", e); //$NON-NLS-1$
            		} catch (final SocketTimeoutException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Se excedio el tiempo de espera de la llamada al servico de recuperacion del servidor intermedio cuando se trataron de obtener los datos para la firma y guardado", e, //$NON-NLS-1$
            					SimpleErrorCode.Communication.RECIVING_DATA_OF_SIGN_AND_SAVE_TIMEOUT);
            		} catch (final IOException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Error al recuperar los datos enviados por el cliente a traves del servidor intermedio", e, //$NON-NLS-1$
            					SimpleErrorCode.Communication.RECIVING_DATA_OF_SIGN_AND_SAVE_OPERATION);
            		}

            		params = ProtocolInvocationUriParser.getParametersToSignAndSave(xmlData, true);
            	} catch (final IntermediateServerErrorSendedException e) {
            		LOGGER.log(Level.SEVERE, "Se obtuvo un error al descargar los datos del servidor intermedio", e); //$NON-NLS-1$
            		processIntermediateServiceError(e.getMessage(), e.getErrorCode(), params.getStorageServletUrl(), params.getId(), requestedProtocolVersion);
            		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            	}
            }

    		// Si la peticion no se hizo a traves de socket/websocket, la version de protocolo se indica en la propia operacion
    		if (requestedProtocolVersion == null) {
    			requestedProtocolVersion = parseProtocolVersion(params.getMinimumProtocolVersion());
    			requestedProtocolVersion = reviewProtocolVersion(requestedProtocolVersion, ctx.javascriptVersionCode());
    		}

            // En caso de comunicacion por servidor intermedio, solicitamos, si corresponde,
            // que se espere activamente hasta el fin de la tarea
            startActiveWaitingIfNeeded(params, ctx.bySocket());

			LOGGER.info("Se inicia la operacion de firma y guardado. Version de protocolo: " //$NON-NLS-1$
					+ requestedProtocolVersion);

			String msg;
            try {
            	final StringBuilder dataToSend =  ProtocolInvocationLauncherSignAndSave.processSign(params, requestedProtocolVersion);
            	msg = dataToSend.toString();
            }
            catch(final AOCancelledOperationException e) {
                LOGGER.severe("Operacion de firma y guardado cancelada por el usuario"); //$NON-NLS-1$
                msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            }
			// solo entra en la excepcion en el caso de que haya que devolver errores a
			// traves del servidor intermedio
            catch(final SocketOperationException e) {
                LOGGER.severe("Error durante la operacion de firma y guardado: " + e); //$NON-NLS-1$
                msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            }

            // Si no es por sockets, se devuelve el resultado al servidor y detenemos la
            // espera activa si se encontraba vigente
            if (!ctx.bySocket()) {
            	LOGGER.info("Enviamos el resultado de la operacion de firma y guardado al servidor intermedio"); //$NON-NLS-1$
            	sendDataToServer(msg, params.getStorageServletUrl().toString(), params.getId(), requestedProtocolVersion);
            }

            return msg;
		} catch (final NeedsUpdatedVersionException e) {
            LOGGER.severe("Se necesita una version mas moderna de Autofirma para procesar la peticion: " + e); //$NON-NLS-1$
			ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final ParameterLocalAccessRequestedException e) {
            LOGGER.severe("Se ha pedido un acceso a una direccion local (localhost o 127.0.0.1): " + e); //$NON-NLS-1$
            ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final ParameterException e) {
            LOGGER.log(Level.SEVERE, "Error en los parametros de firma y guardado: " + e, e); //$NON-NLS-1$
            ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final Exception e) {
            LOGGER.log(Level.SEVERE, "Error en los parametros de firma y guardado: " + e, e); //$NON-NLS-1$
            final ErrorCode errorCode = ErrorCode.Internal.UNKNOWN_SIGNING_ERROR;
            ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, errorCode);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, errorCode);
        }
	}

	/**
	 * Verbo {@code afirma://sign?...}, {@code afirma://cosign?...} y
	 * {@code afirma://countersign?...} — operaciones de firma sin guardado.
	 * El procesador {@link ProtocolInvocationLauncherSign} distingue internamente
	 * el tipo de operación según los parámetros parseados.
	 */
	private static String handleSign(final String urlString, final LaunchContext ctx) {
        LOGGER.info("Se invoca a la aplicacion para realizar una operacion de firma/multifirma"); //$NON-NLS-1$

        ProtocolVersion requestedProtocolVersion = ctx.version();
        try {
            UrlParametersToSign params =
            		ProtocolInvocationUriParserUtil.getParametersToSign(ctx.urlParams(), !ctx.bySocket());

			// Si se indica un identificador de fichero, es que la configuracion de la operacion
            // se tiene que descargar desde el servidor intermedio
            if (params.getFileId() != null) {
            	try {
            		LOGGER.info("Se descargan los datos del servidor intermedio"); //$NON-NLS-1$

            		final byte[] xmlData;
            		try {
            			xmlData = ProtocolInvocationLauncherUtil.getDataFromRetrieveServlet(params);
            		} catch (final DecryptionException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Error al descifrar los datos obtenidos", e); //$NON-NLS-1$
            		} catch (final SocketTimeoutException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Se excedio el tiempo de espera de la llamada al servico de recuperacion del servidor intermedio cuando se trataron de obtener los datos para la firma", e, //$NON-NLS-1$
            					SimpleErrorCode.Communication.RECIVING_DATA_OF_SIGN_TIMEOUT);
            		} catch (final IOException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Error al recuperar los datos enviados por el cliente a traves del servidor intermedio", e, //$NON-NLS-1$
            					SimpleErrorCode.Communication.RECIVING_DATA_OF_SIGN_OPERATION);
            		}

            		LOGGER.info("Fin de la descarga de los datos. Se carga la configuracion de firma de la peticion"); //$NON-NLS-1$

            		params = ProtocolInvocationUriParser.getParametersToSign(xmlData, true);
            	} catch (final IntermediateServerErrorSendedException e) {
            		LOGGER.log(Level.SEVERE, "Se obtuvo un error al descargar los datos del servidor intermedio", e); //$NON-NLS-1$
            		processIntermediateServiceError(e.getMessage(), e.getErrorCode(), params.getStorageServletUrl(), params.getId(), requestedProtocolVersion);
            		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            	}
            }

    		// Si la peticion no se hizo a traves de socket/websocket, la version de protocolo se indica en la propia operacion
    		if (requestedProtocolVersion == null) {
    			requestedProtocolVersion = parseProtocolVersion(params.getMinimumProtocolVersion());
    			requestedProtocolVersion = reviewProtocolVersion(requestedProtocolVersion, ctx.javascriptVersionCode());
    		}

            // En caso de comunicacion por servidor intermedio, solicitamos, si corresponde,
            // que se espere activamente hasta el fin de la tarea
            startActiveWaitingIfNeeded(params, ctx.bySocket());

            LOGGER.info("Se inicia la operacion de firma. Version de protocolo: " + requestedProtocolVersion); //$NON-NLS-1$

            String msg;
            try {
            	final StringBuilder dataToSend = ProtocolInvocationLauncherSign.processSign(params, requestedProtocolVersion, null);
            	msg = dataToSend.toString();
            }
            catch(final AOCancelledOperationException e) {
                LOGGER.severe("Operacion de firma cancelada por el usuario"); //$NON-NLS-1$
                msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            }
			// solo entra en la excepcion en el caso de que haya que devolver errores a
			// traves del servidor intermedio
            catch(final SocketOperationException e) {
                LOGGER.severe("Error durante la operacion de firma: " + e); //$NON-NLS-1$
                msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            }

            // Si no es por sockets, se devuelve el resultado al servidor y detenemos la
            // espera activa si se encontraba vigente
            if (!ctx.bySocket()) {
            	LOGGER.info("Enviamos el resultado de la operacion de firma al servidor intermedio"); //$NON-NLS-1$
            	sendDataToServer(msg, params.getStorageServletUrl().toString(), params.getId(), requestedProtocolVersion);
            }

            return msg;
        } catch (final NeedsUpdatedVersionException e) {
            LOGGER.severe("Se necesita una version mas moderna de Autofirma para procesar la peticion: " + e); //$NON-NLS-1$
			ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final ParameterLocalAccessRequestedException e) {
            LOGGER.severe("Se ha pedido un acceso a una direccion local (localhost o 127.0.0.1): " + e); //$NON-NLS-1$
            ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final ParameterException e) {
        	LOGGER.log(Level.SEVERE, "Error en los parametros de firma", e); //$NON-NLS-1$
        	ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final Exception e) {
        	LOGGER.log(Level.SEVERE, "Error en los parametros de firma", e); //$NON-NLS-1$
        	final ErrorCode errorCode = ErrorCode.Internal.UNKNOWN_SIGNING_ERROR;
            ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, errorCode);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, errorCode);
        }
	}

	/**
	 * Verbo {@code afirma://load?...} — carga de uno o varios ficheros desde
	 * el servidor intermedio. Soporta file_id download para configuración remota.
	 */
	private static String handleLoad(final String urlString, final LaunchContext ctx) {
        LOGGER.info("Se invoca a la aplicacion para realizar una operacion de carga de uno o varios ficheros"); //$NON-NLS-1$

        ProtocolVersion requestedProtocolVersion = ctx.version();
        try {
            UrlParametersToLoad params =
            		ProtocolInvocationUriParserUtil.getParametersToLoad(ctx.urlParams());

			// Si se indica un identificador de fichero, es que la configuracion de la
			// operacion se tiene que descargar desde el servidor intermedio
            if (params.getFileId() != null) {
            	try {
            		final byte[] xmlData;
            		try {
            			xmlData = ProtocolInvocationLauncherUtil.getDataFromRetrieveServlet(params);
            		} catch (final DecryptionException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Error al descifrar los datos obtenidos", e); //$NON-NLS-1$
            		} catch (final SocketTimeoutException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Se excedio el tiempo de espera de la llamada al servico de recuperacion del servidor intermedio cuando se trataron de obtener los datos para la carga de fichero", e, //$NON-NLS-1$
            					SimpleErrorCode.Communication.RECIVING_DATA_OF_LOAD_TIMEOUT);
            		} catch (final IOException e) {
            			throw new IntermediateServerErrorSendedException(
            					"Error al recuperar los datos enviados por el cliente a traves del servidor intermedio", e, //$NON-NLS-1$
            					SimpleErrorCode.Communication.RECIVING_DATA_OF_LOAD_OPERATION);
            		}

            		params = ProtocolInvocationUriParser.getParametersToLoad(xmlData);
            	} catch (final IntermediateServerErrorSendedException e) {
            		LOGGER.log(Level.SEVERE, "Se obtuvo un error al descargar los datos del servidor intermedio", e); //$NON-NLS-1$
            		processIntermediateServiceError(e.getMessage(), e.getErrorCode(), params.getStorageServletUrl(), params.getId(), requestedProtocolVersion);
            		return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            	}
            }

    		// Si la peticion no se hizo a traves de socket/websocket, la version de protocolo se indica en la propia operacion
    		if (requestedProtocolVersion == null) {
    			requestedProtocolVersion = parseProtocolVersion(params.getMinimumProtocolVersion());
    			requestedProtocolVersion = reviewProtocolVersion(requestedProtocolVersion, ctx.javascriptVersionCode());
    		}

            // En caso de comunicacion por servidor intermedio, solicitamos, si corresponde,
            // que se espere activamente hasta el fin de la tarea
            startActiveWaitingIfNeeded(params, ctx.bySocket());

            LOGGER.info("Se inicia la operacion de carga. Version de protocolo: " + requestedProtocolVersion); //$NON-NLS-1$

            String msg;
            try {
                msg = ProtocolInvocationLauncherLoad.processLoad(params, requestedProtocolVersion);
            }
            catch(final AOCancelledOperationException e) {
                LOGGER.severe("Operacion de carga de datos cancelada por el usuario"); //$NON-NLS-1$
                msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            }
			// solo entra en la excepcion en el caso de que haya que devolver errores a
			// traves del servidor intermedio
            catch(final SocketOperationException e) {
                LOGGER.severe("Error durante la operacion de carga de fichero: " + e); //$NON-NLS-1$
                msg = ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
            }

            // Si no es por sockets, se devuelve el resultado al servidor y detenemos la
            // espera activa si se encontraba vigente
            if (!ctx.bySocket()) {
            	LOGGER.info("Enviamos el resultado de la operacion de carga de fichero al servidor intermedio"); //$NON-NLS-1$
            	sendDataToServer(msg, params.getStorageServletUrl().toString(), params.getId(), requestedProtocolVersion);
            }

            return msg;
		} catch (final NeedsUpdatedVersionException e) {
            LOGGER.severe("Se necesita una version mas moderna de Autofirma para procesar la peticion: " + e); //$NON-NLS-1$
			ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final ParameterLocalAccessRequestedException e) {
            LOGGER.severe("Se ha pedido un acceso a una direccion local (localhost o 127.0.0.1): " + e); //$NON-NLS-1$
            ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final ParameterException e) {
            LOGGER.severe("Error en los parametros de carga: " + e); //$NON-NLS-1$
			ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, e);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, e.getErrorCode());
		} catch (final Exception e) {
            LOGGER.severe("Error desconocido en la operacion de carga: " + e); //$NON-NLS-1$
            final ErrorCode errorCode = SimpleErrorCode.Internal.UNKNOWN_LOADING_DATA_ERROR;
            ProtocolInvocationLauncherErrorManager.showError(requestedProtocolVersion, errorCode);
			return ProtocolInvocationLauncherErrorManager.getErrorMessage(requestedProtocolVersion, errorCode);
        }
	}
}
