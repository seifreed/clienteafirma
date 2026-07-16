/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.xades;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.core.misc.LoggerUtil;
import es.gob.afirma.core.misc.http.SSLErrorProcessor;
import es.gob.afirma.core.misc.http.UrlHttpManager;
import es.gob.afirma.core.misc.http.UrlHttpManagerFactory;
import es.gob.afirma.core.misc.http.UrlHttpMethod;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.signers.xml.XMLErrorCode;

/**
 * Resolutor de referencias externas para firmas XAdES.
 *
 * <p>Encapsula los tres caminos por los que una firma XAdES localiza datos
 * fuera del XML que se firma:</p>
 *
 * <ul>
 *   <li>{@link #loadExternalReferenceData(String, byte[], boolean, String)}:
 *       construye un {@link ExternalReferenceData} a partir de datos o huella
 *       precalculada (si los datos son los datos en sí, calcula la huella
 *       internamente).</li>
 *   <li>{@link #loadManifestReferencesData(byte[], String, Properties)}:
 *       lee las referencias <code>uri{N}</code>/<code>md{N}</code> de
 *       {@code extraParams} para construir el listado de referencias del
 *       Manifest.</li>
 *   <li>{@link #createExternalReferenceFromUri(String, XMLSignatureFactory,
 *       DigestMethod, String, Properties)}: dereferencia URIs locales
 *       ({@code file://}) o remotas ({@code http(s)://}) y crea el nodo
 *       {@code &lt;Reference&gt;} con la huella obtenida.</li>
 * </ul>
 *
 * <p>Extra&iacute;do en Fase E.2 del refactor Clean Code de
 * {@code XAdESSigner.sign()} (1114 LOC, 28 catch gen&eacute;ricos). Antes
 * estos m&eacute;todos eran {@code private static} dentro del propio
 * {@code XAdESSigner}.</p>
 */
final class XAdESReferenceResolver {

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	private static final String FILE_PROTOCOL_PREFIX = "file://"; //$NON-NLS-1$
	private static final String HTTP_PROTOCOL_PREFIX = "http://"; //$NON-NLS-1$
	private static final String HTTPS_PROTOCOL_PREFIX = "https://"; //$NON-NLS-1$

	private XAdESReferenceResolver() {
		// Utilidad estática.
	}

	/**
	 * Construye un {@link ExternalReferenceData} para una referencia externa.
	 *
	 * @param uri URI de los datos referenciados.
	 * @param data Datos o huella precalculada. Si es {@code null}, la
	 *   referencia se construye sin huella.
	 * @param isMd {@code true} si {@code data} ya es la huella; {@code false}
	 *   si son los datos y hay que calcular la huella.
	 * @param mdAlgorithm Nombre del algoritmo de huella (cuando {@code isMd}
	 *   es {@code false}).
	 * @return Referencia externa con o sin huella.
	 * @throws NoSuchAlgorithmException Si el algoritmo de huella no está
	 *   disponible en el JRE.
	 */
	static ExternalReferenceData loadExternalReferenceData(
			final String uri,
			final byte[] data,
			final boolean isMd,
			final String mdAlgorithm) throws NoSuchAlgorithmException {

		if (data == null) {
			return new ExternalReferenceData(uri, null);
		}
		if (isMd) {
			return new ExternalReferenceData(uri, data);
		}
		return new ExternalReferenceData(
				uri,
				MessageDigest.getInstance(mdAlgorithm).digest(data));
	}

	/**
	 * Carga el listado de referencias del Manifest leyendo los
	 * par&aacute;metros <code>uri{N}</code> y <code>md{N}</code> de
	 * {@code extraParams}.
	 *
	 * <p>Si el caller proporciona el par&aacute;metro {@code uri} simple +
	 * la huella v&iacute;a {@code digest}, se asume modo retrocompatible
	 * (una sola referencia desde el dato/huella original).</p>
	 *
	 * @param digest Huella precalculada para el modo retrocompatible
	 *   ({@code uri} simple). Cuando se usan {@code uri{N}}/{@code md{N}}
	 *   este par&aacute;metro se ignora.
	 * @param referenceId Identificador a asignar a la referencia
	 *   retrocompatible.
	 * @param extraParams Configuraci&oacute;n de la operaci&oacute;n.
	 * @return Listado de referencias para el Manifest. Nunca vac&iacute;o:
	 *   si no hay ninguna referencia v&aacute;lida lanza {@link AOException}.
	 * @throws AOException Si falta una huella o el base64 es inv&aacute;lido.
	 */
	static List<ExternalReferenceData> loadManifestReferencesData(
			final byte[] digest,
			final String referenceId,
			final Properties extraParams) throws AOException {

		final List<ExternalReferenceData> refsList = new ArrayList<>();

		// Modo retrocompatible: parámetro `uri` simple + huella en `digest`.
		if (extraParams.containsKey(XAdESExtraParams.URI)) {
			if (digest == null) {
				throw new AOException(
					"No se ha proporcionado en el parametro de datos la huella correspondiente a los datos referenciados por la URI", //$NON-NLS-1$
					XAdESErrorCode.Request.REFERENCE_HASH_NOT_FOUND);
			}
			final ExternalReferenceData refData = new ExternalReferenceData(
					extraParams.getProperty(XAdESExtraParams.URI), digest);
			refData.setId(referenceId);
			refData.setMimeType(extraParams.getProperty(XAdESExtraParams.CONTENT_MIME_TYPE));
			refData.setOid(extraParams.getProperty(XAdESExtraParams.CONTENT_TYPE_OID));
			refData.setEncoding(extraParams.getProperty(XAdESExtraParams.CONTENT_ENCODING));
			refsList.add(refData);
			return refsList;
		}

		// Modo Manifest con N referencias indexadas (uri1/md1, uri2/md2, ...).
		int i = 1;
		while (extraParams.containsKey(XAdESExtraParams.URI_PREFIX + i)) {
			if (!extraParams.containsKey(XAdESExtraParams.MD_PREFIX + i)) {
				throw new AOException(
					String.format("No se ha indicado la huella de la referencia %d del manifest", //$NON-NLS-1$
							Integer.valueOf(i)),
					XAdESErrorCode.Request.REFERENCE_HASH_NOT_FOUND);
			}
			final byte[] md;
			try {
				md = Base64.decode(extraParams.getProperty(XAdESExtraParams.MD_PREFIX + i));
			}
			catch (final Exception e) {
				LOGGER.log(Level.WARNING,
						"Se ha indicado un base 64 no valido como huella de la referencia " + i, e); //$NON-NLS-1$
				throw new AOException(
					String.format("Se ha indicado un base 64 no valido como huella de la referencia %d del manifest", //$NON-NLS-1$
							Integer.valueOf(i)),
					e, XAdESErrorCode.Request.INVALID_REFERENCE_HASH);
			}
			final ExternalReferenceData refData = new ExternalReferenceData(
					extraParams.getProperty(XAdESExtraParams.URI_PREFIX + i), md);
			refData.setId("Reference-" + UUID.randomUUID()); //$NON-NLS-1$
			refData.setMimeType(extraParams.getProperty(XAdESExtraParams.CONTENT_MIME_TYPE_PREFIX + i));
			refData.setOid(extraParams.getProperty(XAdESExtraParams.CONTENT_TYPE_OID_PREFIX + i));
			refData.setEncoding(extraParams.getProperty(XAdESExtraParams.CONTENT_ENCODING_PREFIX + i));
			refsList.add(refData);
			i++;
		}

		if (refsList.isEmpty()) {
			throw new AOException(
					"No se han proporcionado las referencias y huellas de los datos a firmar", //$NON-NLS-1$
					XAdESErrorCode.Request.MANIFEST_REFERENCES_NOT_FOUND);
		}

		return refsList;
	}

	/**
	 * Crea un nodo {@code Reference} XML-DSig dereferenciando la URI a los
	 * datos externos. Acepta tres familias de URI:
	 *
	 * <ul>
	 *   <li>{@code file://}: lee el fichero local y calcula la huella.</li>
	 *   <li>{@code http://} / {@code https://}: descarga el recurso v&iacute;a
	 *       {@link UrlHttpManager} y calcula la huella.</li>
	 *   <li>Resto (ej. URIs relativas): crea la referencia sin pre-calcular,
	 *       delegando la dereferencia al motor JSR-105.</li>
	 * </ul>
	 *
	 * @param uri URI a los datos externos.
	 * @param fac Factor&iacute;a JSR-105 para crear la referencia.
	 * @param digestMethod Algoritmo de huella a usar.
	 * @param referenceId Identificador para el atributo {@code Id}.
	 * @param extraParams Configuraci&oacute;n (usado para SSL error processing).
	 * @return Referencia JSR-105 lista para a&ntilde;adir al SignedInfo.
	 * @throws AOException Si la URI no se puede dereferenciar o el algoritmo
	 *   de huella no est&aacute; disponible.
	 */
	static Reference createExternalReferenceFromUri(
			final String uri,
			final XMLSignatureFactory fac,
			final DigestMethod digestMethod,
			final String referenceId,
			final Properties extraParams) throws AOException {

		if (FILE_PROTOCOL_PREFIX.equalsIgnoreCase(uri.substring(0, FILE_PROTOCOL_PREFIX.length()))) {
			return createReferenceFromLocalFile(uri, fac, digestMethod, referenceId);
		}
		if (HTTP_PROTOCOL_PREFIX.equalsIgnoreCase(uri.substring(0, HTTP_PROTOCOL_PREFIX.length()))
				|| HTTPS_PROTOCOL_PREFIX.equalsIgnoreCase(uri.substring(0, HTTPS_PROTOCOL_PREFIX.length()))) {
			return createReferenceFromHttpUri(uri, fac, digestMethod, referenceId, extraParams);
		}
		// Cualquier otra URI: delegamos en el motor JSR-105.
		try {
			return fac.newReference(uri, digestMethod, null, null, referenceId);
		}
		catch (final Exception e) {
			throw new AOException(
					"No se ha podido crear la referencia Externally Detached, probablemente por no obtenerse el metodo de digest: " + e, //$NON-NLS-1$
					e, XMLErrorCode.Internal.UNKWNON_XML_SIGNING_ERROR);
		}
	}

	private static Reference createReferenceFromLocalFile(
			final String uri,
			final XMLSignatureFactory fac,
			final DigestMethod digestMethod,
			final String referenceId) throws AOException {

		try (final InputStream lfis = AOUtil.loadFile(AOUtil.createURI(uri))) {
			return fac.newReference(
					uri,
					digestMethod,
					null,
					null, // Las referencias externas no tienen tipo
					referenceId,
					MessageDigest.getInstance(
							AOSignConstants.getDigestAlgorithmName(digestMethod.getAlgorithm()))
							.digest(AOUtil.getDataFromInputStream(lfis)));
		}
		catch (final IOException e) {
			throw new AOException(
					"Error al leer el documento local al que referencia la firma: " + uri, //$NON-NLS-1$
					e, ErrorCode.Internal.LOADING_LOCAL_FILE_ERROR);
		}
		catch (final NoSuchAlgorithmException e) {
			throw new AOException(
					"Error al leer el documento local al que referencia la firma: " + uri, //$NON-NLS-1$
					e, XMLErrorCode.Request.INVALID_REFERENCES_HASH_ALGORITHM_URI);
		}
		catch (final URISyntaxException e) {
			throw new AOException(
					"El formato de la URI a los datos de firma no es valido: " + uri, //$NON-NLS-1$
					e, XAdESErrorCode.Request.INVALID_DATA_REFERENCE_URI);
		}
		catch (final Exception e) {
			throw new AOException(
					"No se ha podido crear la referencia XML a partir de la URI local " + uri, //$NON-NLS-1$
					e, XMLErrorCode.Internal.UNKWNON_XML_SIGNING_ERROR);
		}
	}

	private static Reference createReferenceFromHttpUri(
			final String uri,
			final XMLSignatureFactory fac,
			final DigestMethod digestMethod,
			final String referenceId,
			final Properties extraParams) throws AOException {

		final UrlHttpManager httpManager = UrlHttpManagerFactory.getManager();
		final SSLErrorProcessor errorProcessor = new SSLErrorProcessor(extraParams);
		final byte[] data;
		try {
			data = httpManager.readUrl(uri, UrlHttpMethod.GET, errorProcessor);
		}
		catch (final IOException e) {
			if (errorProcessor.isCancelled()) {
				LOGGER.info(
						"El usuario no permite la importacion del certificado SSL de confianza de un recurso externo en: " //$NON-NLS-1$
								+ LoggerUtil.getTrimStr(uri));
			}
			throw new AOException(
					"Error en la recuperacion de un recurso externo: " + e, //$NON-NLS-1$
					e, XMLErrorCode.Communication.DERREFERENCING_DATA_ERROR);
		}

		final String digestMethodAlgorithm = AOSignConstants.getDigestAlgorithmName(digestMethod.getAlgorithm());
		try {
			final byte[] md = MessageDigest.getInstance(digestMethodAlgorithm).digest(data);
			return fac.newReference(
					uri,
					digestMethod,
					null,
					null, // Las referencias externas no tienen tipo
					referenceId,
					md);
		}
		catch (final NoSuchAlgorithmException e) {
			throw new AOException(
					"No se ha podido obtener un generador de huellas digitales para el algoritmo " + digestMethodAlgorithm, //$NON-NLS-1$
					e, XMLErrorCode.Request.INVALID_REFERENCES_HASH_ALGORITHM_URI);
		}
		catch (final Exception e) {
			throw new AOException(
					"No se ha podido crear la referencia XML a partir de la URI local " + uri, //$NON-NLS-1$
					e, XMLErrorCode.Internal.UNKWNON_XML_SIGNING_ERROR);
		}
	}
}
