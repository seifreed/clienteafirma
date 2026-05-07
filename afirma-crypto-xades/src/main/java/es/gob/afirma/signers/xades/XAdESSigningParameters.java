/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.xades;

import java.net.URI;
import java.util.Locale;
import java.util.Properties;
import java.util.logging.Logger;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.signers.xml.XMLConstants;
import es.gob.afirma.signers.xml.XMLErrorCode;

/**
 * Conjunto inmutable de par&aacute;metros para una operaci&oacute;n XAdES.
 *
 * <p>Lee y valida la configuraci&oacute;n proporcionada via {@code extraParams}
 * y aplica los invariantes que antes viv&iacute;an dispersos en
 * {@code XAdESSigner.sign()} y {@code checkParams()}:</p>
 *
 * <ul>
 *   <li>Algoritmo MD2/MD5 prohibido (Decisi&oacute;n 130/2011 CE).</li>
 *   <li>Algoritmo de firma debe estar en {@link XMLConstants#SIGN_ALGOS_URI}.</li>
 *   <li>Para perfil baseline, namespace XAdES no compatible se descarta con
 *       traza de aviso.</li>
 *   <li>{@code useManifest=true} fuerza formato Externally Detached.</li>
 *   <li>{@code encoding} debe ser una URI v&aacute;lida (o el alias
 *       {@code "base64"} que se normaliza al URI oficial).</li>
 * </ul>
 *
 * <p>Esta clase es el primer colaborador extra&iacute;do en Fase E.1 del
 * refactor Clean Code de {@code XAdESSigner.sign()} (1114 LOC en un solo
 * m&eacute;todo).</p>
 */
final class XAdESSigningParameters {

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	final String algorithm;
	final String algoUri;
	final String format;
	final String mode;
	final boolean useManifest;
	final boolean onlySignningCert;
	final boolean avoidXpathExtraTransformsOnEnveloped;
	final String envelopedNodeXPath;
	final String nodeToSign;
	final boolean avoidEnvelopedTransformWhenSigningNode;
	final String digestMethodAlgorithm;
	final String externalReferencesHashAlgorithm;
	final String canonicalizationAlgorithm;
	final String xadesNamespace;
	final String signedPropertiesTypeUrl;
	final boolean ignoreStyleSheets;
	final boolean avoidBase64Transforms;
	final boolean headless;
	final boolean addKeyInfoKeyValue;
	final boolean addKeyInfoKeyName;
	final boolean addKeyInfoX509IssuerSerial;
	final boolean facturaeSign;
	final String outputXmlEncoding;
	final String mimeType;
	final String oid;
	final String encoding;
	final boolean validatePkcs1;
	final String profile;
	final boolean keepKeyInfoUnsigned;
	final URI dataUri;

	private XAdESSigningParameters(final Builder b) {
		this.algorithm = b.algorithm;
		this.algoUri = b.algoUri;
		this.format = b.format;
		this.mode = b.mode;
		this.useManifest = b.useManifest;
		this.onlySignningCert = b.onlySignningCert;
		this.avoidXpathExtraTransformsOnEnveloped = b.avoidXpathExtraTransformsOnEnveloped;
		this.envelopedNodeXPath = b.envelopedNodeXPath;
		this.nodeToSign = b.nodeToSign;
		this.avoidEnvelopedTransformWhenSigningNode = b.avoidEnvelopedTransformWhenSigningNode;
		this.digestMethodAlgorithm = b.digestMethodAlgorithm;
		this.externalReferencesHashAlgorithm = b.externalReferencesHashAlgorithm;
		this.canonicalizationAlgorithm = b.canonicalizationAlgorithm;
		this.xadesNamespace = b.xadesNamespace;
		this.signedPropertiesTypeUrl = b.signedPropertiesTypeUrl;
		this.ignoreStyleSheets = b.ignoreStyleSheets;
		this.avoidBase64Transforms = b.avoidBase64Transforms;
		this.headless = b.headless;
		this.addKeyInfoKeyValue = b.addKeyInfoKeyValue;
		this.addKeyInfoKeyName = b.addKeyInfoKeyName;
		this.addKeyInfoX509IssuerSerial = b.addKeyInfoX509IssuerSerial;
		this.facturaeSign = b.facturaeSign;
		this.outputXmlEncoding = b.outputXmlEncoding;
		this.mimeType = b.mimeType;
		this.oid = b.oid;
		this.encoding = b.encoding;
		this.validatePkcs1 = b.validatePkcs1;
		this.profile = b.profile;
		this.keepKeyInfoUnsigned = b.keepKeyInfoUnsigned;
		this.dataUri = b.dataUri;
	}

	/**
	 * Lee y valida los par&aacute;metros desde {@code extraParams}.
	 *
	 * <p>Aplica los invariantes documentados en la JavaDoc de la clase y
	 * lanza {@link AOException} (algoritmo no soportado, encoding inv&aacute;lido)
	 * o {@link IllegalArgumentException} (MD2/MD5).</p>
	 *
	 * @param signAlgorithm Algoritmo de firma (puede ser {@code null}: se usa
	 *   {@link AOSignConstants#DEFAULT_SIGN_ALGO}).
	 * @param xParams Par&aacute;metros adicionales (puede ser {@code null}).
	 * @return Configuraci&oacute;n inmutable lista para alimentar la firma.
	 * @throws AOException Si el algoritmo no est&aacute; soportado o el
	 *   {@code encoding} no es una URI v&aacute;lida.
	 */
	static XAdESSigningParameters parse(final String signAlgorithm, final Properties xParams) throws AOException {

		final String algorithm = signAlgorithm != null ? signAlgorithm : AOSignConstants.DEFAULT_SIGN_ALGO;
		final Properties extraParams = xParams != null ? xParams : new Properties();

		// Decisión 130/2011 CE: MD2 y MD5 prohibidos en firmas XAdES.
		if (algorithm.toUpperCase(Locale.US).startsWith("MD")) { //$NON-NLS-1$
			throw new IllegalArgumentException(
					"XAdES no permite huellas digitales MD2 o MD5 (Decision 130/2011 CE)"); //$NON-NLS-1$
		}

		final String algoUri = XMLConstants.SIGN_ALGOS_URI.get(algorithm);
		if (algoUri == null) {
			throw new AOException(
					"Los formatos de firma XML no soportan el algoritmo de firma " + algorithm, //$NON-NLS-1$
					ErrorCode.Request.UNSUPPORTED_SIGNATURE_ALGORITHM);
		}

		final Builder b = new Builder();
		b.algorithm = algorithm;
		b.algoUri = algoUri;
		b.mode = extraParams.getProperty(XAdESExtraParams.MODE);

		b.avoidXpathExtraTransformsOnEnveloped = bool(extraParams,
				XAdESExtraParams.AVOID_XPATH_EXTRA_TRANSFORMS_ON_ENVELOPED, false);
		b.onlySignningCert = bool(extraParams,
				XAdESExtraParams.INCLUDE_ONLY_SIGNNING_CERTIFICATE, false);
		b.useManifest = bool(extraParams, XAdESExtraParams.USE_MANIFEST, false);
		b.envelopedNodeXPath = extraParams.getProperty(
				XAdESExtraParams.INSERT_ENVELOPED_SIGNATURE_ON_NODE_BY_XPATH);
		b.nodeToSign = extraParams.getProperty(XAdESExtraParams.NODE_TOSIGN);
		b.avoidEnvelopedTransformWhenSigningNode = b.nodeToSign != null
				&& bool(extraParams, XAdESExtraParams.AVOID_ENVELOPED_TRANSFORM_WHEN_SIGNING_NODE, false);

		String format = extraParams.getProperty(XAdESExtraParams.FORMAT,
				AOSignConstants.SIGN_FORMAT_XADES_ENVELOPING);
		// Las firmas manifest siempre se realizaran sobre firmas Externally Detached.
		if (b.useManifest) {
			format = AOSignConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED;
		}
		b.format = format;

		b.digestMethodAlgorithm = extraParams.getProperty(
				XAdESExtraParams.REFERENCES_DIGEST_METHOD, XAdESConstants.DEFAULT_DIGEST_METHOD);
		b.externalReferencesHashAlgorithm = extraParams.getProperty(
				XAdESExtraParams.PRECALCULATED_HASH_ALGORITHM, b.digestMethodAlgorithm);

		String canon = extraParams.getProperty(
				XAdESExtraParams.CANONICALIZATION_ALGORITHM, CanonicalizationMethod.INCLUSIVE);
		if ("none".equalsIgnoreCase(canon)) { //$NON-NLS-1$
			canon = null;
		}
		b.canonicalizationAlgorithm = canon;

		b.profile = extraParams.getProperty(
				XAdESExtraParams.PROFILE, AOSignConstants.DEFAULT_SIGN_PROFILE);

		// Aviso baseline + SHA1 antes de descartar namespaces incompatibles.
		if (AOSignConstants.SIGN_PROFILE_BASELINE.equalsIgnoreCase(b.profile)) {
			if (AOSignConstants.isSHA1SignatureAlgorithm(algorithm)) {
				LOGGER.warning("El algoritmo '" + algorithm //$NON-NLS-1$
						+ "' no esta recomendado para su uso en las firmas baseline"); //$NON-NLS-1$
			}
			if (XMLConstants.URL_SHA1.equals(b.digestMethodAlgorithm)) {
				LOGGER.warning(
						"El algoritmo SHA1 no esta recomendado para generar referencias en las firmas baseline"); //$NON-NLS-1$
			}
			// Si se pide baseline con un namespace no compatible, descartamos
			// el namespace y la URL del tipo de signedProperties.
			if (extraParams.containsKey(XAdESExtraParams.XADES_NAMESPACE)
					&& !XAdESUtil.isBaselineCompatible(extraParams.getProperty(XAdESExtraParams.XADES_NAMESPACE))) {
				LOGGER.warning(
						"Se ha indicado realizar una firma baseline con un espacio de nombres que no lo soporta. " //$NON-NLS-1$
								+ "Se ignorara el espacio de nombres indicado"); //$NON-NLS-1$
				extraParams.remove(XAdESExtraParams.XADES_NAMESPACE);
				extraParams.remove(XAdESExtraParams.SIGNED_PROPERTIES_TYPE_URL);
			}
		}

		b.xadesNamespace = extraParams.getProperty(
				XAdESExtraParams.XADES_NAMESPACE, XAdESConstants.DEFAULT_NAMESPACE_XADES);
		b.signedPropertiesTypeUrl = extraParams.getProperty(
				XAdESExtraParams.SIGNED_PROPERTIES_TYPE_URL,
				XAdESConstants.REFERENCE_TYPE_SIGNED_PROPERTIES);

		b.ignoreStyleSheets = bool(extraParams, XAdESExtraParams.IGNORE_STYLE_SHEETS, false);
		b.avoidBase64Transforms = bool(extraParams, XAdESExtraParams.AVOID_BASE64_TRANSFORMS, false);
		b.headless = bool(extraParams, XAdESExtraParams.HEADLESS, true);
		b.addKeyInfoKeyValue = bool(extraParams, XAdESExtraParams.ADD_KEY_INFO_KEY_VALUE, true);
		b.addKeyInfoKeyName = bool(extraParams, XAdESExtraParams.ADD_KEY_INFO_KEY_NAME, false);
		b.addKeyInfoX509IssuerSerial = bool(extraParams,
				XAdESExtraParams.ADD_KEY_INFO_X509_ISSUER_SERIAL, false);
		b.facturaeSign = bool(extraParams, XAdESExtraParams.FACTURAE_SIGN, false);
		b.outputXmlEncoding = extraParams.getProperty(XAdESExtraParams.OUTPUT_XML_ENCODING);

		b.mimeType = extraParams.getProperty(XAdESExtraParams.CONTENT_MIME_TYPE);
		b.oid = extraParams.getProperty(XAdESExtraParams.CONTENT_TYPE_OID);

		String encoding = extraParams.getProperty(XAdESExtraParams.CONTENT_ENCODING);
		if ("base64".equalsIgnoreCase(encoding)) { //$NON-NLS-1$
			encoding = XMLConstants.BASE64_ENCODING;
		}
		if (encoding != null && !encoding.isEmpty()) {
			try {
				new URI(encoding);
			}
			catch (final Exception e) {
				throw new AOException(
						"La codificacion indicada en 'encoding' debe ser una URI: " + e, e, //$NON-NLS-1$
						XMLErrorCode.Request.INVALID_ENCODING_URI);
			}
		}
		b.encoding = encoding;

		b.validatePkcs1 = bool(extraParams, XAdESExtraParams.INTERNAL_VALIDATE_PKCS1, true);

		// El KeyInfo se firmara salvo que la firma sea Baseline o que se indique
		// expresamente que no se haga.
		b.keepKeyInfoUnsigned = AOSignConstants.SIGN_PROFILE_BASELINE.equalsIgnoreCase(b.profile)
				|| bool(extraParams, XAdESExtraParams.KEEP_KEYINFO_UNSIGNED, false);

		URI dataUri = null;
		if (extraParams.containsKey(XAdESExtraParams.URI)) {
			try {
				dataUri = AOUtil.createURI(extraParams.getProperty(XAdESExtraParams.URI));
			}
			catch (final Exception e) {
				LOGGER.warning(
						"Se ha pasado una URI invalida como referencia a los datos a firmar: " + e); //$NON-NLS-1$
			}
		}
		b.dataUri = dataUri;

		return new XAdESSigningParameters(b);
	}

	private static boolean bool(final Properties props, final String key, final boolean defaultValue) {
		return Boolean.parseBoolean(props.getProperty(key, Boolean.toString(defaultValue)));
	}

	private static final class Builder {
		String algorithm;
		String algoUri;
		String format;
		String mode;
		boolean useManifest;
		boolean onlySignningCert;
		boolean avoidXpathExtraTransformsOnEnveloped;
		String envelopedNodeXPath;
		String nodeToSign;
		boolean avoidEnvelopedTransformWhenSigningNode;
		String digestMethodAlgorithm;
		String externalReferencesHashAlgorithm;
		String canonicalizationAlgorithm;
		String xadesNamespace;
		String signedPropertiesTypeUrl;
		boolean ignoreStyleSheets;
		boolean avoidBase64Transforms;
		boolean headless;
		boolean addKeyInfoKeyValue;
		boolean addKeyInfoKeyName;
		boolean addKeyInfoX509IssuerSerial;
		boolean facturaeSign;
		String outputXmlEncoding;
		String mimeType;
		String oid;
		String encoding;
		boolean validatePkcs1;
		String profile;
		boolean keepKeyInfoUnsigned;
		URI dataUri;
	}
}
