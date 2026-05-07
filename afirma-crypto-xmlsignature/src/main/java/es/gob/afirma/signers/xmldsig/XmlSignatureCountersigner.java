/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 */

package es.gob.afirma.signers.xmldsig;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.w3c.dom.Element;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.signers.xml.Utils;
import es.gob.afirma.signers.xml.XMLConstants;
import es.gob.afirma.signers.xml.XMLErrorCode;

/**
 * Núcleo de la operación de contrafirma XMLDSig: dado un nodo {@code Signature}
 * existente, crea otra firma cuyo {@code Reference} apunta al SignatureValue
 * del nodo recibido. Las 4 estrategias de selección de
 * {@link CountersignNodeSelector} delegan en este componente para producir
 * cada nodo de contrafirma una vez que han decidido qué firmas son objetivo.
 *
 * <p>Extraído del método privado {@code cs()} de {@link AOXMLDSigSigner}
 * (115 LOC) en la Fase D.2 del plan Clean Code (2026-05-07): aísla el
 * núcleo común a las 4 estrategias y permite tests dirigidos.</p>
 */
final class XmlSignatureCountersigner {

	private static final String COUNTERSIGNATURE_TYPE_URI =
			"http://uri.etsi.org/01903#CountersignedSignature"; //$NON-NLS-1$
	private static final String SIGNATURE_VALUE = "SignatureValue"; //$NON-NLS-1$
	private static final String ID_ATTR = "Id"; //$NON-NLS-1$

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$

	/**
	 * Crea una contrafirma XMLDSig sobre {@code signature} y la inserta en
	 * el documento del que cuelga. El documento al que se inserta el
	 * resultado es {@code signature.getOwnerDocument()}.
	 *
	 * @param signature Nodo XMLDSig a contrafirmar.
	 * @param signAlgorithm Algoritmo de firma — antes leído desde
	 *     {@code AOXMLDSigSigner.this.algo}; pasarlo explícito permite
	 *     eliminar el campo mutable en Fase D.3.
	 * @param key Clave privada del firmante.
	 * @param certChain Cadena de certificados.
	 * @param onlySignningCert Si es {@code true} solo se incluye el cert
	 *     firmante (no la cadena entera).
	 * @param refsDigestMethod URI del algoritmo de huella para las referencias.
	 * @param canonicalizationAlgorithm URI del algoritmo de canonicalización.
	 * @param xmlSignaturePrefix Prefijo del namespace XMLDSig.
	 * @throws AOException Si algún parámetro o paso de la firma falla.
	 */
	void countersignNode(final Element signature,
			final String signAlgorithm,
			final PrivateKey key,
			final Certificate[] certChain,
			final boolean onlySignningCert,
			final String refsDigestMethod,
			final String canonicalizationAlgorithm,
			final String xmlSignaturePrefix) throws AOException {

		final Element signatureValue = (Element) signature
				.getElementsByTagNameNS(XMLConstants.DSIGNNS, SIGNATURE_VALUE).item(0);

		final List<Reference> referenceList = new ArrayList<>();
		final XMLSignatureFactory fac = Utils.getDOMFactory();
		final DigestMethod digestMethod;
		try {
			digestMethod = fac.newDigestMethod(refsDigestMethod, null);
		}
		catch (final Exception e) {
			throw new AOException(
				"No se ha podido obtener un generador de huellas digitales para el algoritmo '" //$NON-NLS-1$
				+ refsDigestMethod + "': " + e, e, //$NON-NLS-1$
				XMLErrorCode.Request.INVALID_REFERENCES_HASH_ALGORITHM_URI);
		}
		final String referenceId = "Reference-" + UUID.randomUUID().toString(); //$NON-NLS-1$

		try {
			// Transformada para la canonicalizacion inclusiva con comentarios
			final List<Transform> transformList = new ArrayList<>();
			transformList.add(fac.newTransform(canonicalizationAlgorithm, (TransformParameterSpec) null));
			referenceList.add(
				fac.newReference(
					"#" + signatureValue.getAttribute(ID_ATTR), //$NON-NLS-1$
					digestMethod,
					transformList,
					COUNTERSIGNATURE_TYPE_URI,
					referenceId));
		}
		catch (final Exception e) {
			throw new AOException("No se ha podido anadir la transformacion de canonizacion en la contrafirma: " + e, //$NON-NLS-1$
					e, XMLErrorCode.Request.INVALID_CANONICALIZATION_URI);
		}

		// definicion de identificadores
		final String id = UUID.randomUUID().toString();
		final String signatureId = "Signature-" + id; //$NON-NLS-1$
		final String signatureValueId = "SignatureValue-" + id; //$NON-NLS-1$
		final String keyInfoId = "KeyInfo-" + id; //$NON-NLS-1$

		try {
			// referencia a KeyInfo
			referenceList.add(fac.newReference("#" + keyInfoId, digestMethod)); //$NON-NLS-1$

			final KeyInfoFactory kif = fac.getKeyInfoFactory();
			final X509Certificate cert = (X509Certificate) certChain[0];

			final List<XMLStructure> content = new ArrayList<>();
			content.add(kif.newKeyValue(cert.getPublicKey()));

			// Si se nos pidió expresamente que no insertemos la cadena, solo
			// el cert firmante. Tambien lo haremos cuando al recuperar la
			// cadena nos devuelva null.
			Certificate[] certs = null;
			if (!onlySignningCert) {
				certs = certChain;
			}
			if (certs == null) {
				certs = new Certificate[] { cert };
			}
			content.add(kif.newX509Data(Arrays.asList(certs)));

			final XMLSignature sign = fac.newXMLSignature(
				fac.newSignedInfo(
					fac.newCanonicalizationMethod(canonicalizationAlgorithm,
							(C14NMethodParameterSpec) null),
					fac.newSignatureMethod(XMLConstants.SIGN_ALGOS_URI.get(signAlgorithm), null),
					referenceList),
				kif.newKeyInfo(content, keyInfoId),
				null,
				signatureId,
				signatureValueId);

			final DOMSignContext signContext = new DOMSignContext(
					key, signature.getOwnerDocument().getDocumentElement());

			signContext.putNamespacePrefix(XMLConstants.DSIGNNS, xmlSignaturePrefix);

			try {
				// Dereferenciador a medida que solo actúa cuando falla el por defecto.
				signContext.setURIDereferencer(
					new CustomUriDereferencer(CustomUriDereferencer.getDefaultDereferencer()));
			}
			catch (final Exception e) {
				LOGGER.warning("No se ha podido instalar un dereferenciador a medida, es posible que fallen las firmas de nodos concretos: " + e); //$NON-NLS-1$
			}

			sign.sign(signContext);
		}
		catch (final NoSuchAlgorithmException e) {
			throw new AOException(
				"Hay al menos un algoritmo no soportado: " + e, //$NON-NLS-1$
				e, ErrorCode.Request.UNSUPPORTED_SIGNATURE_ALGORITHM);
		}
		catch (final Exception e) {
			throw new AOException(
				"No se ha podido realizar la contrafirma: " + e, e, //$NON-NLS-1$
				XMLErrorCode.Internal.INTERNAL_XML_SIGNING_ERROR);
		}
	}
}
