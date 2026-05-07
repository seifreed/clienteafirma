/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * Verifica la firma XMLDSig embebida en una TSL contra una clave pública
 * de confianza. Pensado para validar:
 *
 * <ul>
 *   <li>la LOTL (firmada por la Comisión, con clave pinada en el cliente);</li>
 *   <li>cada TSL nacional (firmada por su scheme operator, clave publicada
 *       en la propia LOTL).</li>
 * </ul>
 *
 * <p>El módulo solo expone validación; la <em>cadena</em> de confianza
 * (LOTL → certificate de scheme operator → TSL nacional) se orquesta fuera,
 * en {@code afirma-eudiw-bridge} cuando se integre con la wallet.</p>
 */
public final class TslVerifier {

	/** Verifica XMLDSig sobre el XML proporcionado contra la clave pública dada.
	 *  Usa la implementación JSR-105 del JDK; Apache Santuario está en el
	 *  classpath solo como fallback para algoritmos legacy. */
	public boolean verify(final byte[] xml, final PublicKey trustedKey) throws TslException {
		if (xml == null || xml.length == 0) {
			throw new TslException("TSL vacía"); //$NON-NLS-1$
		}
		if (trustedKey == null) {
			throw new TslException("Clave de confianza no proporcionada"); //$NON-NLS-1$
		}
		try {
			final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); //$NON-NLS-1$
			final DocumentBuilder db = dbf.newDocumentBuilder();
			final Document doc;
			try (ByteArrayInputStream bais = new ByteArrayInputStream(xml)) {
				doc = db.parse(bais);
			}

			final NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature"); //$NON-NLS-1$
			if (nl.getLength() == 0) {
				return false;
			}

			final DOMValidateContext valContext = new DOMValidateContext(trustedKey, nl.item(0));
			valContext.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE); //$NON-NLS-1$
			final XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM"); //$NON-NLS-1$
			final XMLSignature signature = factory.unmarshalXMLSignature(valContext);
			return signature.validate(valContext);
		}
		catch (final Exception e) {
			throw new TslException("Error verificando firma TSL: " + e.getMessage(), e); //$NON-NLS-1$
		}
	}
	// TODO M4.x — soportar TSLs self-contained extrayendo la clave del propio
	// <KeyInfo>/<X509Data>. La LOTL europea no es self-contained (su clave la
	// publica la Comisión por separado), pero las TSLs nacionales pueden serlo
	// según el reglamento de implementación de cada estado miembro.
}
