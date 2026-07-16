/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
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

	/** Verifica una TSL self-contained usando el certificado X.509 embebido en
	 *  {@code ds:Signature/ds:KeyInfo/ds:X509Data}. */
	public boolean verify(final byte[] xml) throws TslException {
		if (xml == null || xml.length == 0) {
			throw new TslException("TSL vacía"); //$NON-NLS-1$
		}
		try {
			final Document doc = parseXml(xml);
			final NodeList signatures = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature"); //$NON-NLS-1$
			if (signatures.getLength() == 0) {
				return false;
			}
			if (signatures.getLength() > 1) {
				throw new TslException("TSL con varias firmas XMLDSig"); //$NON-NLS-1$
			}
			final Element signature = (Element) signatures.item(0);
			final NodeList certificates = signature.getElementsByTagNameNS(XMLSignature.XMLNS, "X509Certificate"); //$NON-NLS-1$
			if (certificates.getLength() == 0) {
				throw new TslException("Firma TSL sin certificado X.509 en KeyInfo"); //$NON-NLS-1$
			}
			if (certificates.getLength() > 1) {
				throw new TslException("Firma TSL con varios certificados X.509 en KeyInfo"); //$NON-NLS-1$
			}
			final X509Certificate cert;
			try {
				final byte[] der = Base64.getMimeDecoder().decode(certificates.item(0).getTextContent());
				final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
				cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
			}
			catch (final IllegalArgumentException | java.security.cert.CertificateException e) {
				throw new TslException("Certificado KeyInfo TSL inválido", e); //$NON-NLS-1$
			}
			cert.checkValidity();
			return validate(doc, cert.getPublicKey());
		}
		catch (final TslException e) {
			throw e;
		}
		catch (final Exception e) {
			throw new TslException("Error verificando firma TSL self-contained: " + e.getMessage(), e); //$NON-NLS-1$
		}
	}

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
			return validate(parseXml(xml), trustedKey);
		}
		catch (final Exception e) {
			throw new TslException("Error verificando firma TSL: " + e.getMessage(), e); //$NON-NLS-1$
		}
	}

	private static Document parseXml(final byte[] xml) throws Exception {
		final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); //$NON-NLS-1$
		dbf.setFeature("http://xml.org/sax/features/external-general-entities", false); //$NON-NLS-1$
		dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false); //$NON-NLS-1$
		dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false); //$NON-NLS-1$
		dbf.setXIncludeAware(false);
		dbf.setExpandEntityReferences(false);
		final DocumentBuilder db = dbf.newDocumentBuilder();
		try (ByteArrayInputStream bais = new ByteArrayInputStream(xml)) {
			return db.parse(bais);
		}
	}

	private static boolean validate(final Document doc, final PublicKey trustedKey) throws Exception {
		final NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature"); //$NON-NLS-1$
		if (nl.getLength() == 0) {
			return false;
		}
		if (nl.getLength() > 1) {
			throw new TslException("TSL con varias firmas XMLDSig"); //$NON-NLS-1$
		}
		final DOMValidateContext valContext = new DOMValidateContext(trustedKey, nl.item(0));
		valContext.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE); //$NON-NLS-1$
		final XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM"); //$NON-NLS-1$
		final XMLSignature signature = factory.unmarshalXMLSignature(valContext);
		return signature.validate(valContext);
	}
}
