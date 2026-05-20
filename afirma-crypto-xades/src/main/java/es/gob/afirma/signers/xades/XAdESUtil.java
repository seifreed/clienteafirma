/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.xades;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.DocumentType;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.AOInvalidSignatureFormatException;
import es.gob.afirma.core.SigningLTSException;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.ui.AOUIFactory;
import es.gob.afirma.signers.xml.XMLConstants;
import es.gob.afirma.signers.xml.XMLErrorCode;
import es.uji.crypto.xades.jxades.security.xml.XAdES.CommitmentTypeIdImpl;
import es.uji.crypto.xades.jxades.security.xml.XAdES.CommitmentTypeIndication;
import es.uji.crypto.xades.jxades.security.xml.XAdES.CommitmentTypeIndicationImpl;
import es.uji.crypto.xades.jxades.security.xml.XAdES.SigningCertificateV2Info;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdES;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdESBase;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XadesWithBaselineAttributes;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XadesWithBasicAttributes;
import es.uji.crypto.xades.jxades.util.XMLUtils;

/**
 * Utilidades varias para firmas XAdES.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s.
 */
public final class XAdESUtil {

	private static final Logger LOGGER = Logger.getLogger("es.gob.afirma");	//$NON-NLS-1$

	private static final String[] SIGNED_PROPERTIES_TYPES = new String[] {
		XAdESConstants.NAMESPACE_XADES_NO_VERSION_SIGNED_PROPERTIES,
		XAdESConstants.NAMESPACE_XADES_1_2_2_SIGNED_PROPERTIES,
		XAdESConstants.NAMESPACE_XADES_1_3_2_SIGNED_PROPERTIES,
		XAdESConstants.NAMESPACE_XADES_1_4_1_SIGNED_PROPERTIES
	};

    private static final String CRYPTO_OPERATION_SIGN = "SIGN"; //$NON-NLS-1$


	private XAdESUtil() {
		// No permitimos la instanciacion
	}

    /**
     * Indica si un tipo se corresponde con el que se debe declarar en la referencia a las
     * propiedades firmadas de una firma.
     * @param type Tipo declarado.
     * @return {@code true} si es un tipo SignedProperties, {@code false} en caso contrario.
     */
    static boolean isSignedPropertiesType(final String type) {
    	for (final String signedPropertiesType : SIGNED_PROPERTIES_TYPES) {
    		if (signedPropertiesType.equals(type)) {
    			return true;
    		}
    	}
    	return false;
    }

	static Element getFirstElementFromXPath(final String xpathExpression, final Element sourceElement) throws AOException {
		final NodeList nodeList;
		try {
			 nodeList = (NodeList)XPathFactory.newInstance().newXPath().evaluate(xpathExpression, sourceElement, XPathConstants.NODESET);
		}
		catch (final XPathExpressionException e1) {
			throw new AOException(
				"No se ha podido evaluar la expresion indicada para la insercion de la firma Enveloped ('" + xpathExpression + "'): " + e1, //$NON-NLS-1$ //$NON-NLS-2$
				e1, XMLErrorCode.Request.INVALID_NODE_SELECTOR_XPATH
			);
		}
		if (nodeList.getLength() < 1) {
			throw new AOException(
				"La expresion indicada para la insercion de la firma Enveloped ('" + xpathExpression + "') no ha devuelto ningun nodo", //$NON-NLS-1$ //$NON-NLS-2$
				XMLErrorCode.Request.INVALID_NODE_SELECTOR_XPATH
			);
		}
		if (nodeList.getLength() > 1) {
			LOGGER.warning(
				"La expresion indicada para la insercion de la firma Enveloped ('" + xpathExpression + "') ha devuelto varios nodos, se usara el primero" //$NON-NLS-1$ //$NON-NLS-2$
			);
		}
		return (Element) nodeList.item(0);
	}

	/**
	 * Busca un nodo con el atributo 'Id' indicado.
	 * @param nodeId Identificador del nodo que queremos encontrar.
	 * @param currentElement Elemento en el que queremos buscar.
	 * @param omitSignatures Si es {@code true}, se omite la b&uacute;squeda dentro de cualquier
	 * nodo de nombre "Signature", aunque podr&iacute;a referenciarse al propio nodo, {@code false}
	 * en caso contrario.
	 * @return Nodo con el identificador indicado o {@code null} si no
	 * se encuentra el nodo.
	 */
	static Element findElementById(final String nodeId, final Element currentElement, final boolean omitSignatures) {

		// Si es este el nodo, lo devolvemos
		if (nodeId.equals(currentElement.getAttribute(XAdESConstants.ID_IDENTIFIER))) {
			return currentElement;
		}

		// Se podria referenciar a un nodo llamado "Signature", pero omitiriamos
		// la busqueda dentro de cualquier nodo con dicho nombre si asi se indica
		if (omitSignatures && currentElement.getLocalName().equals("Signature")) { //$NON-NLS-1$
			return null;
		}

		// Si no, lo buscamos en cada uno de los hijos, deteniendonos
		// en cuanto se encuentre
		Node item;
		final NodeList childList = currentElement.getChildNodes();
		for (int i = 0; i < childList.getLength(); i++) {
			item = childList.item(i);
			if (item.getNodeType() == Node.ELEMENT_NODE) {
				final Element el = findElementById(nodeId, (Element) item, omitSignatures);
				if (el != null) {
					return el;
				}
			}
		}
		// si no lo encontramos en ninguno de los nodos hijo, devolvemos nulo
		return null;
	}

	static String getDigestMethodByCommonName(final String identifierHashAlgorithm) throws NoSuchAlgorithmException {
		final String normalDigAlgo = AOSignConstants.getDigestAlgorithmName(identifierHashAlgorithm);
		if ("SHA1".equalsIgnoreCase(normalDigAlgo)) { //$NON-NLS-1$
			return DigestMethod.SHA1;
		}
		if ("SHA-256".equalsIgnoreCase(normalDigAlgo)) { //$NON-NLS-1$
			return DigestMethod.SHA256;
		}
		if ("SHA-512".equalsIgnoreCase(normalDigAlgo)) { //$NON-NLS-1$
			return DigestMethod.SHA512;
		}
		throw new NoSuchAlgorithmException("No se soporta el algoritmo: " + normalDigAlgo); //$NON-NLS-1$
	}

	static Element getRootElement(final Document docSignature, final Properties extraParams) {

		final Properties xParams = extraParams != null ? extraParams : new Properties();
		final String nodeName            = xParams.getProperty(XAdESExtraParams.ROOT_XML_NODE_NAME , XAdESConstants.TAG_PARENT_NODE);
		final String nodeNamespace       = xParams.getProperty(XAdESExtraParams.ROOT_XML_NODE_NAMESPACE);
		final String nodeNamespacePrefix = xParams.getProperty(XAdESExtraParams.ROOT_XML_NODE_NAMESPACE_PREFIX);

		final Element afirmaRoot;
		if (nodeNamespace == null) {
			afirmaRoot = docSignature.createElement(nodeName);
		}
		else {
			afirmaRoot = docSignature.createElementNS(nodeNamespace, nodeName);
			if (nodeNamespacePrefix != null) {
				afirmaRoot.setAttribute(
					nodeNamespacePrefix.startsWith("xmlns:") ?  nodeNamespacePrefix : "xmlns:" + nodeNamespacePrefix, //$NON-NLS-1$ //$NON-NLS-2$
					nodeNamespace
				);
			}
		}
		afirmaRoot.setAttributeNS(null, XAdESConstants.ID_IDENTIFIER, nodeName + "-Root-" + UUID.randomUUID().toString());  //$NON-NLS-1$

		return afirmaRoot;
	}

	static Map<String, String> getOriginalXMLProperties(final Document docum,
			                                            final String outputXmlEncoding) {

		final Map<String, String> originalXMLProperties = new Hashtable<>();
		if (docum != null) {

			if (outputXmlEncoding != null) {
				originalXMLProperties.put(
					OutputKeys.ENCODING,
					outputXmlEncoding
				);
			}
			else if (docum.getXmlEncoding() != null) {
				originalXMLProperties.put(
					OutputKeys.ENCODING,
					docum.getXmlEncoding()
				);
			}

			String tmpXmlProp = docum.getXmlVersion();
			if (tmpXmlProp != null) {
				originalXMLProperties.put(OutputKeys.VERSION, tmpXmlProp);
			}

			final DocumentType dt = docum.getDoctype();
			if (dt != null) {
				tmpXmlProp = dt.getSystemId();
				if (tmpXmlProp != null) {
					originalXMLProperties.put(OutputKeys.DOCTYPE_SYSTEM, tmpXmlProp);
				}
			}

		}
		return originalXMLProperties;
	}

	 /** Intenta determinar el prefijo del espacio de nombres de XAdES.
     * @param signatureElement Firma XAdES.
     * @return Prefijo del espacio de nombres o nulo si no se ha
     * establecido prefijo o si no se encuentra el espacio de nombres. */
//    static String guessXAdESNamespacePrefix(final Element el) {
//        final String signatureText = new String(Utils.writeXML(el, null, null, null));
//
//        // Buscamos los espacios de nombres declarados en la firma y despues vemos
//        // si alguno es el de XAdES. En cuanto se detecta uno, se utiliza ese
//        int idx = 0;
//        String ns = null;
//        while (ns == null && (idx = signatureText.indexOf(" xmlns:", idx)) != -1) { //$NON-NLS-1$
//        	final int eqIdx = signatureText.indexOf("=", idx); //$NON-NLS-1$
//        	if (eqIdx != -1) {
//        		final String xadesNsPrefix = signatureText.substring(
//        				eqIdx,
//        				Math.min(eqIdx + "=\"http://uri.etsi.org/".length(), signatureText.length())); //$NON-NLS-1$
//        		if ("=\"http://uri.etsi.org/".equals(xadesNsPrefix)) { //$NON-NLS-1$
//        			ns = signatureText.substring(idx + " xmlns:".length(), eqIdx); //$NON-NLS-1$
//        		}
//        	}
//        	idx++;
//        }
//        return ns;
//    }
//    static String guessXAdESNamespacePrefix(final Element signatureElement) {
//
//    	// Obtenemos la referencia a los atributos firmados de la firma
//    	final Element referenceNode = getSignedPropertiesReference(signatureElement);
//    	if (referenceNode == null) {
//    		return null;
//    	}
//
//    	// Recuperamos el identificador del elementos con los atributos firmados
//    	final String uri = referenceNode.getAttribute("URI"); //$NON-NLS-1$
//    	if (uri == null || !uri.startsWith("#")) { //$NON-NLS-1$
//    		return null;
//    	}
//
//    	// Recuperamos el nodo con los elemento firmados
//    	final String signedPropertiesId = uri.substring(1);
//    	final Element signedPropertiesElement = findElementById(signedPropertiesId, signatureElement, false);
//    	if (signedPropertiesElement == null) {
//    		return null;
//    	}
//
//    	// Obtenemos el prefijo del nodo
//    	return signedPropertiesElement.getPrefix();
//    }


	/**
     * Indica si los datos a firmar son obligatorios para la operaci&oacute;n de firma con la
     * configuraci&oacute;n proporcionada.
     * @param cryptoOperation Operaci&oacute;n criptogr&aacute;fica (SIGN, COSIGN o COUNTERSIGN).
     * @param config Configuraci&oacute;n de firma (extraParams).
     * @return {@code true} si la operaci&oacute;n de firma requiere los datos a firmar,
     * {@code false} en caso de que la configuraci&oacute;n pueda ya proporcionar estos datos.
     */
    public static boolean isDataMandatory(final String cryptoOperation, final Properties config) {

    	// Sera obligatorio que se indiquen los datos de entrada para las cofirmas y contrafirmas
    	// y siempre que el formato no sea Externally Detached y no se trate de una firma manifest
    	return !CRYPTO_OPERATION_SIGN.equalsIgnoreCase(cryptoOperation)
    			|| config == null
    			|| !AOSignConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED.equals(config.getProperty(XAdESExtraParams.FORMAT))
    					&& !Boolean.parseBoolean(config.getProperty(XAdESExtraParams.USE_MANIFEST));
    }

}
