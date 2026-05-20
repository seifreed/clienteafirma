/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.xades;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.gob.afirma.signers.xml.XMLConstants;
import es.uji.crypto.xades.jxades.util.XMLUtils;

/** B&uacute;squeda de elementos espec&iacute;ficos en el &aacute;rbol DOM de una firma XAdES:
 * {@code Signature}, {@code SignedInfo}, {@code SignatureMethod},
 * {@code SignedProperties} (firmados y no firmados) y la {@code Reference} que
 * apunta a las propiedades firmadas.
 *
 * <p>Extra&iacute;do de {@link XAdESUtil} como segundo cluster cohesivo del troceo de la
 * "god class" original (ver {@link XAdESSignatureTypeDetector} para el primer cluster).
 * Mantiene los mismos contratos (mismo tipo de retorno, misma sem&aacute;ntica de
 * {@code null}); solo cambian FQN y nombre corto.
 *
 * <p>La clase es {@code final} y no instanciable. */
public final class XAdESDomLookup {

    private static final String[] SIGNED_PROPERTIES_TYPES = {
        XAdESConstants.NAMESPACE_XADES_NO_VERSION_SIGNED_PROPERTIES,
        XAdESConstants.NAMESPACE_XADES_1_2_2_SIGNED_PROPERTIES,
        XAdESConstants.NAMESPACE_XADES_1_3_2_SIGNED_PROPERTIES,
        XAdESConstants.NAMESPACE_XADES_1_4_1_SIGNED_PROPERTIES
    };

    private static final String SIGNATURE_TAG = "Signature"; //$NON-NLS-1$

    private XAdESDomLookup() {
        // No instanciable
    }

    /** Comprueba si el {@code Type} declarado en una {@code Reference} se
     * corresponde con el de las {@code SignedProperties} de cualquier
     * versi&oacute;n XAdES soportada.
     *
     * @param type Tipo declarado en el atributo {@code Type} de una
     *        {@code Reference}.
     * @return {@code true} si es {@code SignedProperties}; {@code false} en
     *         caso contrario. */
    public static boolean isSignedPropertiesType(final String type) {
        for (final String signedPropertiesType : SIGNED_PROPERTIES_TYPES) {
            if (signedPropertiesType.equals(type)) {
                return true;
            }
        }
        return false;
    }

    /** Busca recursivamente el nodo cuyo atributo {@code Id} coincida con el
     * indicado.
     *
     * @param nodeId Identificador del nodo a buscar.
     * @param currentElement Elemento en el que buscar.
     * @param omitSignatures Si es {@code true}, omite la b&uacute;squeda
     *        dentro de elementos {@code Signature}.
     * @return Nodo con el identificador indicado, o {@code null} si no se
     *         encuentra. */
    public static Element findElementById(final String nodeId, final Element currentElement, final boolean omitSignatures) {
        if (nodeId.equals(currentElement.getAttribute(XAdESConstants.ID_IDENTIFIER))) {
            return currentElement;
        }
        if (omitSignatures && SIGNATURE_TAG.equals(currentElement.getLocalName())) {
            return null;
        }
        final NodeList childList = currentElement.getChildNodes();
        for (int i = 0; i < childList.getLength(); i++) {
            final Node item = childList.item(i);
            if (item.getNodeType() == Node.ELEMENT_NODE) {
                final Element found = findElementById(nodeId, (Element) item, omitSignatures);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    /** Obtiene la primera firma encontrada en un elemento XML.
     * @param element Elemento XML donde buscar.
     * @return Primer elemento {@code Signature} encontrado, o {@code null} si
     *         {@code element} es {@code null} o no contiene ninguna firma. */
    public static Element getFirstSignatureElement(final Element element) {
        if (element == null) {
            return null;
        }
        if (XMLConstants.TAG_SIGNATURE.equals(element.getLocalName())) {
            return element;
        }
        final NodeList signatures = element.getElementsByTagNameNS(XMLConstants.DSIGNNS, XMLConstants.TAG_SIGNATURE);
        if (signatures.getLength() > 0) {
            return (Element) signatures.item(0);
        }
        return null;
    }

    /** Obtiene el nodo {@code SignedInfo} de un elemento de firma individual.
     * @param signature Elemento {@code Signature}.
     * @return Elemento {@code SignedInfo}, o {@code null} si no se encuentra. */
    public static Element getSignedInfo(final Element signature) {
        final NodeList childs = signature.getChildNodes();
        for (int i = 0; i < childs.getLength(); i++) {
            final Node child = childs.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE
                    && XMLConstants.DSIGNNS.equals(child.getNamespaceURI())
                    && XMLConstants.TAG_SIGNEDINFO.equals(child.getLocalName())) {
                return (Element) child;
            }
        }
        return null;
    }

    /** Obtiene el elemento {@code SignatureMethod} de una firma XAdES.
     * @param signatureElement Elemento {@code Signature} de una firma XAdES.
     * @return Elemento {@code SignatureMethod}, o {@code null} si no se encuentra. */
    public static Element getSignatureMethodElement(final Element signatureElement) {
        final Element signedInfoElement = getSignedInfo(signatureElement);
        if (signedInfoElement == null) {
            return null;
        }
        final NodeList signatureMethodList = signedInfoElement.getElementsByTagNameNS(XMLConstants.DSIGNNS, XAdESConstants.TAG_SIGNATURE_METHOD);
        return (Element) signatureMethodList.item(0);
    }

    /** Obtiene el elemento {@code Reference} que apunta a los atributos firmados
     * ({@code SignedProperties}) de la firma indicada.
     * @param signatureElement Elemento {@code Signature} de una firma XAdES.
     * @return Elemento {@code Reference} de las propiedades firmadas, o
     *         {@code null} si no se encuentra. */
    static Element getSignedPropertiesReference(final Element signatureElement) {
        final Element signedInfoElement = getSignedInfo(signatureElement);
        if (signedInfoElement == null) {
            return null;
        }
        final NodeList references = signedInfoElement.getElementsByTagNameNS(XMLConstants.DSIGNNS, XMLConstants.TAG_REFERENCE);
        for (int i = 0; i < references.getLength(); i++) {
            final Element reference = (Element) references.item(i);
            final String type = reference.getAttribute("Type"); //$NON-NLS-1$
            if (type != null && !type.isEmpty() && XAdESDomLookup.isSignedPropertiesType(type)) {
                return reference;
            }
        }
        return null;
    }

    /** Obtiene el elemento {@code SignedProperties} usando una referencia ya
     * localizada.
     * @param signatureElement Elemento {@code Signature} de una firma XAdES.
     * @param signedPropertiesReference Elemento {@code Reference} que apunta a
     *        los atributos firmados.
     * @return Elemento {@code SignedProperties}, o {@code null} si la
     *         referencia es inv&aacute;lida o el elemento no existe. */
    static Element getSignedPropertiesElement(final Element signatureElement, final Element signedPropertiesReference) {
        final String uri = signedPropertiesReference.getAttribute("URI"); //$NON-NLS-1$
        if (uri == null || !uri.startsWith("#")) { //$NON-NLS-1$
            return null;
        }
        return XAdESDomLookup.findElementById(uri.substring(1), signatureElement, false);
    }

    /** Obtiene el elemento {@code SignedProperties} de una firma XAdES
     * localizando primero la {@code Reference} que lo apunta.
     * @param signatureElement Elemento {@code Signature} de una firma XAdES.
     * @return Elemento {@code SignedProperties}, o {@code null} si no se
     *         encuentra. */
    static Element getSignedPropertiesElement(final Element signatureElement) {
        final Element referenceNode = getSignedPropertiesReference(signatureElement);
        if (referenceNode == null) {
            return null;
        }
        return getSignedPropertiesElement(signatureElement, referenceNode);
    }

    /** Obtiene el listado de elementos {@code Reference} de {@code SignedInfo}
     * que apuntan a datos firmados (excluye la referencia al
     * {@code SignedProperties} y al {@code KeyInfo}).
     *
     * @param signatureElement Elemento {@code Signature} XML.
     * @return Lista de referencias a datos, o {@code null} si no se encontr&oacute;
     *         {@code SignedInfo}. */
    public static List<Element> getSignatureDataReferenceList(final Element signatureElement) {
        final Element signedInfoElement = getSignedInfo(signatureElement);
        if (signedInfoElement == null) {
            return null;
        }
        final NodeList references = signedInfoElement.getElementsByTagNameNS(XMLConstants.DSIGNNS, XMLConstants.TAG_REFERENCE);
        final List<Element> dataReferences = new ArrayList<>();
        for (int i = 0; i < references.getLength(); i++) {
            final Element reference = (Element) references.item(i);
            if (referencesData(reference, signatureElement)) {
                dataReferences.add(reference);
            }
        }
        return dataReferences;
    }

    private static boolean referencesData(final Element reference, final Element signatureElement) {
        final String type = reference.getAttribute("Type"); //$NON-NLS-1$
        if (type != null && !type.isEmpty()) {
            return !XAdESDomLookup.isSignedPropertiesType(type);
        }
        // Sin Type declarado: clasificamos por URI
        final String uri = reference.getAttribute("URI"); //$NON-NLS-1$
        if (uri == null || !uri.startsWith("#")) { //$NON-NLS-1$
            // Referencia externa: siempre es un dato firmado
            return true;
        }
        final Node referencedNode = XAdESDomLookup.findElementById(uri.substring(1), signatureElement, false);
        if (referencedNode == null) {
            // Referencia interna a un nodo fuera de la firma → datos
            return true;
        }
        // Referencia interna a un nodo dentro de la firma → datos sólo si no es KeyInfo ni SignedProperties
        final String nodeName = referencedNode.getLocalName();
        return !"KeyInfo".equals(nodeName) && !"SignedProperties".equals(nodeName); //$NON-NLS-1$ //$NON-NLS-2$
    }

    /** Obtiene el elemento {@code UnsignedProperties} de una firma XAdES.
     * @param signatureElement Elemento {@code Signature} de una firma XAdES.
     * @return Elemento {@code UnsignedProperties}, o {@code null} si no se
     *         encuentra. */
    static Element getUnSignedPropertiesElement(final Element signatureElement) {
        final Element signedPropertiesElement = getSignedPropertiesElement(signatureElement);
        if (signedPropertiesElement == null) {
            return null;
        }
        final Element qualifyingPropertiesElement = (Element) signedPropertiesElement.getParentNode();
        return XMLUtils.getChildElementByTagNameNS(
                qualifyingPropertiesElement,
                XAdESConstants.TAG_UNSIGNED_PROPERTIES,
                XAdESConstants.NAMESPACE_XADES_1_3_2);
    }

}
