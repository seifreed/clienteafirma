/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.xades;

import java.util.List;
import java.util.Locale;

import javax.xml.crypto.dsig.Transform;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.gob.afirma.signers.xml.XMLConstants;

/** Detector del tipo de firma XAdES (Enveloped, Enveloping, Internally/Externally
 * Detached, Manifest) a partir de la lista de referencias del nodo
 * {@code SignedInfo} y, cuando aplica, del propio {@code Signature} o del
 * elemento ra&iacute;z del documento.
 *
 * <p>Esta clase concentra la l&oacute;gica de detecci&oacute;n que antes viv&iacute;a dispersa
 * en {@link XAdESUtil}. Se extrae para cumplir Clean Architecture
 * (responsabilidad &uacute;nica): {@link XAdESUtil} qued&oacute; convertido en una
 * "god class" de m&aacute;s de mil l&iacute;neas y las cinco operaciones de detecci&oacute;n
 * de tipo formaban un cluster cohesivo con la misma firma {@code (Element, List)}
 * &rarr; boolean.
 *
 * <p>La clase es {@code final} y no instanciable. */
public final class XAdESSignatureTypeDetector {

    private static final String XPATH_ENVELOPED_EQ = "not(ancestor-or-self::%1$s:Signature)"; //$NON-NLS-1$
    private static final String XPATH_ENVELOPED_EQ2 = "count(ancestor-or-self::%1$s:Signature|here()/ancestor::%1$s:Signature[1])>count(ancestor-or-self::%1$s:Signature)"; //$NON-NLS-1$

    private XAdESSignatureTypeDetector() {
        // No instanciable
    }

    /** Comprueba a trav&eacute;s de las transformaciones de las referencias si se
     * trata de una firma <i>enveloped</i> (el contenido firmado contiene la
     * propia firma como nodo hijo).
     *
     * @param signatureElement Elemento con la firma a comprobar.
     * @param references Referencias a datos declaradas en la firma.
     * @return {@code true} si es una firma <i>enveloped</i>; {@code false} en
     *         caso contrario o si {@code references} es {@code null}. */
    public static boolean isEnveloped(final Element signatureElement, final List<Element> references) {
        if (references == null) {
            return false;
        }
        for (int i = 0; i < references.size(); i++) {
            final NodeList transformList = references.get(i).getElementsByTagNameNS(XMLConstants.DSIGNNS, "Transform"); //$NON-NLS-1$
            for (int j = 0; j < transformList.getLength(); j++) {
                final String algorithm = ((Element) transformList.item(j)).getAttribute("Algorithm"); //$NON-NLS-1$
                if (Transform.ENVELOPED.equals(algorithm)) {
                    return true;
                }
                if (Transform.XPATH.equals(algorithm)) {
                    final String signaturePrefix = signatureElement.getPrefix();
                    final String xPath = transformList.item(j).getTextContent().replaceAll("\\s+", ""); //$NON-NLS-1$ //$NON-NLS-2$
                    if (String.format(XPATH_ENVELOPED_EQ, signaturePrefix).equals(xPath)
                            || String.format(XPATH_ENVELOPED_EQ2, signaturePrefix).equals(xPath)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /** Comprueba a trav&eacute;s de las referencias si se trata de una firma
     * <i>enveloping</i> (el contenedor de la firma contiene los datos firmados).
     *
     * @param signatureElement Elemento con la firma a comprobar.
     * @param references Referencias a datos declaradas en la firma.
     * @return {@code true} si es una firma <i>enveloping</i>; {@code false} en
     *         caso contrario o si alguno de los par&aacute;metros es {@code null}. */
    public static boolean isEnveloping(final Element signatureElement, final List<Element> references) {
        if (signatureElement == null || references == null) {
            return false;
        }
        for (int i = 0; i < references.size(); i++) {
            final String uri = references.get(i).getAttribute("URI"); //$NON-NLS-1$
            if (uri != null && uri.startsWith("#")) { //$NON-NLS-1$
                final Node referencedNode = XAdESUtil.findElementById(uri.substring(1), signatureElement, false);
                if (referencedNode != null) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Indica si la firma a la que pertenecen las referencias es
     * <i>externally detached</i> (los datos referenciados est&aacute;n en un
     * recurso accesible por URL HTTP/HTTPS).
     *
     * @param references Referencias a datos encontrados en la firma.
     * @return {@code true} si es <i>externally detached</i>; {@code false}
     *         en caso contrario o si {@code references} es {@code null}. */
    public static boolean isExternallyDetached(final List<Element> references) {
        if (references == null) {
            return false;
        }
        for (int i = 0; i < references.size(); i++) {
            final String uri = references.get(i).getAttribute("URI"); //$NON-NLS-1$
            if (uri != null && (uri.toLowerCase(Locale.US).startsWith("http://") //$NON-NLS-1$
                    || uri.toLowerCase(Locale.US).startsWith("https://"))) { //$NON-NLS-1$
                return true;
            }
        }
        return false;
    }

    /** Indica si la firma es <i>internally detached</i> (los datos referenciados
     * residen en el XML padre, fuera de la firma).
     *
     * <p>Nota: una cofirma sobre una firma <i>enveloping</i> podr&iacute;a
     * clasificarse como <i>internally detached</i>; este m&eacute;todo no
     * intenta descartarlo, manteniendo el comportamiento hist&oacute;rico de
     * {@code XAdESUtil}.
     *
     * @param docElement Elemento ra&iacute;z del documento XML.
     * @param references Referencias a datos encontrados en la firma.
     * @return {@code true} si es <i>internally detached</i>; {@code false} en
     *         caso contrario o si alguno de los par&aacute;metros es
     *         {@code null}. */
    public static boolean isInternallyDetached(final Element docElement, final List<Element> references) {
        if (docElement == null || references == null) {
            return false;
        }
        for (int i = 0; i < references.size(); i++) {
            final String uri = references.get(i).getAttribute("URI"); //$NON-NLS-1$
            if (uri != null && uri.startsWith("#")) { //$NON-NLS-1$
                final Node referencedNode = XAdESUtil.findElementById(uri.substring(1), docElement, true);
                if (referencedNode != null) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Indica si alguna de las referencias est&aacute; declarada como de tipo
     * <i>Manifest</i> (la firma usa un manifest para enlazar los datos).
     *
     * @param references Referencias a datos encontrados en la firma.
     * @return {@code true} si la firma usa manifest; {@code false} en caso
     *         contrario o si {@code references} es {@code null}. */
    public static boolean usesManifest(final List<Element> references) {
        if (references == null) {
            return false;
        }
        for (int i = 0; i < references.size(); i++) {
            final String type = references.get(i).getAttribute("Type"); //$NON-NLS-1$
            if (type != null && type.equals(XAdESConstants.REFERENCE_TYPE_MANIFEST)) {
                return true;
            }
        }
        return false;
    }

}
