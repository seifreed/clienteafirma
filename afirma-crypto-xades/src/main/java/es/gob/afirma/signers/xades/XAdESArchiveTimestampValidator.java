/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.xades;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.gob.afirma.core.SigningLTSException;
import es.uji.crypto.xades.jxades.util.XMLUtils;

/** Validador que detecta {@code ArchiveTimeStamp} (firmas LTV/LTA) en firmas
 * XAdES. El sello de archivo aparece en {@code UnsignedSignatureProperties}
 * y, dependiendo de la versi&oacute;n del XAdES, vive en el namespace
 * 1.4.1, 1.3.2 o 1.2.2.
 *
 * <p>Quinto cluster extra&iacute;do de {@link XAdESUtil} en el troceo de la
 * "god class" (ver {@link XAdESSignatureTypeDetector}, {@link XAdESDomLookup},
 * {@link XAdESProfileChecks} y {@link XAdESBaseFactory}).
 *
 * <p>La clase es {@code final} y no instanciable. */
public final class XAdESArchiveTimestampValidator {

    private static final String[] ARCHIVE_TIMESTAMP_NAMESPACES = {
            XAdESConstants.NAMESPACE_XADES_1_4_1,
            XAdESConstants.NAMESPACE_XADES_1_3_2,
            XAdESConstants.NAMESPACE_XADES_1_2_2
    };

    private XAdESArchiveTimestampValidator() {
        // No instanciable
    }

    /** Verifica que ninguna de las firmas proporcionadas incluya un
     * {@code ArchiveTimeStamp}.
     *
     * @param signatures Lista de elementos {@code Signature}.
     * @throws SigningLTSException Si alguna de las firmas incluye un sello de
     *         archivo. */
    public static void checkArchiveSignatures(final NodeList signatures) throws SigningLTSException {
        for (int i = 0; i < signatures.getLength(); i++) {
            checkArchiveSignatures((Element) signatures.item(i));
        }
    }

    /** Verifica que la firma proporcionada no incluya un
     * {@code ArchiveTimeStamp}.
     *
     * @param signature Elemento {@code Signature} XML.
     * @throws SigningLTSException Si la firma incluye un sello de archivo. */
    public static void checkArchiveSignatures(final Element signature) throws SigningLTSException {
        final Element unsignedProperties = XAdESDomLookup.getUnSignedPropertiesElement(signature);
        if (unsignedProperties == null) {
            return;
        }
        final Element unsignedSignatureProperties = XMLUtils.getChildElementByTagNameNS(
                unsignedProperties,
                XAdESConstants.TAG_UNSIGNED_SIGNATURE_PROPERTIES,
                XAdESConstants.NAMESPACE_XADES_1_3_2);
        if (unsignedSignatureProperties == null) {
            return;
        }
        for (final String namespace : ARCHIVE_TIMESTAMP_NAMESPACES) {
            if (XMLUtils.getChildElementByTagNameNS(unsignedSignatureProperties,
                    XAdESConstants.TAG_ARCHIVE_TIMESTAMP, namespace) != null) {
                throw new SigningLTSException("Se han encontrado firmas de sello de archivo"); //$NON-NLS-1$
            }
        }
    }

}
