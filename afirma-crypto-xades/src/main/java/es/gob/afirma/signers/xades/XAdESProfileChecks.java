/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.xades;

import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.gob.afirma.core.AOInvalidSignatureFormatException;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.ui.AOUIFactory;

/** Comprobaciones de perfil / compatibilidad sobre firmas XAdES:
 * versi&oacute;n del namespace soportada, mezcla de versiones, detecci&oacute;n
 * de perfil Baseline EN y reconciliaci&oacute;n del perfil declarado por el
 * usuario con el detectado en la firma a multifirmar.
 *
 * <p>Tercer cluster extra&iacute;do de {@link XAdESUtil} en el troceo de la
 * "god class" (ver {@link XAdESSignatureTypeDetector} y
 * {@link XAdESDomLookup}). Las cuatro funciones forman un cluster cohesivo:
 * validan o reconcilian la naturaleza de una firma sin tocar sus datos
 * criptogr&aacute;ficos.
 *
 * <p>La clase es {@code final} y no instanciable. */
public final class XAdESProfileChecks {

    private static final String[] SUPPORTED_XADES_NAMESPACE_URIS = {
        XAdESConstants.NAMESPACE_XADES_NO_VERSION,
        XAdESConstants.NAMESPACE_XADES_1_2_2,
        XAdESConstants.NAMESPACE_XADES_1_3_2,
        XAdESConstants.NAMESPACE_XADES_1_4_1
    };

    private XAdESProfileChecks() {
        // No instanciable
    }

    /** Comprueba que todos los nodos pasados sean firmas en formato XAdES (es
     * decir, contienen un {@code QualifyingProperties} de alguno de los
     * namespaces XAdES soportados).
     *
     * @param signNodes Listado de nodos de firma.
     * @return {@code true} cuando todos los nodos son firmas XAdES;
     *         {@code false} en cuanto alguno no lo es. */
    public static boolean checkSignNodes(final List<Node> signNodes) {
        for (final Node signNode : signNodes) {
            int lenCount = 0;
            for (final String xadesNamespace : SUPPORTED_XADES_NAMESPACE_URIS) {
                lenCount += ((Element) signNode).getElementsByTagNameNS(xadesNamespace, XAdESConstants.TAG_QUALIFYING_PROPERTIES).getLength();
            }
            if (lenCount == 0) {
                return false;
            }
        }
        return true;
    }

    /** Comprueba que los nodos de firma usen una versi&oacute;n XAdES soportada y
     * que todos compartan la misma versi&oacute;n (no se permite mezclar
     * 1.2.2 con 1.3.2, etc.). Si la firma incluye {@code SigningCertificateV2}
     * se reporta como firma Baseline EN.
     *
     * @param signNodes Listado de nodos de firma.
     * @return {@code true} si la firma usa el perfil Baseline EN;
     *         {@code false} en caso contrario.
     * @throws AOInvalidSignatureFormatException Si la firma usa una versi&oacute;n
     *         XAdES inexistente, mezcla versiones o no se puede analizar el nodo
     *         {@code SigningCertificate}. */
    public static boolean checkCompatibility(final List<Node> signNodes) throws AOInvalidSignatureFormatException {
        boolean isBaselineENSign = false;
        final Set<String> xadesNamespaceUris = new HashSet<>();

        for (final Node signNode : signNodes) {
            final NodeList qualifyingPropsList = ((Element) signNode).getElementsByTagNameNS("*", XAdESConstants.TAG_QUALIFYING_PROPERTIES); //$NON-NLS-1$

            for (int i = 0; i < qualifyingPropsList.getLength(); i++) {
                final String namespaceUri = qualifyingPropsList.item(i).getNamespaceURI();

                boolean existingNamespace = false;
                for (final String xadesNameSpace : SUPPORTED_XADES_NAMESPACE_URIS) {
                    if (xadesNameSpace.equals(namespaceUri)) {
                        existingNamespace = true;
                        xadesNamespaceUris.add(namespaceUri);
                    }
                }
                if (!existingNamespace) {
                    throw new AOInvalidSignatureFormatException("Una de las firmas encontradas en el documento contiene una version inexistente de XAdES"); //$NON-NLS-1$
                }

                try {
                    final Node signingCertificateNode = qualifyingPropsList.item(i).getChildNodes().item(0).getChildNodes().item(0).getChildNodes().item(1);
                    final String localName = signingCertificateNode.getLocalName();
                    final String signingCertNamespaceUri = signingCertificateNode.getNamespaceURI();

                    if (XAdESConstants.TAG_SIGNING_CERTIFICATE_V2.equals(localName) && namespaceUri.equals(signingCertNamespaceUri)) {
                        isBaselineENSign = true;
                    }
                }
                catch (final Exception e) {
                    throw new AOInvalidSignatureFormatException("Error al intentar analizar el nodo SigningCertificateV2"); //$NON-NLS-1$
                }
            }

            if (xadesNamespaceUris.size() > 1) {
                throw new AOInvalidSignatureFormatException("El documento contiene firmas con distintas versiones de XAdES"); //$NON-NLS-1$
            }
        }

        return isBaselineENSign;
    }

    /** Indica si un espacio de nombres XAdES es compatible con los perfiles
     * <i>Baseline</i> (s&oacute;lo XAdES 1.3.2 y 1.4.1).
     *
     * @param xadesNamespace URL del espacio de nombres XAdES.
     * @return {@code true} si es compatible Baseline; {@code false} en caso
     *         contrario. */
    public static boolean isBaselineCompatible(final String xadesNamespace) {
        return XAdESConstants.NAMESPACE_XADES_1_3_2.equals(xadesNamespace)
                || XAdESConstants.NAMESPACE_XADES_1_4_1.equals(xadesNamespace);
    }

    /** Reconcilia el perfil declarado en {@code extraParams} con el detectado
     * en la firma a multifirmar. Si el perfil declarado no coincide y se ha
     * solicitado confirmaci&oacute;n, se muestra un di&aacute;logo al usuario;
     * en cualquier caso, deja en {@code extraParams.PROFILE} el valor final
     * efectivo ({@code SIGN_PROFILE_BASELINE} o {@code SIGN_PROFILE_ADVANCED}).
     *
     * @param extraParams Par&aacute;metros de configuraci&oacute;n de la
     *        multifirma — pueden ser modificados.
     * @param signatureIsBaselineEN Si la firma a multifirmar es Baseline EN. */
    public static void checkSignProfile(final Properties extraParams, final boolean signatureIsBaselineEN) {
        if (Boolean.TRUE.equals(extraParams.get(XAdESExtraParams.CONFIRM_DIFFERENT_PROFILE))) {
            final String profile = extraParams.getProperty(XAdESExtraParams.PROFILE, AOSignConstants.DEFAULT_SIGN_PROFILE);
            final boolean baselineENRequested = AOSignConstants.SIGN_PROFILE_BASELINE.equals(profile);
            if (signatureIsBaselineEN != baselineENRequested) {
                final int option = AOUIFactory.showConfirmDialog(
                        null,
                        XAdESMessages.getString("AOXAdESSigner.0"), //$NON-NLS-1$
                        XAdESMessages.getString("AOXAdESSigner.1"), //$NON-NLS-1$
                        AOUIFactory.YES_NO_OPTION,
                        AOUIFactory.WARNING_MESSAGE);

                if (option == 0) {
                    extraParams.put(XAdESExtraParams.PROFILE, signatureIsBaselineEN
                            ? AOSignConstants.SIGN_PROFILE_BASELINE
                            : AOSignConstants.SIGN_PROFILE_ADVANCED);
                }
            }
        }
        else {
            extraParams.put(XAdESExtraParams.PROFILE, signatureIsBaselineEN
                    ? AOSignConstants.SIGN_PROFILE_BASELINE
                    : AOSignConstants.SIGN_PROFILE_ADVANCED);
        }
    }

}
