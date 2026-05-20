/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.signers.xades;

import java.security.cert.X509Certificate;

import javax.xml.crypto.URIDereferencer;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.signers.xml.XMLErrorCode;
import es.uji.crypto.xades.jxades.security.xml.XAdES.SigningCertificateV2Info;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdES;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XAdESBase;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XadesWithBaselineAttributes;
import es.uji.crypto.xades.jxades.security.xml.XAdES.XadesWithBasicAttributes;

/** F&aacute;brica de instancias del modelo de objetos XAdES (jxades):
 * {@link XAdESBase} con sus atributos b&aacute;sicos o de perfil Baseline EN, y
 * {@link AOXMLAdvancedSignature} con las propiedades de firma XML avanzada
 * (tipo de propiedades firmadas, m&eacute;todo de huella, canonicalizaci&oacute;n y
 * dereferenciador de URIs).
 *
 * <p>Cuarto cluster extra&iacute;do de {@link XAdESUtil} en el troceo de la
 * "god class" (ver {@link XAdESSignatureTypeDetector}, {@link XAdESDomLookup}
 * y {@link XAdESProfileChecks}). Los dos m&eacute;todos forman un cluster
 * cohesivo: ambos construyen objetos del modelo jxades a partir de
 * par&aacute;metros del firmante.
 *
 * <p>La clase es {@code final} y no instanciable. */
public final class XAdESBaseFactory {

    private XAdESBaseFactory() {
        // No instanciable
    }

    /** Crea una nueva instancia de {@link XAdESBase} para firmar.
     *
     * @param profile Perfil de firma XAdES que se quiere generar
     *        ({@link AOSignConstants#SIGN_PROFILE_BASELINE} u otro).
     * @param xadesNamespace Espacio de nombres XAdES.
     * @param xadesSignaturePrefix Prefijo de los elementos XAdES.
     * @param xmlSignaturePrefix Prefijo de los elementos XMLDSig.
     * @param digestMethodAlgorithm Algoritmo de huella para la firma.
     * @param ownerDocument Documento sobre el que se firma.
     * @param rootSig Nodo ra&iacute;z de la firma.
     * @param signingCertificate Certificado de firma, o {@code null} si se
     *        configurar&aacute; m&aacute;s tarde.
     * @return Instancia {@link XAdESBase} con los atributos del certificado
     *         (si se provey&oacute;) seg&uacute;n el perfil detectado.
     * @throws AOException Si ocurre un error durante la composici&oacute;n de
     *         los atributos. */
    public static XAdESBase newInstance(final String profile, final String xadesNamespace, final String xadesSignaturePrefix,
            final String xmlSignaturePrefix, final String digestMethodAlgorithm, final Document ownerDocument, final Element rootSig,
            final X509Certificate signingCertificate) throws AOException {

        final XAdES xadesProfile = AOSignConstants.SIGN_PROFILE_BASELINE.equalsIgnoreCase(profile)
                ? XAdES.B_LEVEL
                : XAdES.EPES;

        final XAdESBase xades = XAdES.newInstance(
                xadesProfile,
                xadesNamespace,
                xadesSignaturePrefix,
                xmlSignaturePrefix,
                digestMethodAlgorithm,
                ownerDocument,
                rootSig);

        if (signingCertificate != null) {
            attachSigningCertificate(xades, signingCertificate);
        }
        return xades;
    }

    private static void attachSigningCertificate(final XAdESBase xades, final X509Certificate signingCertificate) {
        if (xades instanceof XadesWithBaselineAttributes) {
            // En firmas B-Level el signingCertificateV2 incluye sólo el certificado de firma
            // y no el IssuerSerialV2 — recomendación ETSI EN 319 132-1 V1.1.1 §6.3 j).
            // Aún no se soporta la generación del IssuerSerialV2 (pendiente).
            final SigningCertificateV2Info issuerInfo = null;
            ((XadesWithBaselineAttributes) xades).setSigningCertificateV2(signingCertificate, issuerInfo);
        }
        else if (xades instanceof XadesWithBasicAttributes) {
            // En firmas BES/EPES el signingCertificate incluye el certificado de firma
            // y la referencia al certificado del emisor (IssuerSerial), que se crea por
            // el propio jxades.
            ((XadesWithBasicAttributes) xades).setSigningCertificate(signingCertificate);
        }
    }

    /** Crea una {@link AOXMLAdvancedSignature} configurada con el tipo de
     * propiedades firmadas, el algoritmo de huella, el m&eacute;todo de
     * canonicalizaci&oacute;n y el dereferenciador de URIs indicados.
     *
     * @param xades Modelo {@link XAdESBase} sobre el que componer la firma.
     * @param signedPropertiesTypeUrl URL del tipo de propiedades firmadas.
     * @param digestMethodAlgorithm Algoritmo de huella para las referencias.
     * @param canonicalizationAlgorithm M&eacute;todo de canonicalizaci&oacute;n.
     * @param uriDereferencer Dereferenciador de URIs personalizado, o
     *        {@code null} para usar el por defecto.
     * @return Instancia {@link AOXMLAdvancedSignature} lista para firmar.
     * @throws AOException Si no se puede instanciar la firma o configurar el
     *         algoritmo de huella. */
    static AOXMLAdvancedSignature getXmlAdvancedSignature(final XAdESBase xades,
            final String signedPropertiesTypeUrl,
            final String digestMethodAlgorithm,
            final String canonicalizationAlgorithm,
            final URIDereferencer uriDereferencer) throws AOException {

        final AOXMLAdvancedSignature xmlSignature;
        try {
            xmlSignature = AOXMLAdvancedSignature.newInstance(xades);
        }
        catch (final Exception e) {
            throw new AOMalformedSignatureException(
                    "No se ha podido instanciar la firma XML Avanzada de JXAdES: " + e, e); //$NON-NLS-1$
        }

        xmlSignature.setSignedPropertiesTypeUrl(signedPropertiesTypeUrl);

        try {
            xmlSignature.setDigestMethod(digestMethodAlgorithm);
        }
        catch (final Exception e) {
            throw new AOException(
                    "No se ha podido establecer el algoritmo de huella digital: " + e, //$NON-NLS-1$
                    e,
                    XMLErrorCode.Request.INVALID_REFERENCES_HASH_ALGORITHM_URI);
        }

        xmlSignature.setCanonicalizationMethod(canonicalizationAlgorithm);
        xmlSignature.setUriDereferencer(uriDereferencer);

        return xmlSignature;
    }

}
