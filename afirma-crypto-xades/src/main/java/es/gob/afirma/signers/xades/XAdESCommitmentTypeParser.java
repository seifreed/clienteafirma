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
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import es.uji.crypto.xades.jxades.security.xml.XAdES.CommitmentTypeIdImpl;
import es.uji.crypto.xades.jxades.security.xml.XAdES.CommitmentTypeIndication;
import es.uji.crypto.xades.jxades.security.xml.XAdES.CommitmentTypeIndicationImpl;

/** Parsea los {@code CommitmentTypeIndication} declarados como par&aacute;metros
 * adicionales para una firma XAdES.
 *
 * <p>Sexto cluster extra&iacute;do de {@link XAdESUtil} en el troceo de la
 * "god class" (ver {@link XAdESSignatureTypeDetector}, {@link XAdESDomLookup},
 * {@link XAdESProfileChecks}, {@link XAdESBaseFactory} y
 * {@link XAdESArchiveTimestampValidator}).
 *
 * <p>La clase es {@code final} y no instanciable. */
public final class XAdESCommitmentTypeParser {

    private static final Logger LOGGER = Logger.getLogger("es.gob.afirma"); //$NON-NLS-1$
    private static final String OID_AS_URN = "OIDAsURN"; //$NON-NLS-1$
    private static final String OID_URN_PREFIX = "urn:oid:"; //$NON-NLS-1$
    private static final String LIST_SEPARATOR_REGEX = Pattern.quote("|"); //$NON-NLS-1$

    private XAdESCommitmentTypeParser() {
        // No instanciable
    }

    /** Construye la lista de {@code CommitmentTypeIndication} a incluir en la
     * firma XAdES leyendo los par&aacute;metros adicionales.
     *
     * <p>Los par&aacute;metros relevantes son:
     * <ul>
     * <li>{@link XAdESExtraParams#COMMITMENT_TYPE_INDICATIONS}: n&uacute;mero
     *     total de indicaciones declaradas.</li>
     * <li>{@code commitmentTypeIndication<i>N</i>Identifier},
     *     {@code …Description}, {@code …DocumentationReference},
     *     {@code …CommitmentTypeQualifiers}: campos por cada indicaci&oacute;n
     *     <i>N</i> (de 0 a N).</li>
     * </ul>
     *
     * @param xParams Par&aacute;metros adicionales para la firma. Si es
     *        {@code null} o no contiene el contador, se devuelve lista vac&iacute;a.
     * @param signedDataId Identificador del nodo a firmar (Data Object), o
     *        {@code null} si no aplica.
     * @return Lista de {@link CommitmentTypeIndication}; nunca {@code null}. */
    public static List<CommitmentTypeIndication> parseCommitmentTypeIndications(final Properties xParams,
            final String signedDataId) {

        final List<CommitmentTypeIndication> result = new ArrayList<>();
        if (xParams == null) {
            return result;
        }
        final int nCtis = parseCount(xParams.getProperty(XAdESExtraParams.COMMITMENT_TYPE_INDICATIONS));
        if (nCtis < 1) {
            return result;
        }

        for (int i = 0; i <= nCtis; i++) {
            final CommitmentTypeIndication cti = parseOne(xParams, i, signedDataId);
            if (cti != null) {
                result.add(cti);
            }
        }
        return result;
    }

    private static int parseCount(final String raw) {
        if (raw == null) {
            return 0;
        }
        try {
            final int n = Integer.parseInt(raw);
            return n < 1 ? 0 : n;
        }
        catch (final NumberFormatException e) {
            LOGGER.severe("El parametro adicional 'CommitmentTypeIndications' debe contener un valor numerico entero (el valor actual es " //$NON-NLS-1$
                    + raw + "), no se anadira el CommitmentTypeIndication: " + e); //$NON-NLS-1$
            return 0;
        }
    }

    private static CommitmentTypeIndication parseOne(final Properties xParams, final int i, final String signedDataId) {
        final String prefix = XAdESExtraParams.COMMITMENT_TYPE_INDICATION_PREFIX + i;

        final String identifierKey = xParams.getProperty(prefix + XAdESExtraParams.COMMITMENT_TYPE_INDICATION_IDENTIFIER);
        if (identifierKey == null) {
            return null;
        }
        final String identifier = XAdESExtraParams.COMMITMENT_TYPE_IDENTIFIERS.get(identifierKey);
        if (identifier == null) {
            LOGGER.severe("El identificador del CommitmentTypeIndication " + i //$NON-NLS-1$
                    + " no es un tipo soportado (" + identifierKey //$NON-NLS-1$
                    + "), se omitira y se continuara con el siguiente"); //$NON-NLS-1$
            return null;
        }

        final String description = xParams.getProperty(prefix + XAdESExtraParams.COMMITMENT_TYPE_INDICATION_DESCRIPTION);
        final List<String> documentationReferences = parseUrlList(
                xParams.getProperty(prefix + XAdESExtraParams.COMMITMENT_TYPE_INDICATION_DOCUMENTATION_REFERENCE), i);
        final List<String> commitmentTypeQualifiers = parseStringList(
                xParams.getProperty(prefix + XAdESExtraParams.COMMITMENT_TYPE_INDICATION_QUALIFIERS));

        return new CommitmentTypeIndicationImpl(
                new CommitmentTypeIdImpl(
                        identifier.startsWith(OID_URN_PREFIX) ? OID_AS_URN : null,
                        identifier,
                        description,
                        new ArrayList<>(documentationReferences)),
                signedDataId != null ? "#" + signedDataId : null, //$NON-NLS-1$
                new ArrayList<>(commitmentTypeQualifiers));
    }

    private static List<String> parseUrlList(final String raw, final int ctiIndex) {
        if (raw == null) {
            return new ArrayList<>(0);
        }
        final List<String> urls = new ArrayList<>();
        for (final String candidate : raw.split(LIST_SEPARATOR_REGEX)) {
            try {
                urls.add(new URL(candidate).toString());
            }
            catch (final MalformedURLException e) {
                LOGGER.severe("La referencia documental '" + candidate //$NON-NLS-1$
                        + "' del CommitmentTypeIndication " + ctiIndex //$NON-NLS-1$
                        + " no es una URL, se omitira y se continuara con la siguiente referencia documental: " + e); //$NON-NLS-1$
            }
        }
        return urls;
    }

    private static List<String> parseStringList(final String raw) {
        if (raw == null) {
            return new ArrayList<>(0);
        }
        final List<String> result = new ArrayList<>();
        for (final String item : raw.split(LIST_SEPARATOR_REGEX)) {
            result.add(item);
        }
        return result;
    }

}
