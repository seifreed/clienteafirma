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
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;

/** Construye el elemento {@code ds:Manifest} de una firma XAdES.
 *
 * <p>Cuando se firma con manifest, las referencias a los datos firmados no van
 * directamente dentro del {@code SignedInfo}; van dentro del {@code Manifest}
 * y el {@code SignedInfo} contiene una &uacute;nica referencia al
 * {@code Manifest}. Esto permite firmar una colecci&oacute;n de objetos
 * conjuntamente.
 *
 * <p>S&eacute;ptimo cluster extra&iacute;do de {@link XAdESUtil} en el troceo
 * de la "god class" (ver {@link XAdESSignatureTypeDetector},
 * {@link XAdESDomLookup}, {@link XAdESProfileChecks}, {@link XAdESBaseFactory},
 * {@link XAdESArchiveTimestampValidator} y
 * {@link XAdESCommitmentTypeParser}).
 *
 * <p>La clase es {@code final} y no instanciable. */
public final class XAdESManifestBuilder {

    private static final String MANIFEST_ID_PREFIX = "Manifest-"; //$NON-NLS-1$
    private static final String MANIFEST_OBJECT_ID_PREFIX = "ManifestObject-"; //$NON-NLS-1$
    private static final String MANIFEST_REFERENCE_ID_PREFIX = "Manifest"; //$NON-NLS-1$

    private XAdESManifestBuilder() {
        // No instanciable
    }

    /** Empaqueta las referencias a datos en un {@code Manifest} y deja
     * {@code referenceList} con una &uacute;nica entrada que apunta al
     * Manifest reci&eacute;n creado. El Manifest se a&ntilde;ade como
     * {@code XMLObject} a la firma.
     *
     * <p>Mutaci&oacute;n: el m&eacute;todo modifica {@code referenceList}
     * (clear + add) — preserva la sem&aacute;ntica del implementaci&oacute;n
     * hist&oacute;rica.
     *
     * @param referenceList Lista mutable de referencias a datos. Al volver,
     *        contendr&aacute; una sola entrada: la referencia al
     *        {@code Manifest}.
     * @param fac F&aacute;brica de elementos XML-DSig.
     * @param xmlSignature Firma XML avanzada a la que se a&ntilde;ade el
     *        {@code XMLObject} del Manifest.
     * @param digestMethod Algoritmo de huella para la referencia al Manifest.
     * @param canonicalizationTransform Transformaci&oacute;n de
     *        canonicalizaci&oacute;n a aplicar a la referencia al Manifest, o
     *        {@code null} si no hay.
     * @param referenceId Identificador base de la referencia (se le antepone
     *        "Manifest" para el {@code Reference}).
     * @return La misma {@code referenceList} pasada, con una sola entrada que
     *         apunta al Manifest. */
    public static List<Reference> createManifest(final List<Reference> referenceList,
            final XMLSignatureFactory fac,
            final AOXMLAdvancedSignature xmlSignature,
            final DigestMethod digestMethod,
            final Transform canonicalizationTransform,
            final String referenceId) {

        final String manifestId = MANIFEST_ID_PREFIX + UUID.randomUUID();
        final List<XMLStructure> objectContent = new LinkedList<>();
        objectContent.add(fac.newManifest(new ArrayList<>(referenceList), manifestId));

        final String manifestObjectId = MANIFEST_OBJECT_ID_PREFIX
                + UUID.nameUUIDFromBytes(referenceId.getBytes());
        xmlSignature.addXMLObject(fac.newXMLObject(objectContent, manifestObjectId, null, null));

        // Cuando se usa Manifest, el SignedInfo contiene una sola Reference: la del Manifest.
        // Las referencias originales viven dentro del Manifest, no del SignedInfo.
        final List<Transform> transforms = canonicalizationTransform != null
                ? Collections.singletonList(canonicalizationTransform)
                : new ArrayList<>(0);

        referenceList.clear();
        referenceList.add(fac.newReference(
                "#" + manifestId, //$NON-NLS-1$
                digestMethod,
                transforms,
                XAdESConstants.REFERENCE_TYPE_MANIFEST,
                MANIFEST_REFERENCE_ID_PREFIX + referenceId));

        return referenceList;
    }

}
