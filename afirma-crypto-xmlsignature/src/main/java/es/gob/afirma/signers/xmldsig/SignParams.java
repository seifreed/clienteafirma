/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.signers.xmldsig;

import java.net.URI;
import java.util.Properties;

/**
 * Parámetros inmutables parseados al inicio de {@link AOXMLDSigSigner#sign}.
 *
 * <p>Agrupa los 17 valores extraídos de las {@link Properties} de entrada
 * (formato, modo, algoritmos, banderas booleanas, URI externa, identificadores
 * de contenido y estilo, etc.) y los entrega como un único contenedor
 * inmutable a las fases posteriores del flujo de firma. Su único productor es
 * {@code AOXMLDSigSigner#validateAndParseParams}.</p>
 *
 * <p>Los campos {@code initialMimeType} e {@code initialEncoding} llevan el
 * prefijo {@code initial} porque {@code sign()} los desempaqueta en variables
 * locales mutables que las fases IMPLICIT/EXPLICIT pueden sobrescribir según
 * el contenido detectado en los datos de entrada.</p>
 */
record SignParams(
        String algoUri,
        String format,
        String mode,
        String digestMethodAlgorithm,
        String canonicalizationAlgorithm,
        boolean ignoreStyleSheets,
        boolean avoidBase64Transforms,
        boolean headless,
        boolean avoidXpathExtraTransformsOnEnveloped,
        String xmlSignaturePrefix,
        String initialMimeType,
        String initialEncoding,
        URI uri,
        String precalculatedHashAlgorithm,
        String contentId,
        String styleId,
        Properties extraParams) {
}
