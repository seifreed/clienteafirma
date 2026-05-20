/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.signers.xmldsig;

import java.net.URI;

import org.w3c.dom.Element;

import es.gob.afirma.signers.xml.style.XmlStyle;

/**
 * Salida de la fase 2 de {@link AOXMLDSigSigner#sign} — preparación del
 * {@code dataElement}. Empaqueta los valores que las ramas IMPLICIT
 * (parseo del XML, posible fallback a Base64) y EXPLICIT (digest
 * precalculado o SHA-1 de los datos) producen para que las fases
 * siguientes los consuman.
 *
 * <p>Los campos {@code mimeType}, {@code encoding} y {@code uri} pueden
 * diferir de los valores iniciales de {@link SignParams}: la rama
 * IMPLICIT los rellena con los detectados al parsear el XML, y el
 * fallback a Base64 puede anular {@code uri} y forzar
 * {@link XMLConstants#BASE64_ENCODING}.</p>
 *
 * <p>{@code xmlStyle} se devuelve aquí porque {@link XmlStyle} es una
 * clase final con solo {@link XmlStyle#setStyleElement(Element)} como
 * setter: no se puede mutar el resto de campos in-place, así que la
 * fase 2 IMPLICIT crea una instancia nueva (via {@code XmlStyleResolver})
 * y la devuelve. La rama EXPLICIT devuelve un {@link XmlStyle} vacío.</p>
 */
record PreparedDataElement(
        Element dataElement,
        boolean isBase64,
        boolean wasEncodedToBase64,
        String mimeType,
        String encoding,
        URI uri,
        XmlStyle xmlStyle) {
}
