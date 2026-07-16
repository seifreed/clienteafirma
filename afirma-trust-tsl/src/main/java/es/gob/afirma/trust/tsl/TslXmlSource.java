/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import java.io.IOException;

/** Fuente de bytes XML para una TSL/LOTL. */
@FunctionalInterface
public interface TslXmlSource {

	byte[] load() throws IOException, InterruptedException;
}
