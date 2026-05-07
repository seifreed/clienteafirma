/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

/** Error de parseo, validación o lookup en el subsistema TSL/LOTL. */
public class TslException extends Exception {

	private static final long serialVersionUID = 1L;

	public TslException(final String message) {
		super(message);
	}

	public TslException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
