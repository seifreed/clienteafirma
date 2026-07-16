/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.sdjwt;

/** Error de verificación SD-JWT VC. */
public final class SdJwtVerificationException extends Exception {

	private static final long serialVersionUID = 1L;

	public SdJwtVerificationException(final String message) {
		super(message);
	}

	public SdJwtVerificationException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
