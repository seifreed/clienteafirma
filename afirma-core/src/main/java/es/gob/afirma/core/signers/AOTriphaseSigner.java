package es.gob.afirma.core.signers;

import es.gob.afirma.core.misc.http.UrlHttpManager;

public abstract class AOTriphaseSigner implements AOSigner {

	protected int httpReadTimeout = UrlHttpManager.DEFAULT_TIMEOUT;

	/**
	 * Establece el tiempo de espera de lectura que debe usar para conectar
	 * con el servicio de firma trif&aacute;sica.
	 * @param readTimeout Tiempo de espera de lectura.
	 */
	public void setHttpReadTimeout(final int readTimeout) {
		this.httpReadTimeout = readTimeout;
	}
}
