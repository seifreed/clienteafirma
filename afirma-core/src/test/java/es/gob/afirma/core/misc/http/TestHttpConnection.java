package es.gob.afirma.core.misc.http;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

/** Prueba de las conexiones HTTP y HTTPS. */
public final class TestHttpConnection {

	/** Prueba la conexi&oacute;n Https con un certificado no reconocido por Java.
	 * @throws IOException En cualquier error. */
	@Test
	public void testHttpsConnection() throws IOException {
		Assume.assumeTrue("Test omitido: requiere -Dafirma.it.network=true (conectividad a valide.redsara.es)", //$NON-NLS-1$
				Boolean.getBoolean("afirma.it.network")); //$NON-NLS-1$

		final byte[] webPage = new es.gob.afirma.core.misc.http.UrlHttpManagerImpl().readUrl(
			"https://valide.redsara.es/valide/",  //$NON-NLS-1$
			UrlHttpMethod.GET
		);
		Assert.assertNotNull(webPage);
	}
}
