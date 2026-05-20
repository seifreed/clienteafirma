package es.gob.afirma.keystores.filters;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;

/** Pruebas del filtro de certificados por identificador de pol&iacute;tica de certificaci&oacute;n.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestPseudonymFilter {

	/** Prueba del filtro de certificados por identificador de pol&iacute;tica de certificaci&oacute;n.
	 * @throws Exception en cualquier error. */
	@Test
	public void testPolicyIdFilterMatch() throws Exception {
		final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate( //$NON-NLS-1$
			ClassLoader.getSystemResourceAsStream("pseu-000.cer") //$NON-NLS-1$
		);
		Assert.assertTrue(new PseudonymFilter().matches(cert));
	}

}
