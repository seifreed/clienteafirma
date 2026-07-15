package es.gob.afirma.core.signers;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Pruebas de la informaci&oacute;n de sellos de tiempo. */
final class TestAOTimestampInfo {

	@Test
	@DisplayName("La informacion del sello de tiempo conserva sus datos")
	void testTimestampInfoKeepsData() throws Exception {
		final X509Certificate issuer = loadCertificate("MDEF01.cer"); //$NON-NLS-1$
		final Date date = new Date();

		final AOTimestampInfo timestampInfo = new AOTimestampInfo(issuer, date);
		final X509Certificate returnedIssuer = timestampInfo.getIssuer();
		final Date returnedDate = timestampInfo.getDate();

		assertNotNull(returnedIssuer);
		assertArrayEquals(issuer.getEncoded(), returnedIssuer.getEncoded());
		assertNotSame(date, returnedDate);
		assertEquals(date, returnedDate);
	}

	private static X509Certificate loadCertificate(final String certName) throws Exception {
		final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		try (
			final InputStream is = ClassLoader.getSystemResourceAsStream(certName)
		) {
			return (X509Certificate) cf.generateCertificate(is);
		}
	}
}
