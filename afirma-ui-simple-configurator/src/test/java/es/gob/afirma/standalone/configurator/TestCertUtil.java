package es.gob.afirma.standalone.configurator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;

import org.junit.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.standalone.configurator.CertUtil.CertPack;

/** Pruebas de las utilidades de certificados.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestCertUtil {

	/** Prueba la generaci&oacute;n del certificado y almac&eacute;n de claves.
	 * @throws Exception Cuando ocurre un error. */
	@Test
	public void testCertGeneration() throws Exception {
		final CertPack cp = CertUtil.getCertPackForLocalhostSsl("Autofirma", "654321"); //$NON-NLS-1$ //$NON-NLS-2$
		System.out.println(AOUtil.getCN((X509Certificate) cp.getCaCertificate()));
		System.out.println(AOUtil.getCN((X509Certificate) cp.getSslCertificate()));
		System.out.println();
		System.out.println();
		System.out.println(AOUtil.hexify(cp.getPkcs12(), true));

		final File sslCertFile = File.createTempFile("SSLCERT_", ".cer"); //$NON-NLS-1$ //$NON-NLS-2$
		try (final OutputStream fos = new FileOutputStream(sslCertFile)) {
			fos.write(cp.getSslCertificate().getEncoded());
		}
		System.out.println("Certificado SSL: " + sslCertFile.getAbsolutePath()); //$NON-NLS-1$

		final File sslP12File = File.createTempFile("SSLPKCS12_", ".p12"); //$NON-NLS-1$ //$NON-NLS-2$
		try (final OutputStream fos = new FileOutputStream(sslP12File)) {
				fos.write(cp.getPkcs12());
		}
		System.out.println("PKCS#12 SSL: " + sslP12File.getAbsolutePath()); //$NON-NLS-1$

		final File sslCaCertFile = File.createTempFile("CACERT_", ".cer"); //$NON-NLS-1$ //$NON-NLS-2$
		try (final OutputStream fos = new FileOutputStream(sslCaCertFile)) {
			fos.write(cp.getCaCertificate().getEncoded());
		}
		System.out.println("Certificado CA: " + sslCaCertFile.getAbsolutePath()); //$NON-NLS-1$
	}

}
