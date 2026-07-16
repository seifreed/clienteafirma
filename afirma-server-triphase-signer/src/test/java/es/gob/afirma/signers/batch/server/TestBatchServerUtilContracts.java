package es.gob.afirma.signers.batch.server;

import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.core.misc.Base64;

/** Pruebas locales de utilidades batch del servidor. */
public final class TestBatchServerUtilContracts {

	/** Comprueba decodificaci&oacute;n de lote y certificados reales. */
	@Test
	public void testBatchServerUtilLocalContracts() throws Exception {
		final Constructor<BatchServerUtil> constructor = BatchServerUtil.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		Assert.assertNotNull(constructor.newInstance());

		final byte[] plain = "{\"batch\":true}".getBytes(); //$NON-NLS-1$
		Assert.assertArrayEquals(plain, BatchServerUtil.getSignBatchConfig(plain));
		Assert.assertArrayEquals(plain, BatchServerUtil.getSignBatchConfig(Base64.encode(plain, true).getBytes()));
		assertIllegalArgument(() -> BatchServerUtil.getSignBatchConfig(null));

		final X509Certificate cert = loadCertificate("CERES.cer"); //$NON-NLS-1$
		final String encoded = Base64.encode(cert.getEncoded(), true);
		final X509Certificate[] certs = BatchServerUtil.getCertificates(encoded + ";" + encoded); //$NON-NLS-1$
		Assert.assertEquals(2, certs.length);
		Assert.assertArrayEquals(cert.getEncoded(), certs[0].getEncoded());
		assertIllegalArgument(() -> BatchServerUtil.getCertificates(null));
	}

	private static X509Certificate loadCertificate(final String resource) throws Exception {
		final Path certPath = Path.of("afirma-core", "src", "test", "resources", resource); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		final Path resolvedPath = Files.exists(certPath) ? certPath : Path.of("..").resolve(certPath); //$NON-NLS-1$
		try (var input = Files.newInputStream(resolvedPath)) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input); //$NON-NLS-1$
		}
	}

	private static void assertIllegalArgument(final ThrowingRunnable runnable) throws Exception {
		try {
			runnable.run();
			Assert.fail("Se esperaba IllegalArgumentException"); //$NON-NLS-1$
		}
		catch (final IllegalArgumentException e) {
			// Esperado
		}
	}

	private interface ThrowingRunnable {
		void run() throws Exception;
	}
}
