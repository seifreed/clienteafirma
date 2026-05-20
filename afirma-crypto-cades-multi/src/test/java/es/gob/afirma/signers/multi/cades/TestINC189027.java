package es.gob.afirma.signers.multi.cades;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import es.gob.afirma.core.AOFormatFileException;
import es.gob.afirma.core.SigningLTSException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.signers.cades.AOCAdESSigner;

/** Prueba asociada a la incidencia #189027 de contrafirma de una firma CAdES-T. */
public class TestINC189027 {

	private static final String FILE_CADES_T = "189027_CAdES-T.csig"; //$NON-NLS-1$
	private static final String FILE_CADES_A = "cadesA.csig"; //$NON-NLS-1$

	private static final String PKCS12_KEYSTORE = "ANCERTCCP_FIRMA.p12"; //$NON-NLS-1$
	private static final String PWD = "1111"; //$NON-NLS-1$

	private static InputStream ksIs;
	private static KeyStore ks;

	/** Carga el almac&eacute;n de certificados.
	 * @throws Exception Cuando ocurre algun problema al cargar el almac&eacute;n o los datos. */
	@Before
	public void cargaAlmacen() throws Exception {
		ksIs = getClass().getClassLoader().getResourceAsStream(PKCS12_KEYSTORE);
		ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		ks.load(ksIs, PWD.toCharArray());
	}

	/** Prueba de contrafirma de una firma CAdES-T.
	 * @throws Exception Cuando ocurre un error. */
	@Test
	public void testContrafirmaCAdEST() throws Exception {
		final byte[] signature;
		try (
			final InputStream is = getClass().getClassLoader().getResourceAsStream(FILE_CADES_T);
		) {
			signature = AOUtil.getDataFromInputStream(is);
		}

		final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(ks.aliases().nextElement(), new KeyStore.PasswordProtection(PWD.toCharArray()));

		final Properties config = new Properties();
		final AOCAdESSigner signer = new AOCAdESSigner();

		try {
			final byte[] countersign = signer.countersign(
				signature,
				AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA,
				CounterSignTarget.TREE,
				null,
				pke.getPrivateKey(),
				pke.getCertificateChain(),
				config
			);
			Assert.assertNotNull("La contrafirma CAdES-T no debe ser nula", countersign); //$NON-NLS-1$
			Assert.assertTrue("La contrafirma CAdES-T debe tener contenido", countersign.length > 0); //$NON-NLS-1$
		}
		catch(final AOFormatFileException e) {
			Assert.fail("La contrafirmas de firmas CAdES-T debe estar soportada: " + e); //$NON-NLS-1$
		}
	}

	/** Prueba de cofirma de una firma CAdES-T.
	 * @throws Exception Cuando ocurre un error. */
	@Test
	public void testCofirmaCAdEST() throws Exception {
		final byte[] signature;
		try (
			final InputStream is = getClass().getClassLoader().getResourceAsStream(FILE_CADES_T);
		) {
			signature = AOUtil.getDataFromInputStream(is);
		}

		final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(ks.aliases().nextElement(), new KeyStore.PasswordProtection(PWD.toCharArray()));

		final Properties config = new Properties();
		final AOCAdESSigner signer = new AOCAdESSigner();

		try {
			final byte[] cosign = signer.cosign(
				AOUtil.getDataFromInputStream(TestINC189027.class.getResourceAsStream("/Original.pdf")), //$NON-NLS-1$
				signature,
				AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA,
				pke.getPrivateKey(),
				pke.getCertificateChain(),
				config
			);
			Assert.assertNotNull("La cofirma CAdES-T no debe ser nula", cosign); //$NON-NLS-1$
			Assert.assertTrue("La cofirma CAdES-T debe tener contenido", cosign.length > 0); //$NON-NLS-1$
		}
		catch(final AOFormatFileException e) {
			Assert.fail("Deberia haber cofirmado correctamente la firmas CAdES-T: " + e); //$NON-NLS-1$
		}
	}

	/** Cierra el flujo de lectura del almac&eacute;n de certificados.
	 * @throws IOException Cuando ocurre alg&uacute;n problema al cerrar el flujo de datos. */
	@After
	public void cerrar() throws IOException {
		ksIs.close();
	}

	/** Prueba de contrafirma de una firma CAdES-A.
	 * @throws Exception Cuando ocurre un error. */
	@Test
	public void testContrafirmaCAdESA() throws Exception {
		final byte[] signature;
		try (
			final InputStream is = getClass().getClassLoader().getResourceAsStream(FILE_CADES_A);
		) {
			signature = AOUtil.getDataFromInputStream(is);
		}

		final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(ks.aliases().nextElement(), new KeyStore.PasswordProtection(PWD.toCharArray()));

		final Properties config = new Properties();
		final AOCAdESSigner signer = new AOCAdESSigner();

		try {
			signer.countersign(
				signature,
				AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA,
				CounterSignTarget.TREE,
				null,
				pke.getPrivateKey(),
				pke.getCertificateChain(),
				config
			);
		}
		catch(final SigningLTSException e) {
			return;
		}

		Assert.fail("Deberia haber saltado un SigningLTSException al contrafirmar CAdES-A"); //$NON-NLS-1$
	}

	/** Prueba de cofirma de una firma CAdES-A.
	 * @throws Exception Cuando ocurre un error. */
	@Test
	public void testCofirmaCAdESA() throws Exception {
		final byte[] signature;
		try (
			final InputStream is = getClass().getClassLoader().getResourceAsStream(FILE_CADES_A);
		) {
			signature = AOUtil.getDataFromInputStream(is);
		}

		final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(ks.aliases().nextElement(), new KeyStore.PasswordProtection(PWD.toCharArray()));

		final Properties config = new Properties();
		final AOCAdESSigner signer = new AOCAdESSigner();

		try {
			signer.cosign(
				signature,
				AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA,
				pke.getPrivateKey(),
				pke.getCertificateChain(),
				config
			);
		}
		catch(final SigningLTSException e) {
			return;
		}

		Assert.fail("Deberia haber saltado un SigningLTSException al cofirmar CAdES-A"); //$NON-NLS-1$
	}
}
