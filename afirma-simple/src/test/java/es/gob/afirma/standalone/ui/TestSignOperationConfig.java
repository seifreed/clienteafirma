package es.gob.afirma.standalone.ui;

import java.io.File;
import java.util.List;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.SignValidity.SIGN_DETAIL_TYPE;
import es.gob.afirma.signvalidation.SignValidity.VALIDITY_ERROR;
import es.gob.afirma.standalone.ui.SignOperationConfig.CryptoOperation;

/** Pruebas de contrato local de configuracion de firma. */
public final class TestSignOperationConfig {

	/** Comprueba valores, propiedades y clonacion. */
	@Test
	public void testConfigCloneKeepsIndependentProperties() {
		final SignOperationConfig config = new SignOperationConfig();
		Assert.assertEquals(FileType.BINARY, config.getFileType());
		Assert.assertEquals(CryptoOperation.SIGN, config.getCryptoOperation());
		Assert.assertNull(config.getExtraParams());

		final File dataFile = new File("datos.txt"); //$NON-NLS-1$
		final File signatureFile = new File("firma.csig"); //$NON-NLS-1$
		config.setFileType(FileType.PDF);
		config.setDataFile(dataFile);
		config.setSignatureFile(signatureFile);
		config.setCryptoOperation(CryptoOperation.COUNTERSIGN_TREE);
		config.setSignatureFormatName("CAdES"); //$NON-NLS-1$
		config.setInvalidSignatureText("invalida"); //$NON-NLS-1$
		config.setDigestAlgorithm("SHA-256"); //$NON-NLS-1$
		config.setSignValidity(List.of(new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.NO_MATCH_DATA)));

		final Properties params = new Properties();
		params.setProperty("mode", "implicit"); //$NON-NLS-1$ //$NON-NLS-2$
		config.setExtraParams(params);
		config.addExtraParam("format", "CAdES"); //$NON-NLS-1$ //$NON-NLS-2$
		config.addExtraParams(null);

		final SignOperationConfig copy = config.clone();
		Assert.assertEquals(FileType.PDF, copy.getFileType());
		Assert.assertEquals(dataFile, copy.getDataFile());
		Assert.assertEquals(signatureFile, copy.getSignatureFile());
		Assert.assertEquals(CryptoOperation.COUNTERSIGN_TREE, copy.getCryptoOperation());
		Assert.assertEquals("CAdES", copy.getSignatureFormatName()); //$NON-NLS-1$
		Assert.assertEquals("invalida", copy.getInvalidSignatureText()); //$NON-NLS-1$
		Assert.assertEquals("SHA-256", copy.getDigestAlgorithm()); //$NON-NLS-1$
		Assert.assertEquals("implicit", copy.getExtraParams().getProperty("mode")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals("CAdES", copy.getExtraParams().getProperty("format")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals(1, copy.getSignValidity().size());

		config.getExtraParams().setProperty("mode", "explicit"); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals("implicit", copy.getExtraParams().getProperty("mode")); //$NON-NLS-1$ //$NON-NLS-2$
		try {
			copy.getSignValidity().clear();
			Assert.fail("La lista clonada debe ser inmutable"); //$NON-NLS-1$
		}
		catch (final UnsupportedOperationException expected) {
			// Contrato esperado.
		}

		config.setExtraParams(null);
		Assert.assertTrue(config.getExtraParams().isEmpty());
	}
}
