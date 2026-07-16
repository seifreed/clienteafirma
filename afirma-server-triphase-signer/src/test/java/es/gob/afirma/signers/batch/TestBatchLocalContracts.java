package es.gob.afirma.signers.batch;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.signers.batch.SingleSignConstants.DigestAlgorithm;
import es.gob.afirma.signers.batch.SingleSignConstants.SignFormat;
import es.gob.afirma.signers.batch.SingleSignConstants.SignSubOperation;
import es.gob.afirma.signers.batch.json.PreprocessResult;
import es.gob.afirma.signers.batch.json.ResultSingleSign;
import es.gob.afirma.signers.batch.json.SaveDataException;

/** Pruebas locales del almacenamiento temporal de lotes. */
public final class TestBatchLocalContracts {

	/** Comprueba almacenamiento temporal real y resultados de proceso. */
	@Test
	public void testTempStoreAndProcessResult() throws Exception {
		final TempStore tempStore = TempStoreFactory.getTempStore();
		final byte[] data = "firma".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
		tempStore.store(data, "afirma-test-temp.bin"); //$NON-NLS-1$
		Assert.assertArrayEquals(data, tempStore.retrieve("afirma-test-temp.bin")); //$NON-NLS-1$
		tempStore.delete("afirma-test-temp.bin"); //$NON-NLS-1$

		final SingleSign sign = new SingleSign();
		sign.id = "sign-1"; //$NON-NLS-1$
		tempStore.store(data, sign, "batch-1"); //$NON-NLS-1$
		Assert.assertArrayEquals(data, tempStore.retrieve(sign, "batch-1")); //$NON-NLS-1$
		tempStore.delete(sign, "batch-1"); //$NON-NLS-1$

		final ProcessResult result = new ProcessResult(ProcessResult.Result.DONE_AND_SAVED, "ok"); //$NON-NLS-1$
		result.setId("sign-1"); //$NON-NLS-1$
		Assert.assertTrue(result.wasSaved());
		Assert.assertTrue(result.isFinished());
		Assert.assertEquals("sign-1", result.getId()); //$NON-NLS-1$
		Assert.assertEquals("ok", result.getDescription()); //$NON-NLS-1$
		Assert.assertEquals(ProcessResult.Result.DONE_AND_SAVED, result.getResult());
		Assert.assertFalse(ProcessResult.PROCESS_RESULT_OK_UNSAVED.isFinished());

		try {
			new ProcessResult(null, null);
			Assert.fail("Se esperaba rechazo de resultado nulo"); //$NON-NLS-1$
		}
		catch (final IllegalArgumentException e) {
			// Esperado
		}

		final Exception cause = new Exception("causa"); //$NON-NLS-1$
		Assert.assertEquals("batch", new BatchException("batch").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertSame(cause, new BatchException("batch", cause).getCause()); //$NON-NLS-1$
		Assert.assertEquals("200410", BatchServiceErrorCode.Internal.INTERNAL_JSON_BATCH_ERROR.getCode()); //$NON-NLS-1$
	}

	/** Comprueba contratos locales de firmas individuales y DTOs JSON. */
	@Test
	public void testSingleSignConstantsAndJsonDtos() throws Exception {
		Assert.assertSame(SignSubOperation.SIGN, SignSubOperation.getSubOperation("SIGN")); //$NON-NLS-1$
		Assert.assertSame(SignSubOperation.COSIGN, SignSubOperation.getSubOperation("cosign")); //$NON-NLS-1$
		Assert.assertSame(SignSubOperation.COUNTERSIGN, SignSubOperation.getSubOperation("countersign")); //$NON-NLS-1$
		Assert.assertEquals("sign", SignSubOperation.SIGN.toString()); //$NON-NLS-1$
		assertIllegalArgument(() -> SignSubOperation.getSubOperation("bad")); //$NON-NLS-1$

		Assert.assertSame(SignFormat.CADES, SignFormat.getFormat(AOSignConstants.SIGN_FORMAT_CADES));
		Assert.assertSame(SignFormat.CADES_ASIC, SignFormat.getFormat(AOSignConstants.SIGN_FORMAT_CADES_ASIC_S));
		Assert.assertSame(SignFormat.XADES, SignFormat.getFormat(AOSignConstants.SIGN_FORMAT_XADES));
		Assert.assertSame(SignFormat.XADES_ASIC, SignFormat.getFormat(AOSignConstants.SIGN_FORMAT_XADES_ASIC_S));
		Assert.assertSame(SignFormat.PADES, SignFormat.getFormat(AOSignConstants.SIGN_FORMAT_PADES));
		Assert.assertSame(SignFormat.FACTURAE, SignFormat.getFormat(AOSignConstants.SIGN_FORMAT_FACTURAE));
		Assert.assertSame(SignFormat.PKCS1, SignFormat.getFormat(AOSignConstants.SIGN_FORMAT_PKCS1));
		Assert.assertEquals(AOSignConstants.SIGN_FORMAT_CADES, SignFormat.CADES.toString());
		assertIllegalArgument(() -> SignFormat.getFormat(null));

		Assert.assertSame(DigestAlgorithm.SHA1, DigestAlgorithm.getAlgorithm("SHA1withRSA")); //$NON-NLS-1$
		Assert.assertSame(DigestAlgorithm.SHA256, DigestAlgorithm.getAlgorithm("SHA256withECDSA")); //$NON-NLS-1$
		Assert.assertSame(DigestAlgorithm.SHA384, DigestAlgorithm.getAlgorithm(AOSignConstants.DIGEST_ALGORITHM_SHA384));
		Assert.assertSame(DigestAlgorithm.SHA512, DigestAlgorithm.getAlgorithm(AOSignConstants.DIGEST_ALGORITHM_SHA512));
		Assert.assertEquals(AOSignConstants.DIGEST_ALGORITHM_SHA256, DigestAlgorithm.SHA256.toString());
		assertIllegalArgument(() -> DigestAlgorithm.getAlgorithm("MD5")); //$NON-NLS-1$

		final SingleSign sign = new SingleSign();
		sign.id = "id-1"; //$NON-NLS-1$
		sign.setDataRef("data"); //$NON-NLS-1$
		sign.setFormat(SignFormat.CADES);
		sign.setSubOperation(SignSubOperation.SIGN);
		final Properties extraParams = new Properties();
		sign.setExtraParams(extraParams);
		Assert.assertEquals("id-1", sign.getId()); //$NON-NLS-1$
		Assert.assertEquals("data", sign.getDataRef()); //$NON-NLS-1$
		Assert.assertSame(SignFormat.CADES, sign.getSignFormat());
		Assert.assertSame(SignSubOperation.SIGN, sign.getSubOperation());
		Assert.assertEquals("id-1", sign.getExtraParams().getProperty("SignatureId")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals("id-1", sign.getProcessResult().getId()); //$NON-NLS-1$

		final ResultSingleSign result = new ResultSingleSign("id-1", true, ProcessResult.PROCESS_RESULT_OK_UNSAVED); //$NON-NLS-1$
		Assert.assertEquals("id-1", result.getId()); //$NON-NLS-1$
		Assert.assertTrue(result.isCorrect());
		Assert.assertSame(ProcessResult.PROCESS_RESULT_OK_UNSAVED, result.getResult());
		Assert.assertSame(result, new PreprocessResult(result).getSignResult());
		Assert.assertNull(new PreprocessResult(result).getPresign());
		Assert.assertNull(new PreprocessResult((es.gob.afirma.core.signers.TriphaseData) null).getSignResult());

		final Exception cause = new Exception("causa"); //$NON-NLS-1$
		final SaveDataException saveError = new SaveDataException("save", cause); //$NON-NLS-1$
		Assert.assertEquals("save", saveError.getMessage()); //$NON-NLS-1$
		Assert.assertSame(cause, saveError.getCause());

		final Properties xadesExplicit = new Properties();
		xadesExplicit.setProperty("mode", AOSignConstants.SIGN_MODE_EXPLICIT); //$NON-NLS-1$
		Assert.assertTrue(LegacyFunctions.isXadesExplicitConfigurated(AOSignConstants.SIGN_FORMAT_XADES, xadesExplicit));
		Assert.assertFalse(LegacyFunctions.isXadesExplicitConfigurated(AOSignConstants.SIGN_FORMAT_CADES, xadesExplicit));
		Assert.assertFalse(LegacyFunctions.isXadesExplicitConfigurated(AOSignConstants.SIGN_FORMAT_XADES, new Properties()));
		Assert.assertFalse(LegacyFunctions.isXadesExplicitConfigurated(null, xadesExplicit));

		Assert.assertNotNull(new BatchServiceErrorCode());
		Assert.assertNotNull(new BatchServiceErrorCode.Internal());
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
