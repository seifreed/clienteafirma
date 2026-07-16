package es.gob.afirma.signers.batch.json;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.TriphaseData;
import es.gob.afirma.core.signers.TriphaseData.TriSign;
import es.gob.afirma.signers.batch.ProcessResult;
import es.gob.afirma.signers.batch.ProcessResult.Result;
import es.gob.afirma.signers.batch.SingleSignConstants;

/** Pruebas locales de contratos JSON de lote. */
public final class TestJsonBatchContracts {

	/** Comprueba parseo y serializaci&oacute;n local sin ejecutar firmas. */
	@Test
	public void testJsonBatchLocalContracts() throws Exception {
		final JSONSignBatchConcurrent batch = new JSONSignBatchConcurrent(dataBatchJson());
		Assert.assertEquals("CAdES", AOUtil.base642Properties(batch.getExtraParams()).getProperty("format")); //$NON-NLS-1$ //$NON-NLS-2$
		batch.setExtraParams("otras"); //$NON-NLS-1$
		Assert.assertEquals("otras", batch.getExtraParams()); //$NON-NLS-1$
		final String id = batch.getId();
		batch.setId(null);
		Assert.assertEquals(id, batch.getId());
		batch.setId("batch1"); //$NON-NLS-1$
		Assert.assertEquals("batch1", batch.getId()); //$NON-NLS-1$
		Assert.assertEquals("SHA256", batch.getSignAlgorithm().getName()); //$NON-NLS-1$
		Assert.assertTrue(batch.toString().contains("singlesigns")); //$NON-NLS-1$

		assertIllegalArgument(() -> new JSONSignBatchConcurrent(null));
		assertRuntime(() -> new JSONSignBatchConcurrent("{".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
		assertRuntime(() -> new JSONSignBatchConcurrent("{\"singlesigns\":[{\"id\":\"s1\"}]}".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
		assertIllegalArgument(() -> batch.doPostBatch(null, null));

		final JSONObject signResult = JSONSignBatch.buildSignResult("s\\\"1", Result.ERROR_PRE, new Exception("fallo \"x\"")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals("s\\\"1", signResult.getString("id")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals(Result.ERROR_PRE.name(), signResult.getString("result")); //$NON-NLS-1$
		Assert.assertEquals("fallo \"x\"", signResult.getString("description")); //$NON-NLS-1$ //$NON-NLS-2$

		final JSONObject preBatch = JSONSignBatch.buildPreBatch(
			"CAdES", //$NON-NLS-1$
			new JSONArray().put(new JSONObject().put("signinfo", new JSONArray())), //$NON-NLS-1$
			new JSONArray().put(signResult)
		);
		Assert.assertTrue(preBatch.has("td")); //$NON-NLS-1$
		Assert.assertTrue(preBatch.has("results")); //$NON-NLS-1$

		final ProcessResult processResult = new ProcessResult(Result.ERROR_POST, "error \\ \"grave\""); //$NON-NLS-1$
		processResult.setId("s1"); //$NON-NLS-1$
		Assert.assertTrue(JSONSignBatch.printProcessResult(processResult).contains("\\\\ \\\"grave\\\"")); //$NON-NLS-1$

		final JSONSignBatchConcurrent resultBatch = new JSONSignBatchConcurrent(resultBatchJson());
		Assert.assertTrue(resultBatch.getResultLog().contains("DONE_AND_SAVED")); //$NON-NLS-1$
		resultBatch.deleteAllTemps();
	}

	/** Comprueba el control de errores secuencial sin ejecutar una firma real. */
	@Test
	public void testSerialPreBatchStopsAfterFirstError() throws Exception {
		final JSONSignBatchSerial batch = new JSONSignBatchSerial(serialBatchJson());
		final JSONObject result = batch.doPreBatch(null);
		final JSONArray errors = result.getJSONArray("results"); //$NON-NLS-1$
		Assert.assertEquals(2, errors.length());
		Assert.assertEquals("s1", errors.getJSONObject(0).getString("id")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals(Result.ERROR_PRE.name(), errors.getJSONObject(0).getString("result")); //$NON-NLS-1$
		Assert.assertEquals("s2", errors.getJSONObject(1).getString("id")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals(Result.SKIPPED.name(), errors.getJSONObject(1).getString("result")); //$NON-NLS-1$
		Assert.assertFalse(result.has("td")); //$NON-NLS-1$
	}

	/** Comprueba el corte temprano de la postfirma concurrente ante datos trif&aacute;sicos incompletos. */
	@Test
	public void testConcurrentPostBatchStopsWhenTriphaseDataIsMissing() throws Exception {
		final JSONSignBatchConcurrent batch = new JSONSignBatchConcurrent(serialBatchJson());
		final String result = batch.doPostBatch(null, new TriphaseData(List.of(), "CAdES")); //$NON-NLS-1$
		final JSONObject resultJson = new JSONObject(result);
		final JSONArray signs = resultJson.getJSONArray("signs"); //$NON-NLS-1$
		Assert.assertEquals(2, signs.length());
		Assert.assertEquals("s1", signs.getJSONObject(0).getString("id")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals(Result.ERROR_PRE.name(), signs.getJSONObject(0).getString("result")); //$NON-NLS-1$
		Assert.assertEquals("s2", signs.getJSONObject(1).getString("id")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals(Result.SKIPPED.name(), signs.getJSONObject(1).getString("result")); //$NON-NLS-1$
	}

	/** Comprueba que las tareas individuales convierten errores en resultados. */
	@Test
	public void testSingleSignCallablesReturnErrors() throws Exception {
		final JSONSingleSign sign = new JSONSingleSign("s1"); //$NON-NLS-1$

		final PreprocessResult preResult = sign.getPreProcessCallable(
			null,
			SingleSignConstants.DigestAlgorithm.SHA256,
			null,
			null
		).call();
		Assert.assertNull(preResult.getPresign());
		Assert.assertEquals("s1", preResult.getSignResult().getId()); //$NON-NLS-1$
		Assert.assertFalse(preResult.getSignResult().isCorrect());
		Assert.assertEquals(Result.ERROR_PRE, preResult.getSignResult().getResult().getResult());

		final ResultSingleSign postResult = sign.getPostProcessCallable(
			null,
			null,
			SingleSignConstants.DigestAlgorithm.SHA256,
			"batch1", //$NON-NLS-1$
			null,
			null
		).call();
		Assert.assertEquals("s1", postResult.getId()); //$NON-NLS-1$
		Assert.assertFalse(postResult.isCorrect());
		Assert.assertEquals(Result.ERROR_POST, postResult.getResult().getResult());
	}

	/** Comprueba conversi&oacute;n de datos trif&aacute;sicos entre modelo y JSON. */
	@Test
	public void testTriphaseDataParserRoundtrip() {
		final TriphaseData data = new TriphaseData(
			List.of(new TriSign(Map.of("PRE", "abc", "NEED_PRE", "true"), "s1", "global1")), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
			"CAdES" //$NON-NLS-1$
		);

		final JSONObject json = TriphaseDataParser.triphaseDataToJson(data);
		Assert.assertEquals("CAdES", json.getString("format")); //$NON-NLS-1$ //$NON-NLS-2$
		final TriphaseData parsed = TriphaseDataParser.parseFromJSON(json);
		Assert.assertEquals("CAdES", parsed.getFormat()); //$NON-NLS-1$
		Assert.assertEquals("abc", parsed.getTriSign("s1").getProperty("PRE")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		Assert.assertEquals("global1", parsed.getTriSign("global1").getSignatureId()); //$NON-NLS-1$ //$NON-NLS-2$

		final JSONObject wrapped = new JSONObject()
			.put("format", "XAdES") //$NON-NLS-1$ //$NON-NLS-2$
			.put("signs", new JSONArray().put(new JSONObject().put("signinfo", json.getJSONArray("signinfo")))); //$NON-NLS-1$ //$NON-NLS-2$
		final TriphaseData parsedWrapped = TriphaseDataParser.parseFromJSON(wrapped.toString().getBytes(StandardCharsets.UTF_8));
		Assert.assertEquals("XAdES", parsedWrapped.getFormat()); //$NON-NLS-1$
		Assert.assertEquals("true", parsedWrapped.getTriSign("s1").getProperty("NEED_PRE")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
	}

	private static byte[] dataBatchJson() throws Exception {
		final Properties extra = new Properties();
		extra.setProperty("format", "CAdES"); //$NON-NLS-1$ //$NON-NLS-2$
		final String encodedExtra = AOUtil.properties2Base64(extra);
		final String json = "{\"stoponerror\":true,\"algorithm\":\"SHA256withRSA\",\"format\":\"CAdES\",\"suboperation\":\"sign\"," //$NON-NLS-1$
			+ "\"extraparams\":\"" + encodedExtra + "\",\"singlesigns\":[{\"id\":\"s1\",\"datareference\":\"doc1\"}]}"; //$NON-NLS-1$ //$NON-NLS-2$
		return json.getBytes(StandardCharsets.UTF_8);
	}

	private static byte[] resultBatchJson() {
		return "{\"singlesigns\":[{\"id\":\"s1\",\"result\":\"DONE_AND_SAVED\",\"description\":\"ok\"}]}".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
	}

	private static byte[] serialBatchJson() {
		final String json = "{\"stoponerror\":true,\"algorithm\":\"SHA256withRSA\",\"format\":\"CAdES\",\"suboperation\":\"sign\"," //$NON-NLS-1$
			+ "\"singlesigns\":[{\"id\":\"s1\",\"datareference\":\"doc1\"},{\"id\":\"s2\",\"datareference\":\"doc2\"}]}"; //$NON-NLS-1$
		return json.getBytes(StandardCharsets.UTF_8);
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

	private static void assertRuntime(final ThrowingRunnable runnable) throws Exception {
		try {
			runnable.run();
			Assert.fail("Se esperaba RuntimeException"); //$NON-NLS-1$
		}
		catch (final RuntimeException e) {
			// Esperado
		}
	}

	private interface ThrowingRunnable {
		void run() throws Exception;
	}
}
