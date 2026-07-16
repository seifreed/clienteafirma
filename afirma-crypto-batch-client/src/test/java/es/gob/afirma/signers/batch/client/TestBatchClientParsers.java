package es.gob.afirma.signers.batch.client;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.List;
import java.util.Map;

import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.signers.TriphaseData;
import es.gob.afirma.core.signers.TriphaseData.TriSign;
import es.gob.afirma.signers.batch.client.BatchDataResult.Result;

/** Pruebas locales de DTOs y parsers JSON del cliente de lotes. */
public final class TestBatchClientParsers {

	@Test
	public void testBatchDataResult() {
		final BatchDataResult saved = new BatchDataResult("s1", Result.DONE_AND_SAVED, "ok"); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals("s1", saved.getId()); //$NON-NLS-1$
		Assert.assertEquals(Result.DONE_AND_SAVED, saved.getResult());
		Assert.assertEquals("ok", saved.getDescription()); //$NON-NLS-1$
		Assert.assertTrue(saved.wasSaved());
		Assert.assertFalse(new BatchDataResult("s2", Result.ERROR_PRE, null).wasSaved()); //$NON-NLS-1$
		assertIllegalArgument(() -> new BatchDataResult(null, Result.ERROR_PRE, null));
		assertIllegalArgument(() -> new BatchDataResult("s1", null, null)); //$NON-NLS-1$
	}

	@Test
	public void testBatchInfoUpdateAndResultBuild() {
		final BatchInfo info = JSONBatchInfoParser.parse(bytes(
			"{\"singlesigns\":[{\"id\":\"s1\",\"datareference\":\"d\",\"format\":\"CAdES\",\"suboperation\":\"sign\",\"extraparams\":\"x\"},{\"id\":\"s2\"}]}" //$NON-NLS-1$
		));
		info.updateResults(List.of(
			new BatchDataResult("s1", Result.DONE_AND_SAVED, "guardado"), //$NON-NLS-1$ //$NON-NLS-2$
			new BatchDataResult("s3", Result.ERROR_PRE, null) //$NON-NLS-1$
		));
		final JSONObject updated = new JSONObject(info.getInfoString());
		final JSONObject first = updated.getJSONArray("singlesigns").getJSONObject(0); //$NON-NLS-1$
		Assert.assertEquals(Result.DONE_AND_SAVED.name(), first.getString("result")); //$NON-NLS-1$
		Assert.assertEquals("guardado", first.getString("description")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertFalse(first.has("datareference")); //$NON-NLS-1$
		Assert.assertFalse(first.has("format")); //$NON-NLS-1$
		Assert.assertFalse(first.has("suboperation")); //$NON-NLS-1$
		Assert.assertFalse(first.has("extraparams")); //$NON-NLS-1$
		Assert.assertFalse(updated.getJSONArray("singlesigns").getJSONObject(1).has("result")); //$NON-NLS-1$ //$NON-NLS-2$

		Assert.assertEquals(0, JSONBatchInfoParser.buildEmptyResult().getJSONArray("signs").length()); //$NON-NLS-1$
		final JSONObject result = JSONBatchInfoParser.buildResult(List.of(
			new BatchDataResult("s1", Result.DONE_AND_SAVED, "ok"), //$NON-NLS-1$ //$NON-NLS-2$
			new BatchDataResult("s2", Result.ERROR_PRE, null) //$NON-NLS-1$
		));
		Assert.assertEquals(2, result.getJSONArray("signs").length()); //$NON-NLS-1$
		Assert.assertFalse(result.getJSONArray("signs").getJSONObject(1).has("description")); //$NON-NLS-1$ //$NON-NLS-2$
		assertJsonException(() -> JSONBatchInfoParser.parse(bytes("{"))); //$NON-NLS-1$
	}

	@Test
	public void testPreSignBatchParser() {
		final PresignBatch presign = JSONPreSignBatchParser.parseFromJSON(bytes(
			"{\"td\":{\"format\":\"CAdES\",\"signinfo\":[{\"id\":\"s1\",\"signid\":\"g1\",\"params\":{\"PRE\":\"abc\"}}]}," //$NON-NLS-1$
			+ "\"results\":[{\"id\":\"s2\",\"result\":\"ERROR_PRE\",\"description\":\"fallo\"}]}" //$NON-NLS-1$
		));
		Assert.assertEquals("CAdES", presign.getTriphaseData().getFormat()); //$NON-NLS-1$
		Assert.assertEquals("abc", presign.getTriphaseData().getTriSign("s1").getProperty("PRE")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		Assert.assertEquals("fallo", presign.getErrors().get(0).getDescription()); //$NON-NLS-1$

		final PresignBatch empty = JSONPreSignBatchParser.parseFromJSON(bytes("{\"results\":[]}")); //$NON-NLS-1$
		Assert.assertNull(empty.getTriphaseData());
		Assert.assertNull(empty.getErrors());
		empty.setTriphaseData(presign.getTriphaseData());
		empty.setErrors(presign.getErrors());
		Assert.assertEquals("CAdES", empty.getTriphaseData().getFormat()); //$NON-NLS-1$

		assertJsonException(() -> JSONPreSignBatchParser.parseFromJSON(bytes("{"))); //$NON-NLS-1$
		assertJsonException(() -> JSONPreSignBatchParser.parseFromJSON(bytes("{\"results\":[{\"id\":\"s1\"}]}"))); //$NON-NLS-1$
		assertJsonException(() -> JSONPreSignBatchParser.parseFromJSON(bytes("{\"results\":[{\"id\":\"s1\",\"result\":\"NO\"}]}"))); //$NON-NLS-1$
	}

	@Test
	public void testTriphaseDataParser() {
		final TriphaseData grouped = TriphaseDataParser.parseFromJSON(bytes(
			"{\"format\":\"CAdES\",\"signs\":[{\"signinfo\":[{\"id\":\"s1\",\"signid\":\"g1\",\"params\":{\"PRE\":\"abc\"}}]}]}" //$NON-NLS-1$
		));
		Assert.assertEquals("CAdES", grouped.getFormat()); //$NON-NLS-1$
		Assert.assertEquals("abc", grouped.getTriSign("s1").getProperty("PRE")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

		final TriphaseData flat = TriphaseDataParser.parseFromJSON(new JSONObject(
			"{\"signinfo\":[{\"id\":\"s2\",\"params\":{\"PK1\":\"def\"}}]}" //$NON-NLS-1$
		));
		Assert.assertEquals("def", flat.getTriSign("s2").getProperty("PK1")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

		final String json = TriphaseDataParser.triphaseDataToJsonString(new TriphaseData(
			List.of(new TriSign(Map.of("PRE", "abc"), "s1", "g1")), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
			"CAdES" //$NON-NLS-1$
		));
		Assert.assertEquals("CAdES", new JSONObject(json).getString("format")); //$NON-NLS-1$ //$NON-NLS-2$

		final Map<String, String> params = TriphaseDataParser.parseParamsListJson(bytes(
			"{\"params\":[{\"k\":\"a\",\"v\":\"b%20c\"},{\"k\":\"ignored\"}]}" //$NON-NLS-1$
		));
		Assert.assertEquals("b c", params.get("a")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	@Test
	public void testBatchErrorCodesAreLoaded() {
		Assert.assertEquals("300601", BatchErrorCode.ThirdParty.JSON_BATCH_PRESIGN_ERROR.getCode()); //$NON-NLS-1$
		Assert.assertEquals("300602", BatchErrorCode.ThirdParty.JSON_BATCH_POSTSIGN_ERROR.getCode()); //$NON-NLS-1$
		Assert.assertEquals("401500", BatchErrorCode.Communication.JSON_BATCH_PRESIGN_CONNECTION_ERROR.getCode()); //$NON-NLS-1$
		Assert.assertEquals("401802", BatchErrorCode.Communication.XML_BATCH_POSTSIGN_TIMEOUT.getCode()); //$NON-NLS-1$
		Assert.assertEquals("600419", BatchErrorCode.Request.MALFORMED_JSON_BATCH.getCode()); //$NON-NLS-1$
		Assert.assertEquals("600503", BatchErrorCode.Request.MALFORMED_XML_BATCH.getCode()); //$NON-NLS-1$
		Assert.assertNotNull(new BatchErrorCode());
		Assert.assertNotNull(new BatchErrorCode.ThirdParty());
		Assert.assertNotNull(new BatchErrorCode.Communication());
		Assert.assertNotNull(new BatchErrorCode.Request());
	}

	@Test
	public void testBatchSignerConstructorIsPrivateButReachableForCoverage() throws Exception {
		final Constructor<BatchSigner> constructor = BatchSigner.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		Assert.assertNotNull(constructor.newInstance());
	}

	@Test
	public void testBatchSignerLocalValidation() throws Exception {
		final Certificate[] certs = { loadCertificate() };
		assertIllegalArgument(() -> BatchSigner.signXML(null, "pre", "post", certs, null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertIllegalArgument(() -> BatchSigner.signXML(new byte[0], "pre", "post", certs, null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertIllegalArgument(() -> BatchSigner.signXML(bytes("<signbatch algorithm=\"SHA256\"/>"), "", "post", certs, null)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertIllegalArgument(() -> BatchSigner.signXML(bytes("<signbatch algorithm=\"SHA256\"/>"), "pre", "", certs, null)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertIllegalArgument(() -> BatchSigner.signXML(bytes("<signbatch algorithm=\"SHA256\"/>"), "pre", "post", null, null)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertBatchError(
			BatchErrorCode.Request.MALFORMED_XML_BATCH.getCode(),
			() -> BatchSigner.signXML(bytes("<root/>"), "pre", "post", certs, null) //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		);

		assertIllegalArgument(() -> BatchSigner.signJSON(null, "pre", "post", certs, null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertIllegalArgument(() -> BatchSigner.signJSON(new byte[0], "pre", "post", certs, null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertIllegalArgument(() -> BatchSigner.signJSON(bytes("{\"algorithm\":\"SHA256\"}"), "", "post", certs, null)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertIllegalArgument(() -> BatchSigner.signJSON(bytes("{\"algorithm\":\"SHA256\"}"), "pre", "", certs, null)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertIllegalArgument(() -> BatchSigner.signJSON(bytes("{\"algorithm\":\"SHA256\"}"), "pre", "post", null, null)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertBatchError(
			BatchErrorCode.Request.MALFORMED_JSON_BATCH.getCode(),
			() -> BatchSigner.signJSON(bytes("{"), "pre", "post", certs, null) //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		);
	}

	private static byte[] bytes(final String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	private static Certificate loadCertificate() throws Exception {
		final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		try (InputStream is = Files.newInputStream(Path.of("../afirma-core/src/test/resources/CERES.cer"))) { //$NON-NLS-1$
			return cf.generateCertificate(is);
		}
	}

	private static void assertIllegalArgument(final ThrowingRunnable runnable) {
		try {
			runnable.run();
			Assert.fail("Se esperaba IllegalArgumentException"); //$NON-NLS-1$
		}
		catch (final IllegalArgumentException expected) {
			// Validacion esperada.
		}
		catch (final Exception e) {
			Assert.fail("Excepcion inesperada: " + e); //$NON-NLS-1$
		}
	}

	private static void assertJsonException(final ThrowingRunnable runnable) {
		try {
			runnable.run();
			Assert.fail("Se esperaba JSONException"); //$NON-NLS-1$
		}
		catch (final org.json.JSONException expected) {
			// JSON invalido esperado.
		}
		catch (final Exception e) {
			Assert.fail("Excepcion inesperada: " + e); //$NON-NLS-1$
		}
	}

	private static void assertBatchError(final String code, final ThrowingRunnable runnable) {
		try {
			runnable.run();
			Assert.fail("Se esperaba AOException"); //$NON-NLS-1$
		}
		catch (final AOException expected) {
			Assert.assertEquals(code, expected.getErrorCode().getCode());
		}
		catch (final Exception e) {
			Assert.fail("Excepcion inesperada: " + e); //$NON-NLS-1$
		}
	}

	private interface ThrowingRunnable {
		void run() throws Exception;
	}
}
