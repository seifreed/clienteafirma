package es.gob.afirma.standalone.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.core.SignaturePolicyIncompatibilityException;
import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.core.misc.protocol.ProtocolVersion;
import es.gob.afirma.core.misc.protocol.ParameterException;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AOTriphaseException;
import es.gob.afirma.standalone.SimpleErrorCode;
import es.gob.afirma.standalone.plugins.SignOperation.Operation;
import es.gob.afirma.standalone.protocol.LocalBatchSigner.LocalSingleBatchResult;

/** Pruebas locales de utilidades del lanzador de protocolo. */
final class TestProtocolInvocationLauncherUtil {

	/** Comprueba reconstrucci&oacute;n de excepciones trif&aacute;sicas y detecci&oacute;n de formato local. */
	@Test
	void reconstructsInternalExceptionsAndIdentifiesSignFormat() throws Exception {
		final AOTriphaseException runtimeConfig = AOTriphaseException.parsePresignException(
			"ERR-1", //$NON-NLS-1$
			"politica", //$NON-NLS-1$
			SignaturePolicyIncompatibilityException.class.getName()
		);
		assertSame(runtimeConfig, ProtocolInvocationLauncherUtil.getInternalException(runtimeConfig));

		final AOTriphaseException unknown = AOTriphaseException.parsePresignException(
			"ERR-1", //$NON-NLS-1$
			"desconocida", //$NON-NLS-1$
			"no.existe.Excepcion" //$NON-NLS-1$
		);
		assertSame(unknown, ProtocolInvocationLauncherUtil.getInternalException(unknown));

		final AOTriphaseException notRuntimeConfig = AOTriphaseException.parsePresignException(
			"ERR-1", //$NON-NLS-1$
			"simple", //$NON-NLS-1$
			IllegalArgumentException.class.getName()
		);
		assertSame(notRuntimeConfig, ProtocolInvocationLauncherUtil.getInternalException(notRuntimeConfig));

		assertEquals(
			AOSignConstants.SIGN_FORMAT_PADES,
			ProtocolInvocationLauncherUtil.identifyFormatFromData(
				Files.readAllBytes(Path.of("../afirma-crypto-pdf/src/test/resources/TEST_PDF.pdf")), //$NON-NLS-1$
				Operation.SIGN
			)
		);
		assertEquals(AOSignConstants.SIGN_FORMAT_XADES, ProtocolInvocationLauncherUtil.identifyFormatFromData("<root/>".getBytes(), Operation.SIGN)); //$NON-NLS-1$
		assertEquals(AOSignConstants.SIGN_FORMAT_CADES, ProtocolInvocationLauncherUtil.identifyFormatFromData("texto".getBytes(), Operation.SIGN)); //$NON-NLS-1$
		assertThrows(
			NullPointerException.class,
			() -> ProtocolInvocationLauncherUtil.identifyFormatFromData("texto".getBytes(), Operation.COSIGN) //$NON-NLS-1$
		);

		final ProtocolInvocationLauncherUtil.DecryptionException decryptionError =
				new ProtocolInvocationLauncherUtil.DecryptionException("descifrado", new IllegalStateException("causa")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("descifrado", decryptionError.getMessage()); //$NON-NLS-1$
		assertNotNull(decryptionError.getCause());

		final Constructor<ProtocolInvocationLauncherUtil> constructor = ProtocolInvocationLauncherUtil.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
	}

	/** Comprueba comparaciones locales de versiones del protocolo. */
	@Test
	void versionComparesNumbersAndSuffixes() {
		final Version empty = new Version(null);
		assertEquals("0", empty.toString()); //$NON-NLS-1$
		assertEquals("", empty.getAditionalText()); //$NON-NLS-1$
		empty.getVersionParts().add(Integer.valueOf(9));
		assertEquals("0", empty.toString()); //$NON-NLS-1$

		final Version stable = new Version("1.7.0"); //$NON-NLS-1$
		assertEquals("1.7.0", stable.toString()); //$NON-NLS-1$
		assertTrue(stable.greaterThan("1.6.9")); //$NON-NLS-1$
		assertFalse(stable.greaterThan("1.7.0")); //$NON-NLS-1$
		assertFalse(stable.greaterThan("1.7.0.0")); //$NON-NLS-1$
		assertTrue(new Version("1.7.0.1").greaterThan(stable)); //$NON-NLS-1$
		assertTrue(new Version("1.7a").greaterThan("1.7")); //$NON-NLS-1$ //$NON-NLS-2$
		assertFalse(new Version("1.7").greaterThan("1.7a")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(new Version("1.7b").greaterThan("1.7a")); //$NON-NLS-1$ //$NON-NLS-2$
		assertFalse(new Version("1.7A").greaterThan("1.7a")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(new Version("1.7").greaterThan("1.7 RC1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertFalse(new Version("1.7 RC1").greaterThan("1.7")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("a", new Version("1.7a").getAditionalText()); //$NON-NLS-1$ //$NON-NLS-2$

		assertThrows(NumberFormatException.class, () -> new Version("a.1")); //$NON-NLS-1$
		assertThrows(NumberFormatException.class, () -> new Version("1.a")); //$NON-NLS-1$
	}

	/** Comprueba parseo y respuesta JSON de lotes monof&aacute;sicos locales. */
	@Test
	void jsonBatchManagerParsesAndBuildsLocalBatchJson() throws Exception {
		final String batchExtraParams = Base64.encode("modo=general\\n".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
		final String singleExtraParams = Base64.encode("modo=individual\n".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
		final String json = "{" //$NON-NLS-1$
				+ "\"stoponerror\":true," //$NON-NLS-1$
				+ "\"suboperation\":\"COSIGN\"," //$NON-NLS-1$
				+ "\"format\":\"CAdES\"," //$NON-NLS-1$
				+ "\"algorithm\":\"SHA256withRSA\"," //$NON-NLS-1$
				+ "\"extraparams\":\"" + batchExtraParams + "\"," //$NON-NLS-1$ //$NON-NLS-2$
				+ "\"singlesigns\":[" //$NON-NLS-1$
				+ "{\"id\":\"doc1\",\"datareference\":\"" + Base64.encode("datos1".getBytes(StandardCharsets.UTF_8)) + "\"}," //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				+ "{\"id\":\"doc2\",\"suboperation\":\"SIGN\",\"format\":\"PAdES\",\"datareference\":\"" //$NON-NLS-1$
				+ Base64.encode("datos2".getBytes(StandardCharsets.UTF_8)) + "\",\"extraparams\":\"" + singleExtraParams + "\"}" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				+ "]}"; //$NON-NLS-1$

		final BatchSignOperation batch = JSONBatchManager.parseBatchConfig(json.getBytes(StandardCharsets.UTF_8));
		assertTrue(batch.isStopOnError());
		assertEquals(2, batch.getSigns().size());

		final SingleSignOperation first = batch.getSigns().get(0);
		assertEquals("doc1", first.getDocId()); //$NON-NLS-1$
		assertArrayEquals("datos1".getBytes(StandardCharsets.UTF_8), first.getData()); //$NON-NLS-1$
		assertEquals(SingleSignOperation.Operation.COSIGN, first.getCryptoOperation());
		assertEquals("CAdES", first.getFormat()); //$NON-NLS-1$
		assertEquals("SHA256withRSA", first.getAlgorithm()); //$NON-NLS-1$
		assertEquals("general", first.getExtraParams().getProperty("modo")); //$NON-NLS-1$ //$NON-NLS-2$

		final SingleSignOperation second = batch.getSigns().get(1);
		assertEquals("doc2", second.getDocId()); //$NON-NLS-1$
		assertArrayEquals("datos2".getBytes(StandardCharsets.UTF_8), second.getData()); //$NON-NLS-1$
		assertEquals(SingleSignOperation.Operation.SIGN, second.getCryptoOperation());
		assertEquals("PAdES", second.getFormat()); //$NON-NLS-1$
		assertEquals("individual", second.getExtraParams().getProperty("modo")); //$NON-NLS-1$ //$NON-NLS-2$

		assertThrows(JSONException.class, () -> JSONBatchManager.parseBatchConfig("{".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
		assertThrows(ParameterException.class, () -> JSONBatchManager.parseBatchConfig(
			("{\"algorithm\":\"SHA256withRSA\",\"singlesigns\":[]}").getBytes(StandardCharsets.UTF_8) //$NON-NLS-1$
		));

		final String resultJson = JSONBatchManager.buildBatchResultJson(List.of(
			new LocalSingleBatchResult("ok", "firma".getBytes(StandardCharsets.UTF_8)), //$NON-NLS-1$ //$NON-NLS-2$
			new LocalSingleBatchResult("err", "fallo"), //$NON-NLS-1$ //$NON-NLS-2$
			new LocalSingleBatchResult("skip") //$NON-NLS-1$
		));
		final JSONArray signs = new JSONObject(resultJson).getJSONArray("signs"); //$NON-NLS-1$
		assertEquals("ok", signs.getJSONObject(0).getString("id")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("DONE_AND_SAVED", signs.getJSONObject(0).getString("result")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(Base64.encode("firma".getBytes(StandardCharsets.UTF_8)), signs.getJSONObject(0).getString("signature")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("fallo", signs.getJSONObject(1).getString("description")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("SKIPPED", signs.getJSONObject(2).getString("result")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Comprueba contratos simples de resultados, canal y excepciones del protocolo. */
	@Test
	void protocolValueObjectsAndExceptionsKeepTheirContracts() {
		final byte[] result = "firma".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
		final SignOperationResult operationResult = new SignOperationResult(result, null);
		assertSame(result, operationResult.getResult());
		assertEquals(null, operationResult.getPke());

		final ChannelInfo channel = new ChannelInfo("sesion", new int[] { 1, 2 }); //$NON-NLS-1$
		assertEquals("sesion", channel.getIdSession()); //$NON-NLS-1$
		assertArrayEquals(new int[] { 1, 2 }, channel.getPorts());
		assertEquals(1, channel.nextPortAvailable());
		assertEquals(2, channel.nextPortAvailable());
		assertEquals(-1, channel.nextPortAvailable());
		channel.setPorts(new int[] { 3 });
		assertArrayEquals(new int[] { 3 }, channel.getPorts());

		final AOException cause = new AOException("base", SimpleErrorCode.Request.UNSUPPORTED_OPERATION); //$NON-NLS-1$
		assertEquals(SimpleErrorCode.Request.UNSUPPORTED_OPERATION, new SocketOperationException(cause).getErrorCode());
		assertEquals(SimpleErrorCode.Request.UNSUPPORTED_OPERATION, new SocketOperationException("msg", cause).getErrorCode()); //$NON-NLS-1$
		assertEquals("msg", new SocketOperationException("msg", SimpleErrorCode.Request.UNSUPPORTED_OPERATION).getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(
			SimpleErrorCode.Request.UNSUPPORTED_OPERATION.getDescription(),
			new SocketOperationException(SimpleErrorCode.Request.UNSUPPORTED_OPERATION).getMessage()
		);
		assertEquals("causa", new SocketOperationException(new IllegalStateException("causa"), SimpleErrorCode.Request.UNSUPPORTED_OPERATION).getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("msg", new SocketOperationException("msg", new IllegalStateException("causa"), SimpleErrorCode.Request.UNSUPPORTED_OPERATION).getMessage()); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

		assertEquals("intermedio", new IntermediateServerErrorSendedException("intermedio").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(
			SimpleErrorCode.Request.UNSUPPORTED_OPERATION,
			new IntermediateServerErrorSendedException("intermedio", cause).getErrorCode() //$NON-NLS-1$
		);
		assertEquals(
			SimpleErrorCode.Request.UNSUPPORTED_OPERATION,
			new IntermediateServerErrorSendedException("intermedio", cause, SimpleErrorCode.Request.UNSUPPORTED_OPERATION).getErrorCode() //$NON-NLS-1$
		);

		final ProtocolVersion version = ProtocolVersion.getInstance("4.1"); //$NON-NLS-1$
		final UnsupportedProtocolException unsupported = new UnsupportedProtocolException(version, true);
		assertTrue(unsupported.isNewVersionNeeded());
		assertSame(version, unsupported.getVersion());
		assertEquals("visible", new VisibleSignatureMandatoryException("visible").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		assertNotNull(new VisibleSignatureMandatoryException("visible", new IllegalStateException("causa")).getCause()); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(SimpleErrorCode.Internal.NEEDS_UPDATED_VERSION, new LoadTrustedCertException().getErrorCode());
		assertEquals(SimpleErrorCode.Internal.NEEDS_UPDATED_VERSION, new NeedsUpdatedVersionException().getErrorCode());
	}

	/** Comprueba el formato de errores de protocolo sin mostrar interfaz gr&aacute;fica. */
	@Test
	void protocolErrorMessagesKeepOldAndNewFormats() throws Exception {
		final ProtocolVersion oldVersion = ProtocolVersion.getInstance("4.0"); //$NON-NLS-1$
		final ProtocolVersion newVersion = ProtocolVersion.getInstance("4.1"); //$NON-NLS-1$

		assertEquals("AF" + SimpleErrorCode.Request.UNSUPPORTED_OPERATION.getCode(), //$NON-NLS-1$
			ProtocolInvocationLauncherErrorManager.getErrorCodeWithPrefix(SimpleErrorCode.Request.UNSUPPORTED_OPERATION));
		assertEquals("CANCEL", ProtocolInvocationLauncherErrorManager.getErrorMessage(oldVersion, ErrorCode.Functional.CANCELLED_OPERATION)); //$NON-NLS-1$
		assertTrue(ProtocolInvocationLauncherErrorManager.getErrorMessage(oldVersion, SimpleErrorCode.Request.UNSUPPORTED_OPERATION).startsWith("SAF_04: ")); //$NON-NLS-1$
		assertTrue(ProtocolInvocationLauncherErrorManager.getErrorMessage(oldVersion, new ErrorCode("599999", "sin asociacion")).startsWith("SAF_53: ")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(ProtocolInvocationLauncherErrorManager.getErrorMessage(newVersion, ErrorCode.Functional.CANCELLED_OPERATION).startsWith("err-11:=AF")); //$NON-NLS-1$
		assertTrue(ProtocolInvocationLauncherErrorManager.getErrorMessage(newVersion, SimpleErrorCode.Request.UNSUPPORTED_OPERATION).startsWith("err-00:=AF")); //$NON-NLS-1$

		final Constructor<ProtocolInvocationLauncherErrorManager> constructor = ProtocolInvocationLauncherErrorManager.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
	}
}
