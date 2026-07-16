package es.gob.afirma.core.misc.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Test;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.core.misc.Base64;

/** Pruebas del contrato de versi&oacute;n del protocolo. */
final class TestProtocolVersionContracts {

	/** Comprueba parseo, compatibilidad y soporte de versiones. */
	@Test
	void protocolVersionsParseCompareAndRender() {
		final ProtocolVersion v4 = ProtocolVersion.getInstance(ProtocolVersion.VERSION_4);
		final ProtocolVersion v41 = ProtocolVersion.getInstance(ProtocolVersion.VERSION_4_1);
		final ProtocolVersion v5 = ProtocolVersion.getInstance("5"); //$NON-NLS-1$
		assertEquals(4, v41.getMajorVersion());
		assertEquals(1, v41.getMinorVersion());
		assertEquals("4.1", v41.toString()); //$NON-NLS-1$
		assertTrue(v41.isCompatibleWith(v4));
		assertTrue(v41.hasSupportTo(v4));
		assertFalse(v4.hasSupportTo(v41));
		assertFalse(v41.isCompatibleWith(v5));
		assertTrue(v5.hasSupportTo(v41));

		assertThrows(IllegalArgumentException.class, () -> ProtocolVersion.getInstance(null));
		assertThrows(IllegalArgumentException.class, () -> ProtocolVersion.getInstance("4.x")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> ProtocolVersion.getInstance("-1")); //$NON-NLS-1$
	}

	/** Comprueba par&aacute;metros comunes sin descargas ni llamadas a red. */
	@Test
	void urlParametersKeepCommonStateDefensively() throws Exception {
		final UrlParametersToLoad params = new UrlParametersToLoad();
		final byte[] data = "datos".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
		params.setData(data);
		data[0] = 0;
		assertArrayEquals("datos".getBytes(StandardCharsets.UTF_8), params.getData()); //$NON-NLS-1$
		params.getData()[0] = 0;
		assertArrayEquals("datos".getBytes(StandardCharsets.UTF_8), params.getData()); //$NON-NLS-1$

		final byte[] cipher = "{algo:\"AES\"}".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
		params.setCipherConfig(cipher);
		cipher[0] = 0;
		assertArrayEquals("{algo:\"AES\"}".getBytes(StandardCharsets.UTF_8), params.getCipherConfig()); //$NON-NLS-1$
		params.getCipherConfig()[0] = 0;
		assertArrayEquals("{algo:\"AES\"}".getBytes(StandardCharsets.UTF_8), params.getCipherConfig()); //$NON-NLS-1$

		final Properties extra = new Properties();
		extra.setProperty("k", "v"); //$NON-NLS-1$ //$NON-NLS-2$
		params.setExtraParams(extra);
		extra.setProperty("k", "changed"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("v", params.getExtraParams().getProperty("k")); //$NON-NLS-1$ //$NON-NLS-2$
		params.getExtraParams().setProperty("k", "changed"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("v", params.getExtraParams().getProperty("k")); //$NON-NLS-1$ //$NON-NLS-2$
		params.removeExtraParam("k"); //$NON-NLS-1$
		assertNull(params.getExtraParams().getProperty("k")); //$NON-NLS-1$

		final Map<String, String> common = new HashMap<>();
		common.put("fileid", "abc123"); //$NON-NLS-1$ //$NON-NLS-2$
		common.put("rtservlet", "https://example.com/retrieve"); //$NON-NLS-1$ //$NON-NLS-2$
		common.put("aw", "true"); //$NON-NLS-1$ //$NON-NLS-2$
		common.put("mcv", "1.2.3"); //$NON-NLS-1$ //$NON-NLS-2$
		common.put("servicetimeout", "1500"); //$NON-NLS-1$ //$NON-NLS-2$
		common.put("key", "12345678"); //$NON-NLS-1$ //$NON-NLS-2$
		params.setCommonParameters(common);
		assertEquals("abc123", params.getFileId()); //$NON-NLS-1$
		assertEquals("https://example.com/retrieve", params.getRetrieveServletUrl().toString()); //$NON-NLS-1$
		assertTrue(params.isActiveWaiting());
		assertEquals("1.2.3", params.getMinimumClientVersion()); //$NON-NLS-1$
		assertEquals(1500, params.getServiceTimeout());
		assertTrue(new String(params.getCipherConfig(), StandardCharsets.UTF_8).contains("12345678")); //$NON-NLS-1$

		final Map<String, String> invalidCipher = Map.of("key", "short"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(
			ErrorCode.Request.UNSUPPORTED_CIPHER_KEY,
			assertThrows(ParameterException.class, () -> params.setCommonParameters(invalidCipher)).getErrorCode()
		);
		assertThrows(UrlParameters.LocalAccessRequestException.class, () -> UrlParameters.validateURL("https://localhost/service")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> UrlParameters.validateURL("ftp://example.com/service")); //$NON-NLS-1$
		assertEquals("PKCS12", UrlParameters.getKeyStoreName(Map.of("ksb64", Base64.encode("PKCS12:/tmp/a.p12".getBytes(StandardCharsets.UTF_8))))); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
	}

	/** Comprueba par&aacute;metros espec&iacute;ficos de carga y guardado. */
	@Test
	void loadAndSaveParametersValidateLocalFields() throws Exception {
		final UrlParametersToLoad load = new UrlParametersToLoad();
		load.setLoadParameters(Map.of(
			"ver", "4.1", //$NON-NLS-1$ //$NON-NLS-2$
			"multiload", "true", //$NON-NLS-1$ //$NON-NLS-2$
			"title", "Cargar", //$NON-NLS-1$ //$NON-NLS-2$
			"exts", "pdf,xml", //$NON-NLS-1$ //$NON-NLS-2$
			"desc", "Documentos", //$NON-NLS-1$ //$NON-NLS-2$
			"filePath", "/tmp" //$NON-NLS-1$ //$NON-NLS-2$
		));
		assertEquals("4.1", load.getMinimumProtocolVersion()); //$NON-NLS-1$
		assertTrue(load.getMultiload());
		assertEquals("Cargar", load.getTitle()); //$NON-NLS-1$
		assertEquals("pdf,xml", load.getExtensions()); //$NON-NLS-1$
		assertEquals("Documentos", load.getDescription()); //$NON-NLS-1$
		assertEquals("/tmp", load.getFilepath()); //$NON-NLS-1$

		load.setLoadParameters(Map.of("filePath", "")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(ProtocolVersion.VERSION_0, load.getMinimumProtocolVersion());
		assertFalse(load.getMultiload());
		assertNull(load.getFilepath());

		final UrlParametersToSave save = new UrlParametersToSave();
		save.setSaveParameters(Map.of(
			"fileid", "save123", //$NON-NLS-1$ //$NON-NLS-2$
			"filename", "firma.csig", //$NON-NLS-1$ //$NON-NLS-2$
			"exts", "csig,xsig", //$NON-NLS-1$ //$NON-NLS-2$
			"desc", "Firmas", //$NON-NLS-1$ //$NON-NLS-2$
			"title", "Guardar", //$NON-NLS-1$ //$NON-NLS-2$
			"ver", "4" //$NON-NLS-1$ //$NON-NLS-2$
		));
		assertEquals("save123", save.getId()); //$NON-NLS-1$
		assertEquals("firma.csig", save.getFileName()); //$NON-NLS-1$
		assertEquals("csig,xsig", save.getExtensions()); //$NON-NLS-1$
		assertEquals("Firmas (*.csig*.xsig)", save.getFileTypeDescription()); //$NON-NLS-1$
		assertEquals("Guardar", save.getTitle()); //$NON-NLS-1$
		assertEquals("4", save.getMinimumProtocolVersion()); //$NON-NLS-1$

		assertEquals(
			ErrorCode.Request.DATA_TO_SAVE_NOT_FOUND,
			assertThrows(ParameterException.class, () -> save.setSaveParameters(Map.of())).getErrorCode()
		);
		assertEquals(
			ErrorCode.Request.INVALID_SESSION_ID_TO_SAVE,
			assertThrows(ParameterException.class, () -> save.setSaveParameters(Map.of("fileid", "id-con-guion"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ErrorCode.Request.FILENAME_TO_SAVE_NOT_FOUND,
			assertThrows(ParameterException.class, () -> save.setSaveParameters(Map.of("fileid", "save123", "filename", "bad/name"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		);
		assertEquals(
			ErrorCode.Request.FILE_EXTENSION_TO_SAVE_NOT_FOUND,
			assertThrows(ParameterException.class, () -> save.setSaveParameters(Map.of("fileid", "save123", "exts", "bad ext"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		);

		final UrlParametersToSave remoteSave = new UrlParametersToSave(true);
		assertEquals(
			ErrorCode.Request.STORAGE_URL_TO_SIGN_BATCH_NOT_FOUND,
			assertThrows(ParameterException.class, () -> remoteSave.setSaveParameters(Map.of("id", "save123", "fileid", "save123"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		);
	}

	/** Comprueba par&aacute;metros de firma+guardado y selecci&oacute;n de certificado. */
	@Test
	void signAndSaveAndSelectCertParametersValidateLocalFields() throws Exception {
		final String extraParams = Base64.encode("mode=implicit\n".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
		final UrlParametersToSignAndSave signAndSave = new UrlParametersToSignAndSave();
		signAndSave.setSignAndSaveParameters(Map.of(
			"id", "signsave123", //$NON-NLS-1$ //$NON-NLS-2$
			"cop", "sign", //$NON-NLS-1$ //$NON-NLS-2$
			"format", "CAdES", //$NON-NLS-1$ //$NON-NLS-2$
			"algorithm", "SHA256withRSA", //$NON-NLS-1$ //$NON-NLS-2$
			"filename", "firma.csig", //$NON-NLS-1$ //$NON-NLS-2$
			"properties", extraParams, //$NON-NLS-1$
			"sticky", "true", //$NON-NLS-1$ //$NON-NLS-2$
			"resetsticky", "true", //$NON-NLS-1$ //$NON-NLS-2$
			"ver", "4.1", //$NON-NLS-1$ //$NON-NLS-2$
			"pluginParam", "valor" //$NON-NLS-1$ //$NON-NLS-2$
		));
		signAndSave.setAnotherParams(Map.of("format", "CAdES", "pluginParam", "valor")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		assertEquals("signsave123", signAndSave.getId()); //$NON-NLS-1$
		assertEquals("sign", signAndSave.getOperation()); //$NON-NLS-1$
		assertEquals("CAdES", signAndSave.getSignatureFormat()); //$NON-NLS-1$
		assertEquals("SHA256withRSA", signAndSave.getSignatureAlgorithm()); //$NON-NLS-1$
		assertEquals("firma.csig", signAndSave.getFileName()); //$NON-NLS-1$
		assertEquals("implicit", signAndSave.getExtraParams().getProperty("mode")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(signAndSave.getSticky());
		assertTrue(signAndSave.getResetSticky());
		assertEquals("4.1", signAndSave.getMinimumProtocolVersion()); //$NON-NLS-1$
		assertEquals("valor", signAndSave.getAnotherParams().get("pluginParam")); //$NON-NLS-1$ //$NON-NLS-2$
		signAndSave.getAnotherParams().put("otro", "cambio"); //$NON-NLS-1$ //$NON-NLS-2$
		assertNull(signAndSave.getAnotherParams().get("otro")); //$NON-NLS-1$

		assertEquals(
			ErrorCode.Request.SIGNATURE_FORMAT_NOT_FOUND,
			assertThrows(ParameterException.class, () -> new UrlParametersToSignAndSave().setSignAndSaveParameters(Map.of("id", "a"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ErrorCode.Request.SIGNATURE_ALGORITHM_NOT_FOUND,
			assertThrows(ParameterException.class, () -> new UrlParametersToSignAndSave().setSignAndSaveParameters(Map.of("id", "a", "format", "CAdES"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		);
		assertEquals(
			ErrorCode.Request.UNSUPPORTED_SIGNATURE_ALGORITHM,
			assertThrows(ParameterException.class, () -> new UrlParametersToSignAndSave().setSignAndSaveParameters(Map.of("id", "a", "format", "CAdES", "algorithm", "MD5withRSA"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$ //$NON-NLS-6$
		);
		assertEquals(
			ErrorCode.Request.FILENAME_TO_SAVE_NOT_FOUND,
			assertThrows(ParameterException.class, () -> new UrlParametersToSignAndSave().setSignAndSaveParameters(Map.of("id", "a", "format", "CAdES", "algorithm", "SHA256withRSA", "filename", "bad/name"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$ //$NON-NLS-6$ //$NON-NLS-7$ //$NON-NLS-8$
		);

		final UrlParametersToSelectCert selectCert = new UrlParametersToSelectCert();
		selectCert.setSelectCertParameters(Map.of(
			"id", "cert123", //$NON-NLS-1$ //$NON-NLS-2$
			"ver", "4", //$NON-NLS-1$ //$NON-NLS-2$
			"sticky", "true", //$NON-NLS-1$ //$NON-NLS-2$
			"resetsticky", "false", //$NON-NLS-1$ //$NON-NLS-2$
			"properties", extraParams //$NON-NLS-1$
		));
		assertEquals("cert123", selectCert.getId()); //$NON-NLS-1$
		assertEquals("4", selectCert.getMinimumProtocolVersion()); //$NON-NLS-1$
		assertTrue(selectCert.getSticky());
		assertFalse(selectCert.getResetSticky());
		assertEquals("implicit", selectCert.getExtraParams().getProperty("mode")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(
			ErrorCode.Request.INVALID_SESSION_ID_TO_SELECT_CERT,
			assertThrows(ParameterException.class, () -> new UrlParametersToSelectCert().setSelectCertParameters(Map.of("id", "bad-id"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$
		);
	}

	/** Comprueba par&aacute;metros de firma por lotes sin red. */
	@Test
	void batchParametersValidateLocalFields() throws Exception {
		final String extraParams = Base64.encode("mode=implicit\n".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
		final Map<String, String> params = new HashMap<>();
		params.put("id", "batch123"); //$NON-NLS-1$ //$NON-NLS-2$
		params.put("ver", "4.1"); //$NON-NLS-1$ //$NON-NLS-2$
		params.put("appname", "Mi+App"); //$NON-NLS-1$ //$NON-NLS-2$
		params.put("batchpresignerurl", "https://example.com/pre"); //$NON-NLS-1$ //$NON-NLS-2$
		params.put("batchpostsignerurl", "https://example.com/post"); //$NON-NLS-1$ //$NON-NLS-2$
		params.put("stservlet", "https://example.com/store"); //$NON-NLS-1$ //$NON-NLS-2$
		params.put("sticky", "true"); //$NON-NLS-1$ //$NON-NLS-2$
		params.put("resetsticky", "true"); //$NON-NLS-1$ //$NON-NLS-2$
		params.put("needcert", "true"); //$NON-NLS-1$ //$NON-NLS-2$
		params.put("jsonbatch", "true"); //$NON-NLS-1$ //$NON-NLS-2$
		params.put("properties", extraParams); //$NON-NLS-1$

		final UrlParametersForBatch batch = new UrlParametersForBatch(true);
		batch.setBatchParameters(params);
		assertEquals("batch123", batch.getId()); //$NON-NLS-1$
		assertEquals("4.1", batch.getMinimumProtocolVersion()); //$NON-NLS-1$
		assertEquals("Mi App", batch.getAppName()); //$NON-NLS-1$
		assertEquals("https://example.com/pre", batch.getBatchPresignerUrl()); //$NON-NLS-1$
		assertEquals("https://example.com/post", batch.getBatchPostSignerUrl()); //$NON-NLS-1$
		assertEquals("https://example.com/store", batch.getStorageServletUrl().toString()); //$NON-NLS-1$
		assertTrue(batch.getSticky());
		assertTrue(batch.getResetSticky());
		assertTrue(batch.isCertNeeded());
		assertTrue(batch.isJsonBatch());
		assertFalse(batch.isLocalBatchProcess());
		assertEquals("implicit", batch.getExtraParams().getProperty("mode")); //$NON-NLS-1$ //$NON-NLS-2$

		final UrlParametersForBatch localBatch = new UrlParametersForBatch();
		localBatch.setBatchParameters(Map.of("localBatchProcess", "true")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(localBatch.isLocalBatchProcess());
		assertEquals(ProtocolVersion.VERSION_0, localBatch.getMinimumProtocolVersion());
		assertNull(localBatch.getBatchPresignerUrl());
		assertNull(localBatch.getBatchPostSignerUrl());

		assertEquals(
			ErrorCode.Request.INVALID_SESSION_ID_TO_SIGN_BATCH,
			assertThrows(ParameterException.class, () -> new UrlParametersForBatch().setBatchParameters(Map.of("id", "bad-id"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ErrorCode.Request.POSTSIGN_BATCH_URL_NOT_FOUND,
			assertThrows(ParameterException.class, () -> new UrlParametersForBatch().setBatchParameters(Map.of("id", "batch123"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ErrorCode.Request.PRESIGN_BATCH_URL_NOT_FOUND,
			assertThrows(ParameterException.class, () -> new UrlParametersForBatch().setBatchParameters(Map.of("id", "batch123", "batchpostsignerurl", "https://example.com/post"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		);
	}

	/** Comprueba par&aacute;metros de firma simple sin red. */
	@Test
	void signParametersValidateLocalFields() throws Exception {
		final String extraParams = Base64.encode("mode=explicit\n".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
		final UrlParametersToSign sign = new UrlParametersToSign();
		sign.setSignParameters(Map.of(
			"id", "sign123", //$NON-NLS-1$ //$NON-NLS-2$
			"op", "sign", //$NON-NLS-1$ //$NON-NLS-2$
			"format", "XAdES", //$NON-NLS-1$ //$NON-NLS-2$
			"algorithm", "SHA256withECDSA", //$NON-NLS-1$ //$NON-NLS-2$
			"properties", extraParams, //$NON-NLS-1$
			"sticky", "true", //$NON-NLS-1$ //$NON-NLS-2$
			"resetsticky", "true", //$NON-NLS-1$ //$NON-NLS-2$
			"ver", "4", //$NON-NLS-1$ //$NON-NLS-2$
			"appname", "App+Firma", //$NON-NLS-1$ //$NON-NLS-2$
			"pluginParam", "valor" //$NON-NLS-1$ //$NON-NLS-2$
		));
		sign.setAnotherParams(Map.of("format", "XAdES", "pluginParam", "valor")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		assertEquals("sign123", sign.getId()); //$NON-NLS-1$
		assertEquals("sign", sign.getOperation()); //$NON-NLS-1$
		assertEquals("XAdES", sign.getSignatureFormat()); //$NON-NLS-1$
		assertEquals("SHA256withECDSA", sign.getSignatureAlgorithm()); //$NON-NLS-1$
		assertEquals("explicit", sign.getExtraParams().getProperty("mode")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(sign.getSticky());
		assertTrue(sign.getResetSticky());
		assertEquals("4", sign.getMinimumProtocolVersion()); //$NON-NLS-1$
		assertEquals("App Firma", sign.getAppName()); //$NON-NLS-1$
		assertEquals("valor", sign.getAnotherParams().get("pluginParam")); //$NON-NLS-1$ //$NON-NLS-2$

		final UrlParametersToSign defaults = new UrlParametersToSign();
		defaults.setSignParameters(Map.of(
			"format", "CAdES", //$NON-NLS-1$ //$NON-NLS-2$
			"algorithm", "SHA512" //$NON-NLS-1$ //$NON-NLS-2$
		));
		assertEquals(ProtocolVersion.VERSION_0, defaults.getMinimumProtocolVersion());
		assertFalse(defaults.getSticky());
		assertFalse(defaults.getResetSticky());
		assertNull(defaults.getAppName());

		assertEquals(
			ErrorCode.Request.INVALID_SESSION_ID_TO_SIGN,
			assertThrows(ParameterException.class, () -> new UrlParametersToSign().setSignParameters(Map.of("id", "bad-id"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ErrorCode.Request.SIGNATURE_FORMAT_NOT_FOUND,
			assertThrows(ParameterException.class, () -> new UrlParametersToSign().setSignParameters(Map.of("id", "a"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ErrorCode.Request.SIGNATURE_ALGORITHM_NOT_FOUND,
			assertThrows(ParameterException.class, () -> new UrlParametersToSign().setSignParameters(Map.of("id", "a", "format", "CAdES"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		);
		assertEquals(
			ErrorCode.Request.UNSUPPORTED_SIGNATURE_ALGORITHM,
			assertThrows(ParameterException.class, () -> new UrlParametersToSign().setSignParameters(Map.of("id", "a", "format", "CAdES", "algorithm", "MD5withRSA"))).getErrorCode() //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$ //$NON-NLS-6$
		);
	}

	/** Comprueba parseo p&uacute;blico de URI y XML del protocolo. */
	@Test
	void protocolInvocationParserReadsUriAndXmlWithoutNetwork() throws Exception {
		final Map<String, String> raw = ProtocolInvocationUriParser.parserUri(
			"afirma://sign?format=CAdES&algorithm=SHA256withRSA&fileid=f123&rtservlet=https%3A%2F%2Fexample.com%2Fretrieve&appname=Mi+App&empty=" //$NON-NLS-1$
		);
		assertEquals("sign", raw.get("op")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("https://example.com/retrieve", raw.get("rtservlet")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("", raw.get("empty")); //$NON-NLS-1$ //$NON-NLS-2$

		final UrlParametersToSign sign = ProtocolInvocationUriParser.getParametersToSign(
			"afirma://sign?format=CAdES&algorithm=SHA256withRSA&fileid=f123&rtservlet=https%3A%2F%2Fexample.com%2Fretrieve&appname=Mi+App" //$NON-NLS-1$
		);
		assertEquals("sign", sign.getOperation()); //$NON-NLS-1$
		assertEquals("f123", sign.getFileId()); //$NON-NLS-1$
		assertEquals("https://example.com/retrieve", sign.getRetrieveServletUrl().toString()); //$NON-NLS-1$
		assertEquals("Mi App", sign.getAppName()); //$NON-NLS-1$

		final byte[] xml = (
			"<load>" + //$NON-NLS-1$
			"<e k=\"title\" v=\"Cargar+datos\"/>" + //$NON-NLS-1$
			"<e k=\"multiload\" v=\"true\"/>" + //$NON-NLS-1$
			"</load>" //$NON-NLS-1$
		).getBytes(StandardCharsets.UTF_8);
		final Map<String, String> xmlParams = ProtocolInvocationUriParserUtil.parseXml(xml);
		assertEquals("load", xmlParams.get("op")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("Cargar datos", xmlParams.get("title")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(ProtocolInvocationUriParser.getParametersToLoad(xml).getMultiload());

		assertThrows(IllegalArgumentException.class, () -> ProtocolInvocationUriParser.parserUri("afirma?format=CAdES")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> ProtocolInvocationUriParser.parserUri("bad?x=1://sign")); //$NON-NLS-1$
		assertEquals(
			ErrorCode.ThirdParty.INVALID_OPERATION_XML,
			assertThrows(AOException.class, () -> ProtocolInvocationUriParserUtil.parseXml("<load><bad/></load>".getBytes(StandardCharsets.UTF_8))).getErrorCode() //$NON-NLS-1$
		);
	}
}
