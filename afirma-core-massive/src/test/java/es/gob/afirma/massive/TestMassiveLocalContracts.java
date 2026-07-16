package es.gob.afirma.massive;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.AOUnsupportedSignFormatException;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AOSignerFactory;

/** Pruebas de contratos locales de firma masiva. */
final class TestMassiveLocalContracts {

	/** Comprueba configuraci&oacute;n, logs y cat&aacute;logos sin firmar datos. */
	@Test
	void localContractsAreStable() throws Exception {
		final MassiveSignConfiguration config = new MassiveSignConfiguration(null);
		assertNull(config.getKeyEntry());
		assertEquals(MassiveType.SIGN, config.getMassiveOperation());
		assertEquals(AOSignConstants.DEFAULT_SIGN_ALGO, config.getAlgorithm());
		assertEquals(AOSignConstants.DEFAULT_SIGN_MODE, config.getMode());
		assertEquals(AOSignConstants.DEFAULT_SIGN_FORMAT, config.getDefaultFormat());
		assertTrue(config.isOriginalFormat());

		config.setMassiveOperation(MassiveType.COSIGN);
		config.setAlgorithm("SHA512withRSA"); //$NON-NLS-1$
		config.setMode(AOSignConstants.SIGN_MODE_EXPLICIT);
		config.setDefaultFormat(AOSignConstants.SIGN_FORMAT_CADES);
		config.setSignatureFormat(AOSignConstants.SIGN_FORMAT_XADES_DETACHED);
		config.setOriginalFormat(false);
		assertEquals(MassiveType.COSIGN, config.getMassiveOperation());
		assertEquals("SHA512withRSA", config.getAlgorithm()); //$NON-NLS-1$
		assertEquals(AOSignConstants.SIGN_MODE_EXPLICIT, config.getMode());
		assertEquals(AOSignConstants.SIGN_FORMAT_CADES, config.getDefaultFormat());
		assertEquals(AOSignConstants.SIGN_FORMAT_XADES_DETACHED, config.getSignatureFormat());
		assertFalse(config.isOriginalFormat());

		final Properties extra = new Properties();
		extra.setProperty("k", "v"); //$NON-NLS-1$ //$NON-NLS-2$
		config.setExtraParams(extra);
		extra.setProperty("k", "changed"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("v", config.getExtraParams().getProperty("k")); //$NON-NLS-1$ //$NON-NLS-2$
		config.setExtraParams(null);
		assertTrue(config.getExtraParams().isEmpty());

		config.setMassiveOperation(null);
		config.setAlgorithm(null);
		config.setMode(null);
		config.setDefaultFormat(null);
		config.setSignatureFormat(null);
		assertEquals(MassiveType.SIGN, config.getMassiveOperation());
		assertEquals(AOSignConstants.DEFAULT_SIGN_ALGO, config.getAlgorithm());
		assertEquals(AOSignConstants.DEFAULT_SIGN_MODE, config.getMode());
		assertEquals(AOSignConstants.DEFAULT_SIGN_FORMAT, config.getDefaultFormat());
		assertEquals(AOSignConstants.DEFAULT_SIGN_FORMAT, config.getSignatureFormat());

		assertEquals("506001", MassiveErrorCode.Functional.INDIR_NOT_FOUND.getCode()); //$NON-NLS-1$
		assertEquals("600601", MassiveErrorCode.Request.DECODING_HASH_ERROR.getCode()); //$NON-NLS-1$
		assertNotNull(MassiveSignMessages.getString("DirectorySignatureHelper.25")); //$NON-NLS-1$
		assertEquals("!missing.key!", MassiveSignMessages.getString("missing.key")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(MassiveType.SIGN, MassiveType.valueOf("SIGN")); //$NON-NLS-1$
	}

	/** Comprueba el gestor de log por defecto sobre un flujo en memoria. */
	@Test
	void defaultLogHandlerWritesLevelsAndSummary() throws Exception {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final DefaultLogHandler log = new DefaultLogHandler(out);
		log.addLog(LogHandler.LEVEL_INFO, "ok", "entrada", null); //$NON-NLS-1$ //$NON-NLS-2$
		log.addLog(LogHandler.LEVEL_WARNING, "warn", null, "salida"); //$NON-NLS-1$ //$NON-NLS-2$
		log.addLog(123, "err", null, null); //$NON-NLS-1$
		final Properties closeParams = new Properties();
		closeParams.setProperty("warningsCount", "1"); //$NON-NLS-1$ //$NON-NLS-2$
		closeParams.setProperty("errorsCount", "2"); //$NON-NLS-1$ //$NON-NLS-2$
		log.close(closeParams);

		final String text = out.toString(StandardCharsets.UTF_8.name());
		assertTrue(text.contains("INFO: ok - entrada")); //$NON-NLS-1$
		assertTrue(text.contains("WARNING: warn - salida")); //$NON-NLS-1$
		assertTrue(text.contains("SEVERE: err - ")); //$NON-NLS-1$
		assertTrue(text.contains(": 1")); //$NON-NLS-1$
		assertTrue(text.contains(": 2")); //$NON-NLS-1$
	}

	/** Comprueba familias usando signers reales registrados. */
	@Test
	void signerFamiliesClassifyRealSigners() {
		assertFalse(SignerFamilies.isXmlBased(null));
		assertFalse(SignerFamilies.supportsMultiSignature(null));
		assertFalse(SignerFamilies.isDocumentBased(null));

		assertTrue(SignerFamilies.supportsMultiSignature(AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_CADES)));
		assertTrue(SignerFamilies.isXmlBased(AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_XADES_DETACHED)));
		assertTrue(SignerFamilies.isDocumentBased(AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_PDF)));
	}

	/** Comprueba rutas locales del ayudante de firma masiva sin claves. */
	@Test
	void massiveSignatureHelperHandlesLocalErrorPaths(@TempDir final Path tempDir) throws Exception {
		assertThrows(IllegalArgumentException.class, () -> new MassiveSignatureHelper(null));

		final MassiveSignConfiguration config = new MassiveSignConfiguration(null);
		config.setDefaultFormat(AOSignConstants.SIGN_FORMAT_CADES);
		config.setSignatureFormat(AOSignConstants.SIGN_FORMAT_CADES);
		config.setExtraParams(massiveConfig());

		final MassiveSignatureHelper helper = new MassiveSignatureHelper(config);
		assertTrue(helper.isEnabled());
		assertEquals(AOSignConstants.SIGN_FORMAT_CADES, helper.getDefaultSignatureFormat());
		assertEquals("", helper.getCurrentLogEntry()); //$NON-NLS-1$
		assertEquals("", helper.getAllLogEntries()); //$NON-NLS-1$

		helper.setSignatureFormat(AOSignConstants.SIGN_FORMAT_CADES);
		helper.setSignatureFormat("NO_FORMAT"); //$NON-NLS-1$
		assertNull(helper.signData(null));
		assertTrue(helper.getCurrentLogEntry().length() > 0);
		assertNull(helper.signData("datos".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
		assertTrue(helper.getAllLogEntries().contains("\r\n")); //$NON-NLS-1$

		assertNull(helper.signHash(null));
		config.setMassiveOperation(MassiveType.COSIGN);
		assertNull(helper.signHash(new byte[] { 1, 2, 3 }));
		config.setMassiveOperation(MassiveType.SIGN);
		config.setSignatureFormat(AOSignConstants.SIGN_FORMAT_PADES);
		assertNull(helper.signHash(new byte[] { 1, 2, 3 }));

		assertNull(helper.signFile(null));
		assertNull(helper.signFile("://malformado")); //$NON-NLS-1$
		final Path dataFile = tempDir.resolve("datos.txt"); //$NON-NLS-1$
		Files.writeString(dataFile, "datos", StandardCharsets.UTF_8); //$NON-NLS-1$
		assertNull(helper.signFile(dataFile.toUri().toString()));

		helper.disable();
		assertFalse(helper.isEnabled());
		assertNull(helper.getDefaultSignatureFormat());
	}

	/** Comprueba validaciones locales y recorrido de directorios sin datos firmables. */
	@Test
	void directorySignatureHelperValidatesLocalFilesystem(@TempDir final Path tempDir) throws Exception {
		assertThrows(IllegalArgumentException.class, () ->
			new DirectorySignatureHelper(null, AOSignConstants.SIGN_FORMAT_CADES, AOSignConstants.SIGN_MODE_IMPLICIT)
		);
		assertThrows(AOUnsupportedSignFormatException.class, () ->
			new DirectorySignatureHelper(AOSignConstants.DEFAULT_SIGN_ALGO, "NO_FORMAT", AOSignConstants.SIGN_MODE_IMPLICIT) //$NON-NLS-1$
		);

		final DirectorySignatureHelper helper = new DirectorySignatureHelper(
			AOSignConstants.DEFAULT_SIGN_ALGO,
			AOSignConstants.SIGN_FORMAT_CADES,
			AOSignConstants.SIGN_MODE_IMPLICIT
		);
		assertTrue(helper.isActiveLog());
		helper.setActiveLog(false);
		assertFalse(helper.isActiveLog());
		helper.setLogPath(" "); //$NON-NLS-1$
		assertNull(helper.getLogPath());
		helper.setLogPath(tempDir.resolve("massive.log").toString()); //$NON-NLS-1$
		assertEquals(tempDir.resolve("massive.log").toString(), helper.getLogPath()); //$NON-NLS-1$
		helper.setOverwritePreviuosFileSigns(true);
		assertNotNull(helper.getDefaultSigner());

		final var filter = (java.io.FileFilter) file -> file.getName().endsWith(".txt"); //$NON-NLS-1$
		helper.setFileFilter(filter);
		assertSame(filter, helper.getFileFilter());

		final Properties config = massiveConfig();
		assertThrows(IllegalArgumentException.class, () ->
			helper.massiveSign(MassiveType.SIGN, new String[0], tempDir.toString(), false, true, null, null)
		);
		assertThrows(AOException.class, () ->
			helper.massiveSign(MassiveType.SIGN, tempDir.resolve("missing").toString(), false, tempDir.toString(), false, true, null, config) //$NON-NLS-1$
		);
		assertThrows(IOException.class, () ->
			helper.massiveSign(MassiveType.SIGN, new String[] { tempDir.resolve("missing.txt").toString() }, //$NON-NLS-1$
				tempDir.resolve("missing-out").toString(), false, true, null, config) //$NON-NLS-1$
		);
		assertThrows(IllegalArgumentException.class, () ->
			helper.hashesMassiveSign(null, loadPrivateKeyEntry(), null, config)
		);
		assertThrows(IllegalArgumentException.class, () ->
			helper.hashesMassiveSign(new String[] { "AA==" }, null, null, config) //$NON-NLS-1$
		);
		assertThrows(IllegalArgumentException.class, () ->
			helper.hashesMassiveSign(new String[] { "AA==" }, loadPrivateKeyEntry(), null, null) //$NON-NLS-1$
		);
		assertThrows(ClassCastException.class, () ->
			helper.hashesMassiveSign(new String[] { "AA==" }, loadPrivateKeyEntry(), //$NON-NLS-1$
				AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_XADES_DETACHED), config)
		);
		assertThrows(IllegalArgumentException.class, () ->
			helper.hashesMassiveSign(new String[] { "%%" }, loadPrivateKeyEntry(), null, config) //$NON-NLS-1$
		);

		final Path input = Files.createDirectory(tempDir.resolve("in")); //$NON-NLS-1$
		final Path child = Files.createDirectory(input.resolve("child")); //$NON-NLS-1$
		Files.writeString(child.resolve("ignored.bin"), "data", StandardCharsets.UTF_8); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(helper.massiveSign(MassiveType.SIGN, input.toString(), true, tempDir.toString(), false, true, null, config));
		assertEquals(0, helper.getSignedFilenames().length);

		final Path logPath = tempDir.resolve("missing-input.log"); //$NON-NLS-1$
		helper.setActiveLog(true);
		helper.setLogPath(logPath.toString());
		assertTrue(helper.massiveSign(MassiveType.COUNTERSIGN_LEAFS,
			new String[] { tempDir.resolve("missing.txt").toString() }, tempDir.toString(), false, true, null, config)); //$NON-NLS-1$
		assertTrue(Files.readString(logPath, StandardCharsets.UTF_8).contains("SEVERE")); //$NON-NLS-1$
	}

	/** Comprueba una firma masiva CAdES real sobre ficheros locales. */
	@Test
	void directorySignatureHelperSignsRealFiles(@TempDir final Path tempDir) throws Exception {
		final DirectorySignatureHelper helper = new DirectorySignatureHelper(
			AOSignConstants.DEFAULT_SIGN_ALGO,
			AOSignConstants.SIGN_FORMAT_CADES,
			AOSignConstants.SIGN_MODE_IMPLICIT
		);
		final Path input = tempDir.resolve("datos.txt"); //$NON-NLS-1$
		final Path output = Files.createDirectory(tempDir.resolve("out")); //$NON-NLS-1$
		Files.writeString(input, "datos a firmar", StandardCharsets.UTF_8); //$NON-NLS-1$

		final Properties config = massiveConfig();
		assertTrue(helper.massiveSign(
			null,
			new String[] { input.toString() },
			output.toString(),
			false,
			true,
			loadPrivateKeyEntry(),
			config
		));
		assertFalse(config.containsKey("headless")); //$NON-NLS-1$

		final String[] firstSigns = helper.getSignedFilenames();
		assertEquals(1, firstSigns.length);
		assertTrue(Files.isRegularFile(Path.of(firstSigns[0])));
		assertTrue(Files.size(Path.of(firstSigns[0])) > 0);
		assertTrue(Files.isRegularFile(output.resolve("result.log"))); //$NON-NLS-1$

		assertTrue(helper.massiveSign(
			MassiveType.SIGN,
			new String[] { input.toString() },
			output.toString(),
			false,
			true,
			loadPrivateKeyEntry(),
			config
		));
		final String[] secondSigns = helper.getSignedFilenames();
		assertEquals(1, secondSigns.length);
		assertTrue(secondSigns[0].contains("(1)")); //$NON-NLS-1$
		assertTrue(Files.size(Path.of(secondSigns[0])) > 0);
	}

	/** Comprueba la firma masiva real de huellas precalculadas. */
	@Test
	void directorySignatureHelperSignsRealHashes() throws Exception {
		final DirectorySignatureHelper helper = new DirectorySignatureHelper(
			AOSignConstants.DEFAULT_SIGN_ALGO,
			AOSignConstants.SIGN_FORMAT_CADES,
			AOSignConstants.SIGN_MODE_IMPLICIT
		);
		final byte[] hash = MessageDigest.getInstance("SHA-512").digest("datos".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$ //$NON-NLS-2$

		final String[] signs = helper.hashesMassiveSign(
			new String[] { Base64.getEncoder().encodeToString(hash) },
			loadPrivateKeyEntry(),
			null,
			massiveConfig()
		);

		assertEquals(1, signs.length);
		assertTrue(AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_CADES).isSign(Base64.getDecoder().decode(signs[0])));
	}

	private static Properties massiveConfig() {
		final Properties config = new Properties();
		config.setProperty("format", AOSignConstants.SIGN_FORMAT_CADES); //$NON-NLS-1$
		config.setProperty("mode", AOSignConstants.SIGN_MODE_IMPLICIT); //$NON-NLS-1$
		return config;
	}

	private static PrivateKeyEntry loadPrivateKeyEntry() throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		try (InputStream is = ClassLoader.getSystemResourceAsStream("ANF_PF_Activo.pfx")) { //$NON-NLS-1$
			ks.load(is, "12341234".toCharArray()); //$NON-NLS-1$
		}
		return (PrivateKeyEntry) ks.getEntry(
			"anf usuario activo", //$NON-NLS-1$
			new KeyStore.PasswordProtection("12341234".toCharArray()) //$NON-NLS-1$
		);
	}
}
