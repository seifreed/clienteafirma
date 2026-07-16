package es.gob.afirma.plugin.hash;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.reflect.Constructor;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Pruebas offline de utilidades del plugin de huellas. */
final class TestHashCoreContracts {

	private static final byte[] DATA = "abc".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$

	/** Comprueba conversiones hexadecimales. */
	@Test
	void hexUtilsRoundTripsAndValidates() {
		assertEquals("000FA0", HexUtils.byteArrayToHexString(new byte[] { 0, 15, (byte) 160 })); //$NON-NLS-1$
		assertEquals("000FA0h", HexUtils.byteArrayToHexString(new byte[] { 0, 15, (byte) 160 }, true)); //$NON-NLS-1$
		assertArrayEquals(new byte[] { 0, 15, (byte) 160 }, HexUtils.hexStringToByteArray("000FA0")); //$NON-NLS-1$
		assertArrayEquals(new byte[] { 0, 15, (byte) 160 }, HexUtils.hexStringToByteArray("000FA0h")); //$NON-NLS-1$
		assertTrue(HexUtils.isHexadecimal("000FA0".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
		assertTrue(HexUtils.isHexadecimal("000FA0h".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
		assertFalse(HexUtils.isHexadecimal(null));
		assertFalse(HexUtils.isHexadecimal(new byte[0]));
		assertFalse(HexUtils.isHexadecimal("xyz".getBytes(StandardCharsets.UTF_8))); //$NON-NLS-1$
	}

	/** Comprueba los gestores de digest con datos reales. */
	@Test
	void digestManagersComputeExpectedHashes() throws Exception {
		final byte[] expected = MessageDigest.getInstance("SHA-256").digest(DATA); //$NON-NLS-1$

		final DigestManager manager = new DigestManager("SHA-256", null); //$NON-NLS-1$
		manager.addDataToCompute(DATA[0]);
		manager.addDataToCompute(DATA, 1, 1);
		manager.addDataToCompute("c"); //$NON-NLS-1$
		assertArrayEquals(expected, manager.computeHash());

		final DigestManager providerManager = new DigestManager(
			"SHA-256", //$NON-NLS-1$
			MessageDigest.getInstance("SHA-256").getProvider() //$NON-NLS-1$
		);
		assertArrayEquals(expected, providerManager.computeHash(DATA));
		assertArrayEquals(expected, new DigestManager("SHA-256", null).computeHash("abc")); //$NON-NLS-1$ //$NON-NLS-2$
		assertArrayEquals(
			expected,
			new DigestManager("SHA-256", null).computeHashOptimized(new ByteArrayInputStream(DATA), 2) //$NON-NLS-1$
		);
		assertTrue(DigestManager.equalHashes(expected, expected.clone()));
		assertFalse(DigestManager.equalHashes(expected, MessageDigest.getInstance("SHA-1").digest(DATA))); //$NON-NLS-1$
	}

	/** Comprueba el flujo de digest y el c&aacute;lculo sobre fichero. */
	@Test
	void digestInputStreamAndFileHashReadRealBytes() throws Exception {
		final byte[] expected = MessageDigest.getInstance("SHA-256").digest(DATA); //$NON-NLS-1$

		final DigestManager byteReadManager = new DigestManager("SHA-256", null); //$NON-NLS-1$
		try (DigestManagerInputStream in = new DigestManagerInputStream(new ByteArrayInputStream(DATA), byteReadManager)) {
			assertEquals('a', in.read());
			final byte[] buffer = new byte[2];
			assertEquals(2, in.read(buffer));
		}
		assertArrayEquals(expected, byteReadManager.computeHash());

		final DigestManager optimizedManager = new DigestManager("SHA-256", null); //$NON-NLS-1$
		try (DigestManagerInputStream in = new DigestManagerInputStream(new ByteArrayInputStream(DATA), optimizedManager)) {
			in.readOptimized(2);
			assertArrayEquals(expected, in.digest());
		}

		final File file = File.createTempFile("hash-core", ".txt"); //$NON-NLS-1$ //$NON-NLS-2$
		try {
			Files.write(file.toPath(), DATA);
			assertArrayEquals(expected, HashUtil.getFileHash("SHA-256", file)); //$NON-NLS-1$
			assertArrayEquals(expected, HashUtil.getFileHash("SHA-256", file.toPath())); //$NON-NLS-1$
			assertArrayEquals(expected, HashUtil.getFileHash("SHA-256", file.getAbsolutePath())); //$NON-NLS-1$
			assertEquals(file.getCanonicalFile(), FileUtils.getCanonicalFile(file));
		}
		finally {
			Files.deleteIfExists(file.toPath());
		}
	}

	/** Comprueba mensajes, excepciones y construcci&oacute;n del plugin. */
	@Test
	void messagesExceptionsAndPluginAreConstructible() throws Exception {
		assertNotNull(Messages.getString("CommandLine.123")); //$NON-NLS-1$
		assertEquals("!clave.inexistente!", Messages.getString("clave.inexistente")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(Messages.getString("CommandLine.21", "salida.txt").contains("salida.txt")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

		final Constructor<Messages> constructor = Messages.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());

		final Exception cause = new Exception("causa"); //$NON-NLS-1$
		assertEquals("documento", new DocumentException("documento").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		assertSame(cause, new DocumentException("documento", cause).getCause()); //$NON-NLS-1$
		assertNotNull(new CorruptedDocumentException());
		assertEquals("corrupto", new CorruptedDocumentException("corrupto").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		assertNotNull(new HashPlugin());
		assertNotNull(HashUtil.getApplicationDirectory());

		assertArrayEquals(
			new CreateHashFileDialog.HashFormat[] {
				CreateHashFileDialog.HashFormat.HEX,
				CreateHashFileDialog.HashFormat.BASE64,
				CreateHashFileDialog.HashFormat.BINARY
			},
			CreateHashFileDialog.HashFormat.getHashFormats()
		);
		assertEquals(CreateHashFileDialog.HashFormat.HEX, CreateHashFileDialog.HashFormat.getDefaultFormat());
		assertEquals(CreateHashFileDialog.HashFormat.HEX, CreateHashFileDialog.HashFormat.fromString("hex")); //$NON-NLS-1$
		assertEquals(CreateHashFileDialog.HashFormat.BASE64, CreateHashFileDialog.HashFormat.fromString("b64")); //$NON-NLS-1$
		assertEquals(CreateHashFileDialog.HashFormat.BINARY, CreateHashFileDialog.HashFormat.fromString("bin")); //$NON-NLS-1$
		assertEquals(CreateHashFileDialog.HashFormat.HEX, CreateHashFileDialog.HashFormat.fromString("desconocido")); //$NON-NLS-1$
		assertNotNull(CreateHashFileDialog.HashFormat.HEX.toString());
	}

	/** Comprueba generacion y carga de documentos de hashes. */
	@Test
	void hashDocumentsGenerateAndLoadRealFormats() throws Exception {
		final Map<String, byte[]> hashes = new HashMap<>();
		hashes.put("a.txt", new byte[] { 1, 2, 3 }); //$NON-NLS-1$
		hashes.put("dir/b.bin", new byte[] { 4, 5, 6 }); //$NON-NLS-1$

		final HashDocument txtDocument = HashDocumentFactory.getHashDocument(HashDocumentFactory.FORMAT_TXT);
		txtDocument.setHashes(hashes);
		txtDocument.setAlgorithm("SHA-384"); //$NON-NLS-1$
		txtDocument.setRecursive(true);
		txtDocument.setCharset(StandardCharsets.ISO_8859_1);
		final byte[] txtData = txtDocument.generate();
		final HashDocument loadedTxt = HashDocumentFactory.loadDocument(txtData, "txthashfiles"); //$NON-NLS-1$
		assertEquals("SHA-384", loadedTxt.getAlgorithm()); //$NON-NLS-1$
		assertTrue(loadedTxt.isRecursive());
		assertEquals(Charset.forName("ISO-8859-1"), loadedTxt.getCharset()); //$NON-NLS-1$
		assertArrayEquals(new byte[] { 1, 2, 3 }, loadedTxt.getHashes().get("a.txt")); //$NON-NLS-1$

		final Map<String, byte[]> xmlHashes = new HashMap<>();
		xmlHashes.put("a.txt", new byte[] { 1, 2, 3 }); //$NON-NLS-1$
		final HashDocument xmlDocument = HashDocumentFactory.getHashDocument(HashDocumentFactory.FORMAT_XML);
		xmlDocument.setHashes(xmlHashes);
		xmlDocument.setAlgorithm("SHA-256"); //$NON-NLS-1$
		xmlDocument.setRecursive(false);
		final byte[] xmlData = xmlDocument.generate();
		final String xml = new String(xmlData, StandardCharsets.UTF_8);
		assertTrue(xml.contains("hashAlgorithm=\"SHA-256\"")); //$NON-NLS-1$
		assertTrue(xml.contains("recursive=\"false\"")); //$NON-NLS-1$
		assertTrue(xml.contains("a.txt")); //$NON-NLS-1$
		final HashDocument loadedXml = HashDocumentFactory.loadDocument(xmlData, "hashfiles"); //$NON-NLS-1$
		assertEquals("SHA-256", loadedXml.getAlgorithm()); //$NON-NLS-1$
		assertFalse(loadedXml.isRecursive());
		assertNotNull(loadedXml.getHashes());

		final HashDocument csvDocument = HashDocumentFactory.getHashDocument(HashDocumentFactory.FORMAT_CSV);
		csvDocument.setHashes(hashes);
		final String csv = new String(csvDocument.generate(), StandardCharsets.UTF_8);
		assertTrue(csv.contains("\"a.txt\"")); //$NON-NLS-1$
		assertThrows(UnsupportedOperationException.class, () -> csvDocument.load(csv.getBytes(StandardCharsets.UTF_8)));
		csvDocument.setHashes(null);
		assertArrayEquals(new byte[0], csvDocument.generate());

		assertThrows(IllegalArgumentException.class, () -> HashDocumentFactory.getHashDocument(null));
		assertThrows(IllegalArgumentException.class, () -> HashDocumentFactory.getHashDocument("json")); //$NON-NLS-1$
		assertNotNull(HashDocumentFactory.loadDocument("bad".getBytes(StandardCharsets.UTF_8), "txt")); //$NON-NLS-1$ //$NON-NLS-2$
		assertNotNull(HashDocumentFactory.loadDocument("<bad/>".getBytes(StandardCharsets.UTF_8), "xml")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(DocumentException.class, () -> new XmlHashDocument().load(corruptedXmlHashDocument()));
	}

	/** Comprueba el informe de verificacion de hashes. */
	@Test
	void hashReportTracksResults() {
		final HashReport report = new HashReport();
		assertFalse(report.hasErrors());
		assertEquals(0, report.getProcessedFilesCount());

		report.setAlgorithm("SHA-256"); //$NON-NLS-1$
		report.setRecursive(true);
		report.setCharset(StandardCharsets.ISO_8859_1);
		report.reportMatchingHash("ok.txt"); //$NON-NLS-1$
		report.reportNoMatchingHash("bad.txt"); //$NON-NLS-1$
		report.reportHashWithoutFile("missing.txt"); //$NON-NLS-1$
		report.reportFileWithoutHash("extra.txt"); //$NON-NLS-1$

		assertTrue(report.hasErrors());
		assertTrue(report.isRecursive());
		assertEquals("SHA-256", report.getAlgorithm()); //$NON-NLS-1$
		assertEquals(StandardCharsets.ISO_8859_1, report.getCharset());
		assertEquals(2, report.getProcessedFilesCount());
		assertEquals("ok.txt", first(report.getMatchingHashIterator())); //$NON-NLS-1$
		assertEquals("bad.txt", first(report.getNoMatchingHashIterator())); //$NON-NLS-1$
		assertEquals("missing.txt", first(report.getHashWithoutFileIterator())); //$NON-NLS-1$
		assertEquals("extra.txt", first(report.getFileWithoutHashIterator())); //$NON-NLS-1$
	}

	private static String first(final Iterator<String> iterator) {
		assertTrue(iterator.hasNext());
		return iterator.next();
	}

	private static byte[] corruptedXmlHashDocument() {
		return (
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + //$NON-NLS-1$
			"<entries hashAlgorithm=\"SHA-256\" recursive=\"false\">" + //$NON-NLS-1$
			"<entry name=\"a.txt\" hash=\"AQID\" hexhash=\"040506h\"/>" + //$NON-NLS-1$
			"</entries>" //$NON-NLS-1$
		).getBytes(StandardCharsets.UTF_8);
	}
}
