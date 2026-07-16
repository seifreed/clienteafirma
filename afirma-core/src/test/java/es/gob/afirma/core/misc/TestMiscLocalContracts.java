package es.gob.afirma.core.misc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.io.StringReader;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Pruebas de utilidades locales miscel&aacute;neas. */
final class TestMiscLocalContracts {

	/** Comprueba los l&iacute;mites del lector acotado. */
	@Test
	void boundedBufferedReaderHonorsLineAndLengthLimits() throws Exception {
		try (BoundedBufferedReader reader = new BoundedBufferedReader(new StringReader("uno\ndos"), 2, 10)) { //$NON-NLS-1$
			assertEquals("uno", reader.readLine()); //$NON-NLS-1$
			assertEquals("dos", reader.readLine()); //$NON-NLS-1$
			assertThrows(IOException.class, reader::readLine);
		}
		try (BoundedBufferedReader reader = new BoundedBufferedReader(new StringReader("abcd\nef"), 5, 3)) { //$NON-NLS-1$
			assertEquals("abc", reader.readLine()); //$NON-NLS-1$
			assertEquals("d", reader.readLine()); //$NON-NLS-1$
			assertEquals("ef", reader.readLine()); //$NON-NLS-1$
		}
		assertThrows(IllegalArgumentException.class, () -> new BoundedBufferedReader(new StringReader(""), 0, 1)); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> new BoundedBufferedReader(new StringReader(""), 1, 0)); //$NON-NLS-1$
	}

	/** Comprueba utilidades generales puras sobre rutas, flujos, LDAP y propiedades. */
	@Test
	void aoUtilHandlesLocalUrisStreamsAndTextHelpers(@TempDir final Path tempDir) throws Exception {
		final Path file = tempDir.resolve("datos # uno.txt"); //$NON-NLS-1$
		Files.writeString(file, "contenido", StandardCharsets.UTF_8); //$NON-NLS-1$

		final URI localUri = AOUtil.createURI(file.toString());
		assertEquals("file", localUri.getScheme()); //$NON-NLS-1$
		try (InputStream input = AOUtil.loadFile(localUri)) {
			assertEquals("contenido", new String(AOUtil.getDataFromInputStream(input), StandardCharsets.UTF_8)); //$NON-NLS-1$
		}

		assertEquals(new URI("https://example.com/ruta%20uno"), AOUtil.createURI(" https://example.com/ruta uno ")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("urn", AOUtil.createURI("urn:afirma:test").getScheme()); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class, () -> AOUtil.createURI(null));
		assertThrows(IllegalArgumentException.class, () -> AOUtil.createURI("   ")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> AOUtil.loadFile(null));

		assertArrayEquals(new byte[0], AOUtil.getDataFromInputStream(null));
		assertArrayEquals("abc".getBytes(StandardCharsets.UTF_8), AOUtil.getDataFromInputStream(new ByteArrayInputStream("abc".getBytes(StandardCharsets.UTF_8)))); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("Nombre", AOUtil.getCN("OU=Unidad,CN=Nombre,O=Org")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("Unidad", AOUtil.getCN("OU=Unidad,O=Org")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("texto sin igual", AOUtil.getCN("texto sin igual")); //$NON-NLS-1$ //$NON-NLS-2$
		assertArrayEquals(new String[] { "Uno", "Dos" }, AOUtil.getOUS("OU=Uno,OU=Dos,CN=Nombre")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertEquals("valor", AOUtil.getRDNvalueFromLdapName("CN", "CN=\"valor\",O=Org")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertEquals("", AOUtil.getRDNvalueFromLdapName("CN", "CN=,O=Org")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertEquals("00-0F-10", AOUtil.hexify(new byte[] { 0, 15, 16 }, true)); //$NON-NLS-1$
		assertEquals("00:0F:10", AOUtil.hexify(new byte[] { 0, 15, 16 }, ":")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("null", AOUtil.hexify(null, false)); //$NON-NLS-1$
		assertArrayEquals(new String[] { "uno", "", "dos", "" }, AOUtil.split("uno--dos-", "-")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$

		final Path copied = tempDir.resolve("copia.txt"); //$NON-NLS-1$
		AOUtil.copyFile(file.toFile(), copied.toFile());
		assertEquals("contenido", Files.readString(copied, StandardCharsets.UTF_8)); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> AOUtil.copyFile(null, copied.toFile()));

		final Properties properties = new Properties();
		properties.setProperty("clave", "valor"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("valor", AOUtil.base642Properties(AOUtil.properties2Base64(properties)).getProperty("clave")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(AOUtil.propertiesAsString(properties).contains("clave=valor")); //$NON-NLS-1$
		assertEquals("", AOUtil.properties2Base64(null)); //$NON-NLS-1$
		assertEquals("", AOUtil.propertiesAsString(null)); //$NON-NLS-1$
		assertTrue(AOUtil.isJava9orNewer());
		assertTrue(AOUtil.isOnlyNumber("12345")); //$NON-NLS-1$

		final Constructor<AOUtil> constructor = AOUtil.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertEquals(AOUtil.class, constructor.newInstance().getClass());
	}

	/** Comprueba detecci&oacute;n local de plataforma sin depender de red ni UI. */
	@Test
	void platformDetectsLocalValuesAndKnownUserAgents() throws Exception {
		assertEquals(Platform.BROWSER.OTHER, Platform.getBrowser(null));
		assertEquals(Platform.BROWSER.INTERNET_EXPLORER, Platform.getBrowser("Mozilla MSIE")); //$NON-NLS-1$
		assertEquals(Platform.BROWSER.FIREFOX, Platform.getBrowser("Firefox/100")); //$NON-NLS-1$
		assertEquals(Platform.BROWSER.CHROME, Platform.getBrowser("Chrome Safari")); //$NON-NLS-1$
		assertEquals(Platform.BROWSER.SAFARI, Platform.getBrowser("Version Safari")); //$NON-NLS-1$
		assertEquals(Platform.BROWSER.OPERA, Platform.getBrowser("Opera")); //$NON-NLS-1$
		assertEquals(Platform.BROWSER.OTHER, Platform.getBrowser("Navegador")); //$NON-NLS-1$

		final String oldArch = System.getProperty("os.arch"); //$NON-NLS-1$
		try {
			System.setProperty("os.arch", "aarch64"); //$NON-NLS-1$ //$NON-NLS-2$
			assertEquals(Platform.MACHINE.ARM64, Platform.getMachineType());
			System.setProperty("os.arch", "mips64"); //$NON-NLS-1$ //$NON-NLS-2$
			assertEquals(Platform.MACHINE.MIPS64, Platform.getMachineType());
			System.setProperty("os.arch", "mips"); //$NON-NLS-1$ //$NON-NLS-2$
			assertEquals(Platform.MACHINE.MIPS32, Platform.getMachineType());
			System.setProperty("os.arch", "x86_64"); //$NON-NLS-1$ //$NON-NLS-2$
			assertEquals(Platform.MACHINE.AMD64, Platform.getMachineType());
			System.setProperty("os.arch", "x86"); //$NON-NLS-1$ //$NON-NLS-2$
			assertEquals(Platform.MACHINE.X86, Platform.getMachineType());
			System.setProperty("os.arch", "desconocida"); //$NON-NLS-1$ //$NON-NLS-2$
			assertEquals(Platform.MACHINE.OTHER, Platform.getMachineType());
		}
		finally {
			if (oldArch == null) {
				System.clearProperty("os.arch"); //$NON-NLS-1$
			}
			else {
				System.setProperty("os.arch", oldArch); //$NON-NLS-1$
			}
		}

		assertNotNull(Platform.getOS());
		assertNotNull(Platform.getJavaArch());
		assertNotNull(Platform.getJavaHome());
		assertNotNull(Platform.getJavaLibraryPath());
		assertNotNull(Platform.getUserHome());
		assertNotNull(Platform.getSystemRoot());
		assertNotNull(Platform.getSystemLibDir());
		assertTrue(Platform.isUnixSystem(Platform.OS.LINUX));
		assertTrue(Platform.isUnixSystem(Platform.OS.MACOSX));
		assertTrue(Platform.isUnixSystem(Platform.OS.SOLARIS));
		assertFalse(Platform.isUnixSystem(Platform.OS.WINDOWS));
		assertFalse(Platform.isUnixSystem(Platform.OS.ANDROID));
		assertFalse(Platform.isUnixSystem(Platform.OS.OTHER));

		final Constructor<Platform> constructor = Platform.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertEquals(Platform.class, constructor.newInstance().getClass());
	}

	/** Comprueba contratos MIME locales sobre bytes reales. */
	@Test
	void mimeHelperDetectsXmlBinaryAndMappings() throws Exception {
		assertThrows(IllegalArgumentException.class, () -> new MimeHelper(null));

		final MimeHelper xml = new MimeHelper("<?xml version=\"1.0\"?><r/>".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
		assertEquals("text/xml", xml.getMimeType()); //$NON-NLS-1$
		assertEquals("xml", xml.getExtension()); //$NON-NLS-1$
		assertEquals("Documento XML", xml.getDescription()); //$NON-NLS-1$
		assertEquals("text/xml", xml.getMimeType()); //$NON-NLS-1$
		assertEquals("xml", xml.getExtension()); //$NON-NLS-1$
		assertEquals("Documento XML", xml.getDescription()); //$NON-NLS-1$

		final MimeHelper binary = new MimeHelper(new byte[] { 0, 1, 2, 3 });
		assertNotNull(binary.getMimeType());
		assertNotNull(binary.getDescription());
		assertFalse(binary.isZipData());

		final MimeHelper zip = new MimeHelper(new byte[] { 0x50, 0x4B, 0x03, 0x04 });
		assertFalse(zip.isZipData());
		final Field mimeInfo = MimeHelper.class.getDeclaredField("mimeInfo"); //$NON-NLS-1$
		mimeInfo.setAccessible(true);
		mimeInfo.set(zip, null);
		assertTrue(zip.isZipData());

		assertEquals(MimeHelper.DEFAULT_CONTENT_OID_DATA, MimeHelper.transformMimeTypeToOid(null));
		assertEquals(MimeHelper.DEFAULT_CONTENT_OID_DATA, MimeHelper.transformMimeTypeToOid("application/no-existe")); //$NON-NLS-1$
		assertEquals(MimeHelper.DEFAULT_MIMETYPE, MimeHelper.transformOidToMimeType(null));
		assertEquals(MimeHelper.DEFAULT_MIMETYPE, MimeHelper.transformOidToMimeType("1.2.3.4.5")); //$NON-NLS-1$
		assertEquals("text/xml", MimeHelper.transformOidToMimeType(MimeHelper.transformMimeTypeToOid("text/xml"))); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
