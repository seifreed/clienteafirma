package es.gob.afirma.core.ui;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Pruebas de contratos locales de utilidades UI sin mostrar interfaz. */
final class TestUiLocalContracts {

	/** Comprueba el filtro gen&eacute;rico de ficheros. */
	@Test
	void genericFileFilterClonesExtensionsAndComparesValues() {
		final String[] extensions = new String[] { "pdf", "xml" }; //$NON-NLS-1$ //$NON-NLS-2$
		final GenericFileFilter filter = new GenericFileFilter(extensions, "Documentos"); //$NON-NLS-1$
		extensions[0] = "txt"; //$NON-NLS-1$

		assertArrayEquals(new String[] { "pdf", "xml" }, filter.getExtensions()); //$NON-NLS-1$ //$NON-NLS-2$
		assertNotSame(filter.getExtensions(), filter.getExtensions());
		assertEquals("Documentos", filter.getDescription()); //$NON-NLS-1$
		assertTrue(filter.equals(new GenericFileFilter(new String[] { "pdf", "xml" }, "Documentos"))); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertFalse(filter.equals(new GenericFileFilter(new String[] { "pdf" }, "Documentos"))); //$NON-NLS-1$ //$NON-NLS-2$
		assertFalse(filter.equals("Documentos")); //$NON-NLS-1$

		final GenericFileFilter empty = new GenericFileFilter(null, null);
		assertNull(empty.getExtensions());
		assertNull(empty.getDescription());
		assertTrue(empty.equals(new GenericFileFilter(null, null)));
	}

	/** Comprueba la instalaci&oacute;n local de idiomas desde un ZIP real. */
	@Test
	void languageManagerImportsZipMetadataAndLocaleFiles(@TempDir final File tempDir) throws Exception {
		final File languagesDir = new File(tempDir, "languages"); //$NON-NLS-1$
		LanguageManager.init(languagesDir);

		assertNull(LanguageManager.getImportedLocales());
		assertArrayEquals(LanguageManager.getAfirmaDefaultLocales(), LanguageManager.getAfirmaDefaultLocales());
		assertTrue(LanguageManager.isDefaultLocale(new Locale("es", "ES"))); //$NON-NLS-1$ //$NON-NLS-2$
		assertFalse(LanguageManager.isDefaultLocale(new Locale("pt", "PT"))); //$NON-NLS-1$ //$NON-NLS-2$

		final File langZip = new File(tempDir, "pt_PT.zip"); //$NON-NLS-1$
		createLanguageZip(langZip,
				"locale=pt_PT\nlanguage.name=Portugues\nfallback.locale=es_ES\n", //$NON-NLS-1$
				"mensagem=ola\n"); //$NON-NLS-1$

		final Map<String, String> props = LanguageManager.addLanguage(langZip);
		assertEquals("pt_PT", props.get(LanguageManager.LOCALE_PROP)); //$NON-NLS-1$
		assertEquals("Portugues", props.get(LanguageManager.LANGUAGE_NAME_PROP)); //$NON-NLS-1$
		assertEquals(languagesDir, LanguageManager.getLanguagesDir());

		final Locale importedLocale = new Locale("pt", "PT"); //$NON-NLS-1$ //$NON-NLS-2$
		assertArrayEquals(new Locale[] { importedLocale }, LanguageManager.getImportedLocales());
		assertEquals("Portugues", LanguageManager.getLanguageName(importedLocale)); //$NON-NLS-1$
		assertEquals(new Locale("es", "ES"), LanguageManager.readMetadataBaseLocale(importedLocale)); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(new File(languagesDir, "pt_PT/messages.properties").isFile()); //$NON-NLS-1$

		final Locale previousDefault = Locale.getDefault();
		try {
			Locale.setDefault(importedLocale);
			assertTrue(LanguageManager.existDefaultLocaleNewVersion());
		}
		finally {
			Locale.setDefault(previousDefault);
		}
	}

	private static void createLanguageZip(final File zipFile, final String metadata, final String messages) throws IOException {
		try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(zipFile.toPath()))) {
			zos.putNextEntry(new ZipEntry("metadata.info")); //$NON-NLS-1$
			zos.write(metadata.getBytes(StandardCharsets.UTF_8));
			zos.closeEntry();
			zos.putNextEntry(new ZipEntry("messages.properties")); //$NON-NLS-1$
			zos.write(messages.getBytes(StandardCharsets.UTF_8));
			zos.closeEntry();
		}
	}
}
