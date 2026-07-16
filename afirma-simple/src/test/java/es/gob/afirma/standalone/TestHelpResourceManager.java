package es.gob.afirma.standalone;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import es.gob.afirma.standalone.updater.Updater;

/** Pruebas locales del gestor de recursos de ayuda. */
final class TestHelpResourceManager {

	/** Comprueba extracci&oacute;n local, versi&oacute;n y generaci&oacute;n del lanzador. */
	@Test
	void helpResourcesAreExtractedAndVersioned(@TempDir final Path tempDir) throws Exception {
		final File helpDir = tempDir.resolve("help").toFile(); //$NON-NLS-1$
		assertFalse(HelpResourceManager.isLocalHelpUpdated(helpDir));
		assertTrue(HelpResourceManager.isDifferentHelpFile(tempDir.resolve("missing.version").toFile())); //$NON-NLS-1$

		HelpResourceManager.extractHelpResources(helpDir);
		assertTrue(helpDir.isDirectory());
		assertTrue(new File(helpDir, "index_es_ES.html").isFile()); //$NON-NLS-1$
		assertTrue(new File(helpDir, "help.version").isFile()); //$NON-NLS-1$
		assertTrue(HelpResourceManager.isLocalHelpUpdated(helpDir));

		final Path currentVersion = tempDir.resolve("current.version"); //$NON-NLS-1$
		Files.writeString(currentVersion, Updater.getCurrentVersion(), StandardCharsets.UTF_8);
		assertFalse(HelpResourceManager.isDifferentHelpFile(currentVersion.toFile()));

		final Path oldVersion = tempDir.resolve("old.version"); //$NON-NLS-1$
		Files.writeString(oldVersion, "0.0.0", StandardCharsets.UTF_8); //$NON-NLS-1$
		assertTrue(HelpResourceManager.isDifferentHelpFile(oldVersion.toFile()));

		final String launcher = HelpResourceManager.createHelpFileLauncher(new File(helpDir, "index_es_ES.html").getAbsolutePath()); //$NON-NLS-1$
		assertTrue(launcher.startsWith("file:///")); //$NON-NLS-1$
		assertTrue(Files.readString(Path.of(launcher.substring("file:///".length())), StandardCharsets.UTF_8).contains("index_es_ES.html")); //$NON-NLS-1$ //$NON-NLS-2$
		assertNotNull(Updater.getCurrentVersionText());

		final Constructor<HelpResourceManager> constructor = HelpResourceManager.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
	}
}
