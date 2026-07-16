package es.gob.afirma.triphase.server;

import java.io.File;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.core.misc.Base64;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.triphase.server.document.FileSystemDocumentManager;
import es.gob.afirma.triphase.server.document.SelfishDocumentManager;

/** Pruebas locales de contratos del servidor trif&aacute;sico. */
public final class TestServerLocalContracts {

	/** Comprueba utilidades de rutas y mensajes de error. */
	@Test
	public void testErrorsAndPathComposition() throws Exception {
		final Constructor<ErrorManager> constructor = ErrorManager.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		Assert.assertNotNull(constructor.newInstance());
		Assert.assertEquals("ERR-1", ErrorManager.getErrorPrefix(ErrorManager.OPERATION_ARGUMENT_NOT_FOUND)); //$NON-NLS-1$
		Assert.assertTrue(ErrorManager.getErrorMessage(ErrorManager.OPERATION_ARGUMENT_NOT_FOUND).contains("operacion")); //$NON-NLS-1$
		Assert.assertTrue(ErrorManager.getErrorMessage(ErrorManager.UNSUPPORTED_OPERATION, "E01").contains("E01")); //$NON-NLS-1$ //$NON-NLS-2$

		final File base = Files.createTempDirectory("triphase-base").toFile(); //$NON-NLS-1$
		try {
			Assert.assertEquals(new File(base, "data.bin").getCanonicalFile(), FileSystemUtils.composeTargetFile(base.getCanonicalFile(), "data.bin")); //$NON-NLS-1$
			try {
				FileSystemUtils.composeTargetFile(base.getCanonicalFile(), "../escape.bin"); //$NON-NLS-1$
				Assert.fail("Se esperaba rechazo de rutas fuera del directorio base"); //$NON-NLS-1$
			}
			catch (final SecurityException e) {
				// Esperado
			}
		}
		finally {
			base.delete();
		}
	}

	/** Comprueba gestores documentales reales con ficheros temporales. */
	@Test
	public void testDocumentManagers() throws Exception {
		final byte[] data = "contenido".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
		final SelfishDocumentManager selfish = new SelfishDocumentManager(new Properties());
		final String stored = selfish.storeDocument(null, null, data, new Properties());
		Assert.assertArrayEquals(data, selfish.getDocument(stored.replace('+', '-').replace('/', '_'), null, new Properties()));

		final File inDir = Files.createTempDirectory("triphase-in").toFile(); //$NON-NLS-1$
		final File outDir = Files.createTempDirectory("triphase-out").toFile(); //$NON-NLS-1$
		try {
			Files.write(new File(inDir, "input.txt").toPath(), data); //$NON-NLS-1$
			final Properties config = new Properties();
			config.setProperty("docmanager.filesystem.indir", inDir.getAbsolutePath()); //$NON-NLS-1$
			config.setProperty("docmanager.filesystem.outdir", outDir.getAbsolutePath()); //$NON-NLS-1$
			config.setProperty("docmanager.filesystem.overwrite", "false"); //$NON-NLS-1$ //$NON-NLS-2$
			config.setProperty("docmanager.filesystem.maxDocSize", "100"); //$NON-NLS-1$ //$NON-NLS-2$

			final FileSystemDocumentManager manager = new FileSystemDocumentManager();
			manager.init(config);
			final String dataRef = Base64.encode("input.txt".getBytes(StandardCharsets.UTF_8)); //$NON-NLS-1$
			Assert.assertArrayEquals(data, manager.getDocument(dataRef, null, new Properties()));

			final Properties cades = new Properties();
			cades.setProperty("format", AOSignConstants.SIGN_FORMAT_CADES); //$NON-NLS-1$
			final String outRef = manager.storeDocument(dataRef, null, "firma".getBytes(StandardCharsets.UTF_8), cades); //$NON-NLS-1$
			Assert.assertEquals("input.csig", new String(Base64.decode(outRef), StandardCharsets.UTF_8)); //$NON-NLS-1$
			Assert.assertTrue(new File(outDir, "input.csig").isFile()); //$NON-NLS-1$
			try {
				manager.storeDocument(dataRef, null, "firma".getBytes(StandardCharsets.UTF_8), cades); //$NON-NLS-1$
				Assert.fail("Se esperaba rechazo al sobrescribir"); //$NON-NLS-1$
			}
			catch (final Exception e) {
				Assert.assertTrue(e.getMessage().contains("existe")); //$NON-NLS-1$
			}
		}
		finally {
			deleteTree(inDir);
			deleteTree(outDir);
		}
	}

	private static void deleteTree(final File file) {
		if (file != null && file.isDirectory()) {
			for (final File child : file.listFiles()) {
				deleteTree(child);
			}
		}
		if (file != null) {
			file.delete();
		}
	}
}
