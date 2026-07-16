package es.gob.afirma.signfolder.server.proxy;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/** Pruebas unitarias de utilidades internas del servicio de almacenamiento. */
public final class TestStorageInternals {

	private static File configDir;
	private static File storageDir;

	@BeforeClass
	public static void configureStorageConfig() throws Exception {
		configDir = Files.createTempDirectory("afirma-storage-config").toFile(); //$NON-NLS-1$
		storageDir = Files.createTempDirectory("afirma-storage-data").toFile(); //$NON-NLS-1$
		Files.writeString(
			new File(configDir, "intermediate_config.properties").toPath(), //$NON-NLS-1$
			"tmpDir=" + storageDir.getAbsolutePath() + "\nexpTime=60000\nmaxFileSize=4\n", //$NON-NLS-1$ //$NON-NLS-2$
			StandardCharsets.UTF_8
		);
		System.setProperty("clienteafirma.config.path", configDir.getAbsolutePath()); //$NON-NLS-1$
	}

	@AfterClass
	public static void clearStorageConfig() {
		System.clearProperty("clienteafirma.config.path"); //$NON-NLS-1$
		delete(storageDir);
		delete(configDir);
	}

	@Test
	public void testErrorManager() throws Exception {
		instantiate(ErrorManager.class);
		Assert.assertTrue(ErrorManager.genError(ErrorManager.ERROR_MISSING_OPERATION_NAME).startsWith("ERR-00:=")); //$NON-NLS-1$
		Assert.assertEquals("X:=detalle", ErrorManager.genError("X", "detalle")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		Assert.assertEquals("X:=Error gen\u00E9rico", ErrorManager.genError("X")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	@Test
	public void testStorageConfig() throws Exception {
		Assert.assertEquals(storageDir.getCanonicalFile(), StorageConfig.getTempDir());
		Assert.assertTrue(StorageConfig.getExpirationTime() > 0);
		Assert.assertEquals(4, StorageConfig.getMaxDataSize());
		Assert.assertNull(invokeString(StorageConfig.class, "mapSystemProperties", (String) null)); //$NON-NLS-1$

		final String propertyName = "afirma.test.storage.path"; //$NON-NLS-1$
		System.setProperty(propertyName, "valor"); //$NON-NLS-1$
		try {
			Assert.assertEquals("pre-valor-post", invokeString(StorageConfig.class, "mapSystemProperties", "pre-${" + propertyName + "}-post")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
			Assert.assertEquals("pre-${missing}-post", invokeString(StorageConfig.class, "mapSystemProperties", "pre-${missing}-post")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		}
		finally {
			System.clearProperty(propertyName);
		}
	}

	@Test
	public void testStoreSign() throws Exception {
		Assert.assertTrue(store(null, null).startsWith("ERR-05")); //$NON-NLS-1$
		Assert.assertTrue(store("bad/id", null).startsWith("ERR-06")); //$NON-NLS-1$ //$NON-NLS-2$

		Assert.assertEquals("OK", store("missingData", null)); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertTrue(Files.readString(new File(storageDir, "missingData").toPath()).startsWith("ERR-02")); //$NON-NLS-1$ //$NON-NLS-2$

		Assert.assertEquals("OK", store("small", "ok")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		Assert.assertEquals("ok", Files.readString(new File(storageDir, "small").toPath())); //$NON-NLS-1$ //$NON-NLS-2$

		Assert.assertEquals("OK", store("encoded", "a%2B")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		Assert.assertEquals("a+", Files.readString(new File(storageDir, "encoded").toPath())); //$NON-NLS-1$ //$NON-NLS-2$

		Assert.assertEquals("OK", store("big", "large")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		Assert.assertTrue(Files.readString(new File(storageDir, "big").toPath()).startsWith("ERR-07")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	@Test
	public void testStorageServiceHelpers() throws Exception {
		final File target = composeTargetFile(storageDir, "data"); //$NON-NLS-1$
		Assert.assertEquals(storageDir.getCanonicalFile(), target.getParentFile());
		try {
			composeTargetFile(storageDir, "../data"); //$NON-NLS-1$
			Assert.fail("Se debio rechazar la salida del directorio base"); //$NON-NLS-1$
		}
		catch (final SecurityException expected) {
			// Ruta fuera del directorio base.
		}

		final File oldFile = new File(storageDir, "old"); //$NON-NLS-1$
		Assert.assertTrue(oldFile.createNewFile());
		Assert.assertTrue(oldFile.setLastModified(System.currentTimeMillis() - 120000));
		Assert.assertTrue(isExpired(oldFile, 1));
		Assert.assertFalse(isExpired(oldFile, Long.MAX_VALUE));
		removeExpiredFiles();
		Assert.assertFalse(oldFile.exists());
	}

	private static void instantiate(final Class<?> type) throws Exception {
		final Constructor<?> constructor = type.getDeclaredConstructor();
		constructor.setAccessible(true);
		constructor.newInstance();
	}

	private static String invokeString(final Class<?> type, final String methodName, final String text) throws Exception {
		final Method method = type.getDeclaredMethod(methodName, String.class);
		method.setAccessible(true);
		return (String) method.invoke(null, text);
	}

	private static String store(final String id, final String data) throws Exception {
		final StringWriter result = new StringWriter();
		final Method method = StorageService.class.getDeclaredMethod("storeSign", PrintWriter.class, String.class, String.class); //$NON-NLS-1$
		method.setAccessible(true);
		method.invoke(null, new PrintWriter(result), id, data);
		return result.toString().trim();
	}

	private static File composeTargetFile(final File baseDir, final String filename) throws Exception {
		final Method method = StorageService.class.getDeclaredMethod("composeTargetFile", File.class, String.class); //$NON-NLS-1$
		method.setAccessible(true);
		try {
			return (File) method.invoke(null, baseDir.getCanonicalFile(), filename);
		}
		catch (final InvocationTargetException e) {
			if (e.getCause() instanceof SecurityException) {
				throw (SecurityException) e.getCause();
			}
			throw e;
		}
	}

	private static boolean isExpired(final File file, final long expirationTimeLimit) throws Exception {
		final Method method = StorageService.class.getDeclaredMethod("isExpired", File.class, long.class); //$NON-NLS-1$
		method.setAccessible(true);
		return ((Boolean) method.invoke(null, file, Long.valueOf(expirationTimeLimit))).booleanValue();
	}

	private static void removeExpiredFiles() throws Exception {
		final Method method = StorageService.class.getDeclaredMethod("removeExpiredFiles"); //$NON-NLS-1$
		method.setAccessible(true);
		method.invoke(null);
	}

	private static void delete(final File file) {
		if (file == null || !file.exists()) {
			return;
		}
		if (file.isDirectory()) {
			for (final File child : file.listFiles()) {
				delete(child);
			}
		}
		file.delete();
	}
}
