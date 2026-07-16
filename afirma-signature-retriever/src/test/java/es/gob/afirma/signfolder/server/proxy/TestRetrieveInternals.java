package es.gob.afirma.signfolder.server.proxy;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.junit.Assert;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/** Pruebas unitarias de utilidades internas del servicio de recuperaci&oacute;n. */
public final class TestRetrieveInternals {

	private static File configDir;
	private static File retrieveDir;

	@BeforeClass
	public static void configureRetrieveConfig() throws Exception {
		configDir = Files.createTempDirectory("afirma-retrieve-config").toFile(); //$NON-NLS-1$
		retrieveDir = Files.createTempDirectory("afirma-retrieve-data").toFile(); //$NON-NLS-1$
		Files.writeString(
			new File(configDir, "intermediate_config.properties").toPath(), //$NON-NLS-1$
			"tmpDir=" + retrieveDir.getAbsolutePath() + "\nexpTime=60000\n", //$NON-NLS-1$ //$NON-NLS-2$
			StandardCharsets.UTF_8
		);
		System.setProperty("clienteafirma.config.path", configDir.getAbsolutePath()); //$NON-NLS-1$
	}

	@AfterClass
	public static void clearRetrieveConfig() {
		System.clearProperty("clienteafirma.config.path"); //$NON-NLS-1$
		delete(retrieveDir);
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
	public void testRetrieveConfig() throws Exception {
		Assert.assertTrue(RetrieveConfig.getTempDir().isDirectory());
		Assert.assertTrue(RetrieveConfig.getExpirationTime() > 0);
		Assert.assertNull(invokeString(RetrieveConfig.class, "mapSystemProperties", (String) null)); //$NON-NLS-1$

		final String propertyName = "afirma.test.retrieve.path"; //$NON-NLS-1$
		System.setProperty(propertyName, "valor"); //$NON-NLS-1$
		try {
			Assert.assertEquals("pre-valor-post", invokeString(RetrieveConfig.class, "mapSystemProperties", "pre-${" + propertyName + "}-post")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
			Assert.assertEquals("pre-${missing}-post", invokeString(RetrieveConfig.class, "mapSystemProperties", "pre-${missing}-post")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		}
		finally {
			System.clearProperty(propertyName);
		}
	}

	@Test
	public void testRetrieveServiceHelpers() throws Exception {
		final File baseDir = Files.createTempDirectory("afirma-retrieve").toFile(); //$NON-NLS-1$
		try {
			final File target = composeTargetFile(baseDir, "data"); //$NON-NLS-1$
			Assert.assertEquals(baseDir.getCanonicalFile(), target.getParentFile());
			try {
				composeTargetFile(baseDir, "../data"); //$NON-NLS-1$
				Assert.fail("Se debio rechazar la salida del directorio base"); //$NON-NLS-1$
			}
			catch (final SecurityException expected) {
				// Ruta fuera del directorio base.
			}

			final File oldFile = new File(retrieveDir, "old"); //$NON-NLS-1$
			Assert.assertTrue(oldFile.createNewFile());
			Assert.assertTrue(oldFile.setLastModified(System.currentTimeMillis() - 120000));
			Assert.assertTrue(isExpired(oldFile, 1));
			Assert.assertFalse(isExpired(oldFile, Long.MAX_VALUE));
			removeExpiredFiles();
			Assert.assertFalse(oldFile.exists());
		}
		finally {
			for (final File file : baseDir.listFiles()) {
				file.delete();
			}
			baseDir.delete();
		}

		Assert.assertArrayEquals(new byte[0], read(null));
		Assert.assertEquals("datos", new String(read(new ByteArrayInputStream("datos".getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8)); //$NON-NLS-1$ //$NON-NLS-2$
	}

	@Test
	public void testGetTrim() throws Exception {
		setAllowExtendedLogs(null);
		Assert.assertNull(RetrieveService.getTrim(null));
		Assert.assertEquals("corto", RetrieveService.getTrim("corto")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals(203, RetrieveService.getTrim("x".repeat(200)).length()); //$NON-NLS-1$

		System.setProperty("allow.extended.logs", "true"); //$NON-NLS-1$ //$NON-NLS-2$
		try {
			setAllowExtendedLogs(null);
			Assert.assertEquals(200, RetrieveService.getTrim("x".repeat(200)).length()); //$NON-NLS-1$
		}
		finally {
			System.clearProperty("allow.extended.logs"); //$NON-NLS-1$
			setAllowExtendedLogs(null);
		}
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

	private static File composeTargetFile(final File baseDir, final String filename) throws Exception {
		final Method method = RetrieveService.class.getDeclaredMethod("composeTargetFile", File.class, String.class); //$NON-NLS-1$
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
		final Method method = RetrieveService.class.getDeclaredMethod("isExpired", File.class, long.class); //$NON-NLS-1$
		method.setAccessible(true);
		return ((Boolean) method.invoke(null, file, Long.valueOf(expirationTimeLimit))).booleanValue();
	}

	private static void removeExpiredFiles() throws Exception {
		final Method method = RetrieveService.class.getDeclaredMethod("removeExpiredFiles"); //$NON-NLS-1$
		method.setAccessible(true);
		method.invoke(null);
	}

	private static byte[] read(final ByteArrayInputStream input) throws Exception {
		final Method method = RetrieveService.class.getDeclaredMethod("getDataFromInputStream", java.io.InputStream.class); //$NON-NLS-1$
		method.setAccessible(true);
		return (byte[]) method.invoke(null, input);
	}

	private static void setAllowExtendedLogs(final Boolean value) throws Exception {
		final Field field = RetrieveService.class.getDeclaredField("allowExtendedLogs"); //$NON-NLS-1$
		field.setAccessible(true);
		field.set(null, value);
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
