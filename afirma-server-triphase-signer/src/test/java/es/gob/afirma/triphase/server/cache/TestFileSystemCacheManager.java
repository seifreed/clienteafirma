package es.gob.afirma.triphase.server.cache;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Test;

/** Pruebas locales de la cache en disco. */
public final class TestFileSystemCacheManager {

	/** Comprueba guardado, recuperaci&oacute;n y caducidad de cache. */
	@Test
	public void testCacheRoundTripAndExpiration() throws Exception {
		final File cacheDir = Files.createTempDirectory("triphase-cache").toFile(); //$NON-NLS-1$
		try {
			final Properties config = new Properties();
			config.setProperty("cache.tmpDir", cacheDir.getAbsolutePath()); //$NON-NLS-1$
			config.setProperty("cache.expTime", "60000"); //$NON-NLS-1$ //$NON-NLS-2$
			config.setProperty("cache.maxUseToCleaning", "2"); //$NON-NLS-1$ //$NON-NLS-2$
			final FileSystemCacheManager cache = new FileSystemCacheManager(config);
			final byte[] data = "cache".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
			final String id = cache.storeDocumentToCache(data);
			Assert.assertArrayEquals(data, cache.getDocumentFromCache(id));
			Assert.assertNull(cache.getDocumentFromCache(id));
			Assert.assertNull(cache.getDocumentFromCache("../escape")); //$NON-NLS-1$
			Assert.assertNull(cache.getDocumentFromCache("0123456789012345678901234567890123456789012345678901234567891")); //$NON-NLS-1$

			final File expired = new File(cacheDir, "expired"); //$NON-NLS-1$
			Files.write(expired.toPath(), data);
			expired.setLastModified(System.currentTimeMillis() - 10000);
			Assert.assertTrue(FileSystemCacheManager.isExpired(expired, 1));
			Assert.assertFalse(FileSystemCacheManager.isExpired(expired, 1000000));
			cache.cleanCache();
		}
		finally {
			deleteTree(cacheDir);
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
