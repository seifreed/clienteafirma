/* Copyright (C) 2026 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.core.misc.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import es.gob.afirma.core.misc.Platform;

/** Pruebas del almac&eacute;n local de certificados de confianza. */
final class TestTrustStoreManager {

	/** Comprueba el ciclo completo de importaci&oacute;n, consulta, recarga y borrado del almac&eacute;n. */
	@Test
	void importsReloadsAndDeletesCertificates(@TempDir final Path tempDir) throws Exception {
		final String originalUserHomeProperty = System.getProperty("user.home"); //$NON-NLS-1$
		final Field platformUserHome = Platform.class.getDeclaredField("userHome"); //$NON-NLS-1$
		platformUserHome.setAccessible(true);
		final Object originalPlatformUserHome = platformUserHome.get(null);
		final Field managerInstance = TrustStoreManager.class.getDeclaredField("instance"); //$NON-NLS-1$
		managerInstance.setAccessible(true);
		final Object originalManagerInstance = managerInstance.get(null);

		try {
			System.setProperty("user.home", tempDir.toString()); //$NON-NLS-1$
			platformUserHome.set(null, null);
			managerInstance.set(null, null);

			final Path storeDir = tempDir.resolve(".afirma"); //$NON-NLS-1$
			Files.createDirectories(storeDir);
			assertEquals(storeDir.resolve("TrustedCertsKeystore.jks").toFile(), TrustStoreManager.getJKSFile()); //$NON-NLS-1$
			assertArrayEquals(new X509Certificate[0], TrustStoreManager.getCertificates(null));

			final X509Certificate ceres = loadCertificate("CERES.cer"); //$NON-NLS-1$
			final X509Certificate mdef = loadCertificate("MDEF01.cer"); //$NON-NLS-1$
			TrustStoreManager.importCerts((X509Certificate[]) null);
			TrustStoreManager.importCerts(ceres, mdef, ceres);

			assertTrue(TrustStoreManager.containsCert(ceres));
			assertTrue(TrustStoreManager.containsCert(mdef));
			assertEquals(2, TrustStoreManager.getCertificates(null).length);
			assertTrue(TrustStoreManager.readTrustStoreContent().length > 0);

			managerInstance.set(null, null);
			final X509Certificate[] reloadedCerts = TrustStoreManager.getCertificates(null);
			assertEquals(2, reloadedCerts.length);
			assertTrue(Arrays.asList(reloadedCerts).contains(ceres));
			assertTrue(Arrays.asList(reloadedCerts).contains(mdef));

			TrustStoreManager.deleteCert(ceres);
			assertFalse(TrustStoreManager.containsCert(ceres));
			assertTrue(TrustStoreManager.containsCert(mdef));
			TrustStoreManager.deleteCert(ceres);
			TrustStoreManager.deleteCert(mdef);
			assertEquals(0, TrustStoreManager.getCertificates(null).length);
		}
		finally {
			if (originalUserHomeProperty != null) {
				System.setProperty("user.home", originalUserHomeProperty); //$NON-NLS-1$
			}
			else {
				System.clearProperty("user.home"); //$NON-NLS-1$
			}
			platformUserHome.set(null, originalPlatformUserHome);
			managerInstance.set(null, originalManagerInstance);
		}
	}

	private static X509Certificate loadCertificate(final String certName) throws Exception {
		final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
		try (InputStream is = TestTrustStoreManager.class.getResourceAsStream("/" + certName)) { //$NON-NLS-1$
			return (X509Certificate) cf.generateCertificate(is);
		}
	}
}
