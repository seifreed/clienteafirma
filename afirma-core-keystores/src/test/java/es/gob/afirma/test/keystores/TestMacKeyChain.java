/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

package es.gob.afirma.test.keystores;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.keystores.AOKeyStore;
import es.gob.afirma.keystores.AOKeyStoreManager;
import es.gob.afirma.keystores.AOKeyStoreManagerFactory;

/** Pruebas espec&iacute;ficas para los almacenes de Mac OS X.
 *
 * <p>Ambos tests requieren un Keychain real y la contrase&ntilde;a del usuario; por eso est&aacute;n
 * condicionados a {@code -Dafirma.it.macos.keychain=true} y a ejecutarse en macOS. Sin esa
 * propiedad activa, los tests se omiten — no se mockean — siguiendo la pol&iacute;tica
 * "No mocks (mandatory)" del CLAUDE.md ra&iacute;z.
 *
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
class TestMacKeyChain {

    /** Prueba de carga y uso de un <i>KeyChain</i> en fichero suelto. Requiere
     * el recurso {@code test.keychain} y la contrase&ntilde;a del usuario para
     * desbloquearlo.
     * @throws Exception En cualquier error. */
	@Test
	@EnabledOnOs(OS.MAC)
	@EnabledIfSystemProperty(named = "afirma.it.macos.keychain", matches = "true")
    void testStandaloneKeyChain() throws Exception {
        Logger.getLogger("es.gob.afirma").setLevel(Level.WARNING); //$NON-NLS-1$

        // Copiamos el KeyChain a un fichero temporal
        final File kc = File.createTempFile("test", ".keychain"); //$NON-NLS-1$ //$NON-NLS-2$
        kc.deleteOnExit();
        try (
    		final OutputStream os = new FileOutputStream(kc);
		) {
	        os.write(AOUtil.getDataFromInputStream(ClassLoader.getSystemResourceAsStream("test.keychain"))); //$NON-NLS-1$
	        os.flush();
        }

        final AOKeyStoreManager ksm = AOKeyStoreManagerFactory.getAOKeyStoreManager(
    		AOKeyStore.APPLE,
    		kc.getAbsolutePath(),
    		"Mac-Afirma", //$NON-NLS-1$
    		AOKeyStore.APPLE.getStorePasswordCallback(null),
    		null
		);
        assertNotNull(ksm);
        final String[] aliases = ksm.getAliases();
        assertNotNull(aliases);
        assertTrue(aliases.length > 0);

        final PrivateKeyEntry pke = ksm.getKeyEntry(aliases[0]);
        assertNotNull(pke);

        final X509Certificate cert = (X509Certificate) pke.getCertificate();
        assertNotNull(cert);

        assertNotNull(pke.getPrivateKey());
    }

    /** Prueba de carga y uso del <i>KeyChain</i> del sistema. Requiere importada
     * en el sistema una entrada con alias "anf usuario activo" que tenga clave
     * privada accesible.
     * @throws Exception En cualquier error. */
	@Test
	@EnabledOnOs(OS.MAC)
	@EnabledIfSystemProperty(named = "afirma.it.macos.keychain", matches = "true")
    void testSystemKeyChain() throws Exception {
        Logger.getLogger("es.gob.afirma").setLevel(Level.WARNING); //$NON-NLS-1$

        final AOKeyStoreManager ksm = AOKeyStoreManagerFactory.getAOKeyStoreManager(AOKeyStore.APPLE, null, "Mac-Afirma", null, null); //$NON-NLS-1$
        assertNotNull(ksm);
        final String[] aliases = ksm.getAliases();
        assertNotNull(aliases);
        assertTrue(aliases.length > 0);
        final PrivateKeyEntry pke = ksm.getKeyEntry(aliases[0]);
        assertNotNull(pke);
        final X509Certificate cert = (X509Certificate) pke.getCertificate();
        assertNotNull(cert);

        assertNotNull(cert.getSubjectX500Principal().toString());
        assertNotNull(pke.getPrivateKey());
    }

}
