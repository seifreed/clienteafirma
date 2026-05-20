package es.gob.afirma.test.keystores;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Signature;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

/** Prueba simple de firma con CSP de Windows usando token CLAUER.
 *
 * <p>Gateado por {@code afirma.it.clauer=true}: requiere un CLAUER conectado
 * y registrado en el almac&eacute;n personal de Windows. Sin la propiedad
 * activa el test se omite — no se mockea — conforme a la pol&iacute;tica
 * "No mocks (mandatory)" del CLAUDE.md.
 *
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
final class TestClauerCSP {

	private static final String ALIAS = "CLAUER_PERSONA FISICA DE LA PEᦚ DE PROVES"; //$NON-NLS-1$

	/** Prueba de firma con CSP.
	 * @throws Exception En cualquier error. */
	@Test
	@EnabledOnOs(OS.WINDOWS)
	@EnabledIfSystemProperty(named = "afirma.it.clauer", matches = "true")
	void testCapi() throws Exception {
		final KeyStore ks = KeyStore.getInstance("WINDOWS-MY"); //$NON-NLS-1$
		ks.load(null, null);

		final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(ALIAS, new KeyStore.PasswordProtection(new char[0]));

		final Signature signature = Signature.getInstance("SHA256withRSA"); //$NON-NLS-1$
		signature.initSign(pke.getPrivateKey());
		signature.update("Hola Mundo!!".getBytes()); //$NON-NLS-1$
		assertNotNull(signature.sign());
	}

}
