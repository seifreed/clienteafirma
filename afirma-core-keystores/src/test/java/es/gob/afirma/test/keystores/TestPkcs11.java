package es.gob.afirma.test.keystores;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Enumeration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import es.gob.afirma.keystores.AOKeyStore;
import es.gob.afirma.keystores.AOKeyStoreManager;
import es.gob.afirma.keystores.AOKeyStoreManagerFactory;
import es.gob.afirma.keystores.callbacks.CachePasswordCallback;

/** Prueba simple de firma con PKCS#11.
 *
 * <p>Tests gateados por {@code afirma.it.pkcs11.dnie=true} (DNIe) o
 * {@code afirma.it.pkcs11.fnmt=true} (FNMT/CERES). Requieren las
 * correspondientes DLLs PKCS#11 instaladas en Windows. Sin la propiedad
 * activa, los tests se omiten — no se mockean — conforme a la pol&iacute;tica
 * "No mocks (mandatory)" del CLAUDE.md.
 *
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
final class TestPkcs11 {

	private static final String LIB_NAME_DNIE = "C:\\WINDOWS\\SysWOW64\\DNIe_P11_priv.dll"; //$NON-NLS-1$
	private static final char[] PIN_DNIE = "12345678".toCharArray(); //$NON-NLS-1$

	private static final String LIB_NAME_FNMT = "C:\\WINDOWS\\System32\\FNMT_P11_x64.dll"; //$NON-NLS-1$
	private static final char[] PIN_FNMT = "1234".toCharArray(); //$NON-NLS-1$

	/** Prueba de firma con PKCS#11 del DNIe.
	 * @throws Exception En cualquier error. */
	@Test
	@EnabledOnOs(OS.WINDOWS)
	@EnabledIfSystemProperty(named = "afirma.it.pkcs11.dnie", matches = "true")
	void testPkcs11Dnie() throws Exception {
		final AOKeyStoreManager ksm = AOKeyStoreManagerFactory.getAOKeyStoreManager(
    		AOKeyStore.PKCS11,
    		LIB_NAME_DNIE,
    		"Afirma-P11", //$NON-NLS-1$
    		AOKeyStore.PKCS11.getStorePasswordCallback(null),
    		null
		);
		String al = null;
		for (final String alias : ksm.getAliases()) {
			al = alias;
		}
		assertNotNull(al);

		final Signature s = Signature.getInstance("SHA256withRSA"); //$NON-NLS-1$
		s.initSign(ksm.getKeyEntry(al).getPrivateKey());
		s.update("Hola".getBytes()); //$NON-NLS-1$
		assertNotNull(s.sign());
	}

	/** Prueba de firma con PKCS#11 de la tarjeta CERES.
	 * @throws Exception En cualquier error. */
	@Test
	@EnabledOnOs(OS.WINDOWS)
	@EnabledIfSystemProperty(named = "afirma.it.pkcs11.fnmt", matches = "true")
	void testPkcs11Fnmt() throws Exception {
		final AOKeyStoreManager ksm = AOKeyStoreManagerFactory.getAOKeyStoreManager(
    		AOKeyStore.PKCS11,
    		LIB_NAME_FNMT,
    		"Afirma-P11", //$NON-NLS-1$
    		new CachePasswordCallback(PIN_FNMT),
    		null
		);
		String al = null;
		for (final String alias : ksm.getAliases()) {
			al = alias;
		}
		assertNotNull(al);

		final Signature s = Signature.getInstance("SHA256withRSA"); //$NON-NLS-1$
		s.initSign(ksm.getKeyEntry(al).getPrivateKey());
		s.update("Hola".getBytes()); //$NON-NLS-1$
		assertNotNull(s.sign());
	}

	/** Prueba de firma con PKCS#11 usando directamente JRE.
	 * @throws Exception En cualquier error. */
	@Test
	@EnabledOnOs(OS.WINDOWS)
	@EnabledIfSystemProperty(named = "afirma.it.pkcs11.dnie", matches = "true")
	void testRawPkcs11() throws Exception {
        final Constructor<?> sunPKCS11Contructor = Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(InputStream.class); //$NON-NLS-1$
        final Provider p = (Provider) sunPKCS11Contructor.newInstance(
    		new ByteArrayInputStream((
				"name=pkcs11-win_dll\n" + //$NON-NLS-1$
				"library=" + LIB_NAME_DNIE + "\n" + //$NON-NLS-1$ //$NON-NLS-2$
				"showInfo=false" //$NON-NLS-1$
			).getBytes())
		);
		Security.addProvider(p);

		final KeyStore ks = KeyStore.getInstance("PKCS11"); //$NON-NLS-1$
		ks.load(null, PIN_DNIE);
		final Enumeration<String> aliases = ks.aliases();
		final String alias = aliases.nextElement();
		assertNotNull(alias);

		final Signature s = Signature.getInstance("SHA256withRSA", p); //$NON-NLS-1$
		s.initSign(((PrivateKeyEntry) ks.getEntry(alias, null)).getPrivateKey());
		s.update("Hola".getBytes()); //$NON-NLS-1$
		assertNotNull(s.sign());
	}

}
