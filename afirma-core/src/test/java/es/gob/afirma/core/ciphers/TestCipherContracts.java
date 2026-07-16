package es.gob.afirma.core.ciphers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;

import es.gob.afirma.core.ciphers.CipherConstants.AOCipherAlgorithm;
import es.gob.afirma.core.ciphers.CipherConstants.AOCipherBlockMode;
import es.gob.afirma.core.ciphers.CipherConstants.AOCipherPadding;

/** Pruebas de contratos de configuraci&oacute;n de cifrado. */
final class TestCipherContracts {

	/** Comprueba cat&aacute;logos de algoritmos, modos y rellenos. */
	@Test
	void cipherEnumsExposeLookupMetadataAndDefaults() throws Exception {
		assertSame(AOCipherAlgorithm.AES, AOCipherAlgorithm.getDefault());
		assertSame(AOCipherAlgorithm.AES, AOCipherAlgorithm.getValueOf("aes")); //$NON-NLS-1$
		assertNull(AOCipherAlgorithm.getValueOf("desconocido")); //$NON-NLS-1$
		assertTrue(AOCipherAlgorithm.AES.supportsKey());
		assertFalse(AOCipherAlgorithm.AES.supportsPassword());
		assertTrue(AOCipherAlgorithm.PBEWITHMD5ANDDES.supportsPassword());
		assertEquals("AES", AOCipherAlgorithm.AES.getName()); //$NON-NLS-1$
		assertEquals("2.16.840.1.101.3.4.1", AOCipherAlgorithm.AES.getOid()); //$NON-NLS-1$
		assertEquals("Advanced Encryption Standard (AES)", AOCipherAlgorithm.AES.toString()); //$NON-NLS-1$

		assertSame(AOCipherBlockMode.CBC, AOCipherBlockMode.getValueOf("CBC")); //$NON-NLS-1$
		assertNull(AOCipherBlockMode.getValueOf("cbc")); //$NON-NLS-1$
		assertEquals("Cipher-Block Chaining (CBC)", AOCipherBlockMode.CBC.toString()); //$NON-NLS-1$

		assertSame(AOCipherPadding.PKCS5PADDING, AOCipherPadding.getValueOf("PKCS5PADDING")); //$NON-NLS-1$
		assertNull(AOCipherPadding.getValueOf("pkcs5padding")); //$NON-NLS-1$
		assertEquals("Relleno PKCS#5", AOCipherPadding.PKCS5PADDING.toString()); //$NON-NLS-1$

		final Constructor<CipherConstants> constructor = CipherConstants.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		constructor.newInstance();
	}

	/** Comprueba parseo, defaults e igualdad de configuraciones. */
	@Test
	void cipherConfigParsesDefaultsAndExplicitValues() throws Exception {
		final AOCipherConfig defaults = new AOCipherConfig(null, null, null);
		assertSame(AOCipherAlgorithm.AES, defaults.getAlgorithm());
		assertSame(AOCipherBlockMode.ECB, defaults.getBlockMode());
		assertSame(AOCipherPadding.PKCS5PADDING, defaults.getPadding());
		assertEquals("AES/ECB/PKCS5PADDING", defaults.toString()); //$NON-NLS-1$

		final AOCipherConfig pbe = new AOCipherConfig(AOCipherAlgorithm.PBEWITHMD5ANDDES, null, null);
		assertSame(AOCipherBlockMode.CBC, pbe.getBlockMode());

		final AOCipherConfig parsed = AOCipherConfig.parse("AES/CBC/NOPADDING"); //$NON-NLS-1$
		assertSame(AOCipherAlgorithm.AES, parsed.getAlgorithm());
		assertSame(AOCipherBlockMode.CBC, parsed.getBlockMode());
		assertSame(AOCipherPadding.NOPADDING, parsed.getPadding());
		assertEquals(parsed, new AOCipherConfig(AOCipherAlgorithm.AES, AOCipherBlockMode.CBC, AOCipherPadding.NOPADDING));
		assertEquals(parsed.hashCode(), new AOCipherConfig(AOCipherAlgorithm.AES, AOCipherBlockMode.CBC, AOCipherPadding.NOPADDING).hashCode());
		assertNotEquals(parsed, "AES/CBC/NOPADDING"); //$NON-NLS-1$

		parsed.setAlgorithm(AOCipherAlgorithm.DES);
		parsed.setBlockMode(AOCipherBlockMode.CFB);
		parsed.setPadding(AOCipherPadding.ISO10126PADDING);
		assertEquals("DES/CFB/ISO10126PADDING", parsed.toString()); //$NON-NLS-1$

		assertThrows(NoSuchAlgorithmException.class, () -> AOCipherConfig.parse("NOPE")); //$NON-NLS-1$
	}
}
