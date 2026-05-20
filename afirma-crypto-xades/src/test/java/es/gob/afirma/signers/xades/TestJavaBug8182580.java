package es.gob.afirma.signers.xades;

import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;

import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.core.signers.AOSigner;

/** Regresi&oacute;n del bug <a href="https://bugs.openjdk.org/browse/JDK-8182580">JDK-8182580</a>
 * (firma XAdES con clave EC fallaba en JDK 8/9). El bug est&aacute; resuelto desde JDK 11+;
 * este test verifica que el flujo sigue funcionando en el JDK actual (21+).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestJavaBug8182580 {

	/** Prueba simple de firma XAdES con clave de curva el&iacute;ptica.
	 * @throws Exception En cualquier error. */
	@Test
	public void testSignXadesEc() throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		ks.load(
			TestJavaBug8182580.class.getResourceAsStream("/juaneliptico.p12"), //$NON-NLS-1$
			"12341234".toCharArray() //$NON-NLS-1$
		);
		final String alias = ks.aliases().nextElement();
		final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(
			alias,
			new KeyStore.PasswordProtection("12341234".toCharArray()) //$NON-NLS-1$
		);
		final AOSigner signer = new AOXAdESSigner();
		final byte[] sign = signer.sign(
			"sdjhgajdgajsgd".getBytes(), //$NON-NLS-1$
			"SHA512withECDSA", //$NON-NLS-1$
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			null
		);
		Assert.assertNotNull("La firma XAdES con clave EC debe producir un resultado no nulo", sign); //$NON-NLS-1$
		Assert.assertTrue("La firma XAdES con clave EC debe tener contenido", sign.length > 0); //$NON-NLS-1$
	}

}
