package es.gob.afirma.signers.cadestri.client;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.signers.cadestri.client.asic.AOCAdESASiCSTriPhaseSigner;

/** Pruebas de firma CAdES trif&aacute;sica end-to-end contra el WAR
 * {@code afirma-server-triphase-signer}.
 *
 * <p>Gateados por {@code afirma.it.triphase.cades=true}: requiere un servidor
 * triphase corriendo (por defecto apunta a la sede de USAL) y los PKCS#12 de
 * prueba en el classpath. Sin la propiedad activa, los tests se omiten — no
 * se mockean — conforme a la pol&iacute;tica "No mocks (mandatory)" del
 * CLAUDE.md.
 *
 * <p>Para apuntar a otro servidor, sobreescribir con
 * {@code -Dafirma.it.triphase.cades.url=https://miservidor/.../SignatureService}.
 *
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
final class TestCadesTriphase {

	private static final String DEFAULT_SERVER_URL = "https://sede.usal.es/afirma-server-triphase-signer/SignatureService"; //$NON-NLS-1$
	private static final String PROPERTY_SIGN_SERVER_URL = "serverUrl"; //$NON-NLS-1$
	private static final String PROPERTY_DOC_ID = "documentId"; //$NON-NLS-1$
	private static final String DOC_ID = "Entrada.pdf"; //$NON-NLS-1$

	private static final String CERT_PATH = "PFActivoFirSHA1.pfx"; //$NON-NLS-1$
	private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
	private static final String CERT_ALIAS = "fisico activo prueba"; //$NON-NLS-1$

	private static final String CERT_PATH_2 = "PJActivoFirSHA1.pfx"; //$NON-NLS-1$
	private static final String CERT_PASS_2 = "12341234"; //$NON-NLS-1$
	private static final String CERT_ALIAS_2 = "juridico activo prueba-b12345678"; //$NON-NLS-1$

	private static final String SIGN_ALGO = "SHA512withRSA"; //$NON-NLS-1$

	private Properties serverConfig;
	private PrivateKeyEntry pke;
	private PrivateKeyEntry pke2;

	/** Carga los almacenes de prueba y la configuraci&oacute;n del servidor.
	 * @throws Exception en cualquier error. */
	@BeforeEach
	void loadKeystore() throws Exception {
		this.pke = loadKeyEntry(CERT_PATH, CERT_PASS, CERT_ALIAS);
		this.pke2 = loadKeyEntry(CERT_PATH_2, CERT_PASS_2, CERT_ALIAS_2);

		final String url = System.getProperty("afirma.it.triphase.cades.url", DEFAULT_SERVER_URL); //$NON-NLS-1$
		this.serverConfig = new Properties();
		this.serverConfig.setProperty(PROPERTY_SIGN_SERVER_URL, url);
		this.serverConfig.setProperty(PROPERTY_DOC_ID, DOC_ID);
	}

	private static PrivateKeyEntry loadKeyEntry(final String path, final String pass, final String alias) throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		try (final InputStream is = ClassLoader.getSystemResourceAsStream(path)) {
			ks.load(is, pass.toCharArray());
		}
		return (PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(pass.toCharArray()));
	}

	/** Firma CAdES-ASiC-S trif&aacute;sica contra el servidor.
	 * @throws Exception Cuando falla la firma. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.triphase.cades", matches = "true")
	void testTriPhaseSignCAdESASiCS() throws Exception {
		final AOSigner signer = new AOCAdESASiCSTriPhaseSigner();
		final Properties config = new Properties();
		config.putAll(this.serverConfig);

		final byte[] result = signer.sign(
			"Hola Mundo".getBytes(), //$NON-NLS-1$
			SIGN_ALGO,
			this.pke.getPrivateKey(),
			this.pke.getCertificateChain(),
			config
		);

		assertNotNull(result, "Error durante el proceso de firma, resultado nulo"); //$NON-NLS-1$
	}

	/** Firma CAdES trif&aacute;sica de payload largo, modo implicit.
	 * @throws Exception en cualquier error. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.triphase.cades", matches = "true")
	void testTriPhaseSignCAdES() throws Exception {
		final AOSigner signer = new AOCAdESTriPhaseSigner();
		final Properties config = new Properties();
		config.putAll(this.serverConfig);
		config.setProperty("mode", "implicit"); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] result = signer.sign(
			("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. " //$NON-NLS-1$
				+ "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.").getBytes(), //$NON-NLS-1$
			SIGN_ALGO,
			this.pke.getPrivateKey(),
			this.pke.getCertificateChain(),
			config
		);

		assertNotNull(result, "Error durante el proceso de firma, resultado nulo"); //$NON-NLS-1$
	}

	/** Cofirma CAdES trif&aacute;sica usando una firma previa de fixture.
	 * @throws Exception en cualquier error. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.triphase.cades", matches = "true")
	void cofirma() throws Exception {
		final AOSigner signer = new AOCAdESTriPhaseSigner();
		final Properties config = new Properties();
		config.putAll(this.serverConfig);

		final byte[] signature;
		try (final InputStream is = ClassLoader.getSystemResourceAsStream("firma_tri.csig")) { //$NON-NLS-1$
			signature = AOUtil.getDataFromInputStream(is);
		}

		final byte[] result = signer.cosign(
			signature,
			SIGN_ALGO,
			this.pke2.getPrivateKey(),
			this.pke2.getCertificateChain(),
			config
		);

		assertNotNull(result, "Error durante el proceso de cofirma, resultado nulo"); //$NON-NLS-1$
	}

	/** Contrafirma CAdES trif&aacute;sica sobre fixture de cofirma.
	 * @throws Exception en cualquier error. */
	@Test
	@EnabledIfSystemProperty(named = "afirma.it.triphase.cades", matches = "true")
	void contrafirma() throws Exception {
		final AOSigner signer = new AOCAdESTriPhaseSigner();
		final Properties config = new Properties();
		config.putAll(this.serverConfig);

		final byte[] signature;
		try (final InputStream is = ClassLoader.getSystemResourceAsStream("cofirma_tri.csig")) { //$NON-NLS-1$
			signature = AOUtil.getDataFromInputStream(is);
		}

		final byte[] result = signer.countersign(
			signature,
			SIGN_ALGO,
			CounterSignTarget.TREE,
			null,
			this.pke2.getPrivateKey(),
			this.pke2.getCertificateChain(),
			config
		);

		assertNotNull(result, "Error durante el proceso de contrafirma, resultado nulo"); //$NON-NLS-1$
	}

}
