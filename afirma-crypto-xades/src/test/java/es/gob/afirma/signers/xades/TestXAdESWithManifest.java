package es.gob.afirma.signers.xades;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.MessageDigest;
import java.util.Properties;

import org.junit.jupiter.api.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;

/** Pruebas de firmas XAdES con MANIFEST.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
final class TestXAdESWithManifest {

    private static final String CERT_PATH = "CATCERT CIUTADANIA PF CPIXSA-2.p12"; //$NON-NLS-1$
    private static final String CERT_PASS = "1111"; //$NON-NLS-1$
    private static final String CERT_ALIAS = "persona física de la peça de proves"; //$NON-NLS-1$

    private static final String ALGORITHM = "SHA256withRSA"; //$NON-NLS-1$
    private static final String FIXTURE_DATA = "ANF_con cadena_certificacion.jks"; //$NON-NLS-1$

    private static PrivateKeyEntry loadKeyEntry() throws Exception {
        final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
        try (final InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
            ks.load(is, CERT_PASS.toCharArray());
        }
        return (PrivateKeyEntry) ks.getEntry(CERT_ALIAS, new KeyStore.PasswordProtection(CERT_PASS.toCharArray()));
    }

    private static byte[] loadFixture(final String name) throws Exception {
        try (final InputStream is = ClassLoader.getSystemResourceAsStream(name)) {
            return AOUtil.getDataFromInputStream(is);
        }
    }

    /** Firma XAdES Externally Detached con Manifest y URI no dereferenciable (URN).
     * @throws Exception En cualquier error. */
	@Test
    void testXadesExternallyDetachedUseManifest() throws Exception {
        final PrivateKeyEntry pke = loadKeyEntry();

        // Los datos son la huella SHA-512 del payload
        final byte[] data = MessageDigest.getInstance("SHA-512").digest(loadFixture(FIXTURE_DATA)); //$NON-NLS-1$

        final Properties p = new Properties();
        p.setProperty("useManifest", "true"); //$NON-NLS-1$ //$NON-NLS-2$
        p.setProperty("precalculatedHashAlgorithm", "SHA-512"); //$NON-NLS-1$ //$NON-NLS-2$
        p.setProperty("format", AOSignConstants.SIGN_FORMAT_XADES_EXTERNALLY_DETACHED); //$NON-NLS-1$
        p.setProperty("uri", "urn:id:001"); //$NON-NLS-1$ //$NON-NLS-2$

        final byte[] signature = new AOXAdESSigner().sign(data, ALGORITHM, pke.getPrivateKey(), pke.getCertificateChain(), p);

        assertNotNull(signature, "Firma XAdES Externally Detached con Manifest debe devolver bytes"); //$NON-NLS-1$
        assertTrue(signature.length > 0, "La firma resultante no puede estar vacia"); //$NON-NLS-1$
        // Sanity check sobre el XML resultante
        final String xml = new String(signature, java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(xml.contains("Manifest"), "El XML firmado debe contener un Manifest"); //$NON-NLS-1$ //$NON-NLS-2$
    }

}
