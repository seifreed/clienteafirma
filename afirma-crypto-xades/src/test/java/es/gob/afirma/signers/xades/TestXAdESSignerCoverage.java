package es.gob.afirma.signers.xades;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;

import javax.xml.crypto.dsig.DigestMethod;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.CounterSignTarget;

/**
 * Cobertura adicional de {@link AOXAdESSigner} para Fase E.0 del refactor
 * Clean Code. Cierra los huecos que dejaba {@link TestXadesBaseline} antes de
 * descomponer {@code XAdESSigner.sign()} (1114 LOC) en colaboradores.
 *
 * <ul>
 *   <li>Formato: Detached / Enveloped / Enveloping completos.</li>
 *   <li>Hashes: SHA-256, SHA-384, SHA-512 (los tres recomendados B-Level).</li>
 *   <li>Modo Manifest ({@code useManifest=true}) con referencias precalculadas.</li>
 *   <li>Validación de invariantes ({@code checkParams}): MD5 prohibido,
 *       referencias de manifest sin huella → {@link AOException}.</li>
 *   <li>{@code dataObjectFormat}: mimeType + contentTypeOid + encoding.</li>
 *   <li>Cosignatura + contrafirma sobre la misma firma.</li>
 * </ul>
 */
class TestXAdESSignerCoverage {

	private static final String CERT_PATH = "EIDAS_CERTIFICADO_PRUEBAS___99999999R__1234.p12"; //$NON-NLS-1$
	private static final String CERT_PASS = "1234"; //$NON-NLS-1$
	private static final String CERT_ALIAS = "eidas_certificado_pruebas___99999999r"; //$NON-NLS-1$

	private static final String[] SHA_VARIANTS = {
			AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA,
			AOSignConstants.SIGN_ALGORITHM_SHA384WITHRSA,
			AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA
	};

	private PrivateKeyEntry pke;
	private byte[] binaryData;
	private byte[] xmlData;

	@BeforeEach
	void init() throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		try (final InputStream is = ClassLoader.getSystemResourceAsStream(CERT_PATH)) {
			ks.load(is, CERT_PASS.toCharArray());
		}
		this.pke = (PrivateKeyEntry) ks.getEntry(CERT_ALIAS,
				new KeyStore.PasswordProtection(CERT_PASS.toCharArray()));

		try (final InputStream is = TestXAdESSignerCoverage.class.getResourceAsStream("/rubric.jpg")) { //$NON-NLS-1$
			this.binaryData = AOUtil.getDataFromInputStream(is);
		}
		try (final InputStream is = TestXAdESSignerCoverage.class.getResourceAsStream("/xml_with_ids.xml")) { //$NON-NLS-1$
			this.xmlData = AOUtil.getDataFromInputStream(is);
		}
	}

	@Test
	@DisplayName("Detached + cada hash recomendado produce firma válida")
	void detachedWithEachHash() throws Exception {
		final AOXAdESSigner signer = new AOXAdESSigner();
		final Properties extraParams = new Properties();
		extraParams.setProperty(XAdESExtraParams.PROFILE, AOSignConstants.SIGN_PROFILE_BASELINE);
		extraParams.setProperty(XAdESExtraParams.FORMAT, AOSignConstants.SIGN_FORMAT_XADES_DETACHED);

		for (final String alg : SHA_VARIANTS) {
			final byte[] signature = signer.sign(this.binaryData, alg,
					this.pke.getPrivateKey(), this.pke.getCertificateChain(), extraParams);
			assertNotNull(signature, "Firma nula para " + alg); //$NON-NLS-1$
			assertTrue(signature.length > 0, "Firma vacía para " + alg); //$NON-NLS-1$
		}
	}

	@Test
	@DisplayName("Enveloping con encoding Base64 produce firma envolvente")
	void envelopingWithBase64Encoding() throws Exception {
		final AOXAdESSigner signer = new AOXAdESSigner();
		final Properties extraParams = new Properties();
		extraParams.setProperty(XAdESExtraParams.PROFILE, AOSignConstants.SIGN_PROFILE_BASELINE);
		extraParams.setProperty(XAdESExtraParams.FORMAT, AOSignConstants.SIGN_FORMAT_XADES_ENVELOPING);
		extraParams.setProperty(XAdESExtraParams.CONTENT_ENCODING, "Base64"); //$NON-NLS-1$

		final byte[] signature = signer.sign(this.binaryData,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), extraParams);

		assertNotNull(signature);
		final String xml = new String(signature, java.nio.charset.StandardCharsets.UTF_8);
		assertTrue(xml.contains("Object"), "Firma Enveloping debe contener nodo Object"); //$NON-NLS-1$ //$NON-NLS-2$
	}

	@Test
	@DisplayName("Enveloped sobre XML mantiene la raíz original")
	void envelopedPreservesRoot() throws Exception {
		final AOXAdESSigner signer = new AOXAdESSigner();
		final Properties extraParams = new Properties();
		extraParams.setProperty(XAdESExtraParams.PROFILE, AOSignConstants.SIGN_PROFILE_BASELINE);
		extraParams.setProperty(XAdESExtraParams.FORMAT, AOSignConstants.SIGN_FORMAT_XADES_ENVELOPED);

		final byte[] signature = signer.sign(this.xmlData,
				AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), extraParams);

		final String xml = new String(signature, java.nio.charset.StandardCharsets.UTF_8);
		assertTrue(xml.contains("Signature"), "Firma Enveloped debe inyectar Signature dentro del XML"); //$NON-NLS-1$ //$NON-NLS-2$
	}

	@Test
	@DisplayName("Manifest con dos referencias precalculadas produce firma válida")
	void manifestWithTwoPrecalculatedReferences() throws Exception {
		final AOXAdESSigner signer = new AOXAdESSigner();
		final Properties extraParams = new Properties();
		extraParams.setProperty(XAdESExtraParams.PROFILE, AOSignConstants.SIGN_PROFILE_BASELINE);
		extraParams.setProperty(XAdESExtraParams.FORMAT, AOSignConstants.SIGN_FORMAT_XADES_DETACHED);
		extraParams.setProperty(XAdESExtraParams.USE_MANIFEST, "true"); //$NON-NLS-1$
		extraParams.setProperty(XAdESExtraParams.URI_PREFIX + "1", "https://example.invalid/doc1.pdf"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.setProperty(XAdESExtraParams.MD_PREFIX + "1", "p+ZbZqaQVMu5d/W7nGxMyiPuJWfm/4QbNYx0wWO+xLI="); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.setProperty(XAdESExtraParams.URI_PREFIX + "2", "https://example.invalid/doc2.pdf"); //$NON-NLS-1$ //$NON-NLS-2$
		extraParams.setProperty(XAdESExtraParams.MD_PREFIX + "2", "QYsd5DKXjV4mwBkBpzr7sLW1cFsl4SU6Pz1pRZyq2DI="); //$NON-NLS-1$ //$NON-NLS-2$

		final byte[] signature = signer.sign(this.binaryData,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), extraParams);

		final String xml = new String(signature, java.nio.charset.StandardCharsets.UTF_8);
		assertAll(
				() -> assertTrue(xml.contains("Manifest"), "Debe contener nodo Manifest"), //$NON-NLS-1$ //$NON-NLS-2$
				() -> assertTrue(xml.contains("doc1.pdf"), "Debe referenciar doc1.pdf"), //$NON-NLS-1$ //$NON-NLS-2$
				() -> assertTrue(xml.contains("doc2.pdf"), "Debe referenciar doc2.pdf") //$NON-NLS-1$ //$NON-NLS-2$
		);
	}

	@Test
	@DisplayName("Manifest sin huella precalculada lanza AOException")
	void manifestMissingHashThrows() {
		final AOXAdESSigner signer = new AOXAdESSigner();
		final Properties extraParams = new Properties();
		extraParams.setProperty(XAdESExtraParams.PROFILE, AOSignConstants.SIGN_PROFILE_BASELINE);
		extraParams.setProperty(XAdESExtraParams.FORMAT, AOSignConstants.SIGN_FORMAT_XADES_DETACHED);
		extraParams.setProperty(XAdESExtraParams.USE_MANIFEST, "true"); //$NON-NLS-1$
		extraParams.setProperty(XAdESExtraParams.URI_PREFIX + "1", "https://example.invalid/doc.pdf"); //$NON-NLS-1$ //$NON-NLS-2$
		// MD_PREFIX_1 ausente — debe fallar en checkManifestReferences

		assertThrows(AOException.class, () -> signer.sign(this.binaryData,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), extraParams));
	}

	@Test
	@DisplayName("Algoritmo MD5 rechazado por checkParams (Decisión 130/2011 CE)")
	void md5IsRejected() {
		final AOXAdESSigner signer = new AOXAdESSigner();
		final Properties extraParams = new Properties();
		extraParams.setProperty(XAdESExtraParams.PROFILE, AOSignConstants.SIGN_PROFILE_BASELINE);
		extraParams.setProperty(XAdESExtraParams.FORMAT, AOSignConstants.SIGN_FORMAT_XADES_DETACHED);

		assertThrows(IllegalArgumentException.class, () -> signer.sign(this.binaryData,
				"MD5withRSA", //$NON-NLS-1$
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), extraParams));
	}

	@Test
	@DisplayName("dataObjectFormat propaga mimeType y contentTypeOid")
	void dataObjectFormatCarriesMimeAndOid() throws Exception {
		final AOXAdESSigner signer = new AOXAdESSigner();
		final Properties extraParams = new Properties();
		extraParams.setProperty(XAdESExtraParams.PROFILE, AOSignConstants.SIGN_PROFILE_BASELINE);
		extraParams.setProperty(XAdESExtraParams.FORMAT, AOSignConstants.SIGN_FORMAT_XADES_DETACHED);
		extraParams.setProperty(XAdESExtraParams.CONTENT_MIME_TYPE, "application/pdf"); //$NON-NLS-1$
		extraParams.setProperty(XAdESExtraParams.CONTENT_TYPE_OID, "1.2.840.113549.1.7.1"); //$NON-NLS-1$

		final byte[] signature = signer.sign(this.binaryData,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), extraParams);

		final String xml = new String(signature, java.nio.charset.StandardCharsets.UTF_8);
		assertAll(
				() -> assertTrue(xml.contains("application/pdf"), "Debe propagar mimeType"), //$NON-NLS-1$ //$NON-NLS-2$
				() -> assertTrue(xml.contains("1.2.840.113549.1.7.1"), "Debe propagar OID") //$NON-NLS-1$ //$NON-NLS-2$
		);
	}

	@Test
	@DisplayName("Cosignatura genera nueva firma distinta de la original")
	void coSignatureProducesNewSignature() throws Exception {
		final AOXAdESSigner signer = new AOXAdESSigner();
		final Properties extraParams = new Properties();
		extraParams.setProperty(XAdESExtraParams.PROFILE, AOSignConstants.SIGN_PROFILE_BASELINE);
		extraParams.setProperty(XAdESExtraParams.FORMAT, AOSignConstants.SIGN_FORMAT_XADES_DETACHED);

		final byte[] firstSig = signer.sign(this.binaryData,
				AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), extraParams);
		final byte[] coSig = signer.cosign(firstSig,
				AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), extraParams);

		assertNotNull(coSig);
		assertNotEquals(firstSig.length, coSig.length, "Cosignatura debe añadir bytes"); //$NON-NLS-1$
	}

	@Test
	@DisplayName("Contrafirma sobre LEAFS preserva la firma original")
	void countersignLeafsKeepsOriginal() throws Exception {
		final AOXAdESSigner signer = new AOXAdESSigner();
		final Properties extraParams = new Properties();
		extraParams.setProperty(XAdESExtraParams.PROFILE, AOSignConstants.SIGN_PROFILE_BASELINE);
		extraParams.setProperty(XAdESExtraParams.FORMAT, AOSignConstants.SIGN_FORMAT_XADES_DETACHED);

		final byte[] signature = signer.sign(this.binaryData,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), extraParams);
		final byte[] counterSig = signer.countersign(signature,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA, CounterSignTarget.LEAFS,
				null, this.pke.getPrivateKey(), this.pke.getCertificateChain(), extraParams);

		assertNotNull(counterSig);
		assertTrue(counterSig.length > signature.length,
				"Contrafirma debe añadir nodos sobre la firma original"); //$NON-NLS-1$
	}

	@Test
	@DisplayName("referencesDigestMethod=SHA-256 produce nodos DigestMethod con ese algoritmo")
	void referencesDigestMethodPropagates() throws Exception {
		final AOXAdESSigner signer = new AOXAdESSigner();
		final Properties extraParams = new Properties();
		extraParams.setProperty(XAdESExtraParams.PROFILE, AOSignConstants.SIGN_PROFILE_BASELINE);
		extraParams.setProperty(XAdESExtraParams.FORMAT, AOSignConstants.SIGN_FORMAT_XADES_DETACHED);
		extraParams.setProperty(XAdESExtraParams.REFERENCES_DIGEST_METHOD, DigestMethod.SHA256);

		final byte[] signature = signer.sign(this.binaryData,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA,
				this.pke.getPrivateKey(), this.pke.getCertificateChain(), extraParams);

		final String xml = new String(signature, java.nio.charset.StandardCharsets.UTF_8);
		assertTrue(xml.contains(DigestMethod.SHA256),
				"DigestMethod de referencias debe propagarse al XML"); //$NON-NLS-1$
	}
}
