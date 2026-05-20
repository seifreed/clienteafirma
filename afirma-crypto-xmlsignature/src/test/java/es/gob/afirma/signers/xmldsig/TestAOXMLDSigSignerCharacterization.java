/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.signers.xmldsig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;
import java.util.stream.Stream;

import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;

/**
 * Caracterización de {@link AOXMLDSigSigner} — fija el comportamiento actual de
 * {@code sign() / cosign() / isSign() / getData() / getSignersStructure()}
 * antes del refactor pendiente del método {@code sign()} (839 LoC).
 *
 * <p>Red de seguridad para la oleada de refactor estructural: cada test
 * asserta invariantes <em>observables</em> de la API pública (resultado no
 * vacío, reconocido por {@code isSign}, parseable como XML con un elemento
 * {@code <Signature>} del namespace XMLDSig, etc.) sin atarse a detalles
 * internos del proceso de firma.</p>
 *
 * <p>Reutiliza los fixtures existentes en {@code src/test/resources/}:
 * {@code PFActivoFirSHA256.pfx} (PKCS#12 de pruebas, alias
 * "fisico activo prueba", pass "12341234") y {@code sample-encoding-UTF-8.xml}.
 * </p>
 *
 * @see TestCountersignTargets para la cobertura específica de los 4 destinos
 *      de contrafirma (TREE/LEAFS/NODES/SIGNERS).
 */
final class TestAOXMLDSigSignerCharacterization {

	private static final String CERT_PATH = "PFActivoFirSHA256.pfx"; //$NON-NLS-1$
	private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
	private static final String CERT_ALIAS = "fisico activo prueba"; //$NON-NLS-1$
	private static final String XML_FIXTURE = "sample-encoding-UTF-8.xml"; //$NON-NLS-1$

	private static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"; //$NON-NLS-1$

	private static PrivateKeyEntry pke;
	private static byte[] xmlBytes;

	@BeforeAll
	static void loadFixtures() throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		ks.load(ClassLoader.getSystemResourceAsStream(CERT_PATH), CERT_PASS.toCharArray());
		pke = (PrivateKeyEntry) ks.getEntry(CERT_ALIAS,
				new KeyStore.PasswordProtection(CERT_PASS.toCharArray()));
		xmlBytes = AOUtil.getDataFromInputStream(
				ClassLoader.getSystemResourceAsStream(XML_FIXTURE));
		assertNotNull(pke, "Fixture PKCS#12 no se cargó"); //$NON-NLS-1$
		assertNotNull(xmlBytes, "Fixture XML no se cargó"); //$NON-NLS-1$
		assertTrue(xmlBytes.length > 0, "Fixture XML vacío"); //$NON-NLS-1$
	}

	// =====================================================================
	// sign(): 6 combinaciones format × mode × algoritmo
	// =====================================================================

	/** Combinaciones válidas para parametrización. */
	static Stream<Arguments> signCombinations() {
		return Stream.of(
				Arguments.of("ENVELOPING IMPLICIT SHA256", //$NON-NLS-1$
						AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPING,
						AOSignConstants.SIGN_MODE_IMPLICIT,
						AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA),
				Arguments.of("ENVELOPING EXPLICIT SHA256", //$NON-NLS-1$
						AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPING,
						AOSignConstants.SIGN_MODE_EXPLICIT,
						AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA),
				Arguments.of("ENVELOPED IMPLICIT SHA256", //$NON-NLS-1$
						AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPED,
						AOSignConstants.SIGN_MODE_IMPLICIT,
						AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA),
				Arguments.of("ENVELOPED IMPLICIT SHA512", //$NON-NLS-1$
						AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPED,
						AOSignConstants.SIGN_MODE_IMPLICIT,
						AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA),
				Arguments.of("DETACHED IMPLICIT SHA256", //$NON-NLS-1$
						AOSignConstants.SIGN_FORMAT_XMLDSIG_DETACHED,
						AOSignConstants.SIGN_MODE_IMPLICIT,
						AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA),
				Arguments.of("DETACHED EXPLICIT SHA256", //$NON-NLS-1$
						AOSignConstants.SIGN_FORMAT_XMLDSIG_DETACHED,
						AOSignConstants.SIGN_MODE_EXPLICIT,
						AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA));
	}

	@ParameterizedTest(name = "sign() con {0} produce firma XMLDSig válida")
	@MethodSource("signCombinations")
	@DisplayName("sign(): formato × modo × algoritmo → firma reconocible y bien formada")
	void testSignProducesValidXmlDSig(final String caseName,
			final String format, final String mode, final String algorithm) throws Exception {
		final byte[] signed = sign(xmlBytes, format, mode, algorithm);

		final AOXMLDSigSigner signer = new AOXMLDSigSigner();
		assertNotNull(signed, "Resultado de sign() no puede ser null"); //$NON-NLS-1$
		assertTrue(signed.length > 0, "Resultado de sign() no puede estar vacío"); //$NON-NLS-1$
		assertTrue(signer.isSign(signed), "Resultado debe identificarse como firma XML válida"); //$NON-NLS-1$

		final Document doc = parseXml(signed);
		final NodeList signatures = doc.getElementsByTagNameNS(XMLDSIG_NS, "Signature"); //$NON-NLS-1$
		assertTrue(signatures.getLength() >= 1,
				"El documento firmado debe contener al menos un <Signature> del namespace XMLDSig"); //$NON-NLS-1$
	}

	// =====================================================================
	// cosign(): los dos overloads
	// =====================================================================

	@Test
	@DisplayName("cosign(data, sign, ...) duplica el número de firmas en el documento")
	void testCosignWithOriginalDataAddsSecondSignature() throws Exception {
		final byte[] signed = sign(xmlBytes,
				AOSignConstants.SIGN_FORMAT_XMLDSIG_DETACHED,
				AOSignConstants.SIGN_MODE_IMPLICIT,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA);
		assertEquals(1, countSignatures(signed),
				"Pre-condición: la firma inicial debe tener una sola <Signature>"); //$NON-NLS-1$

		final byte[] cosigned = new AOXMLDSigSigner().cosign(xmlBytes, signed,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA,
				pke.getPrivateKey(), pke.getCertificateChain(), null);

		assertTrue(new AOXMLDSigSigner().isSign(cosigned),
				"cosigned debe seguir siendo una firma XML válida"); //$NON-NLS-1$
		assertEquals(2, countSignatures(cosigned),
				"cosign() debe añadir exactamente una <Signature> nueva"); //$NON-NLS-1$
	}

	@Test
	@DisplayName("cosign(sign, ...) acepta solo el documento firmado (sin data) y añade una segunda firma")
	void testCosignAcceptingOnlySignBytes() throws Exception {
		final byte[] signed = sign(xmlBytes,
				AOSignConstants.SIGN_FORMAT_XMLDSIG_DETACHED,
				AOSignConstants.SIGN_MODE_IMPLICIT,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA);

		final byte[] cosigned = new AOXMLDSigSigner().cosign(signed,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA,
				pke.getPrivateKey(), pke.getCertificateChain(), null);

		assertTrue(new AOXMLDSigSigner().isSign(cosigned),
				"cosigned debe seguir siendo una firma XML válida"); //$NON-NLS-1$
		assertEquals(2, countSignatures(cosigned),
				"cosign(sign) debe añadir exactamente una <Signature> nueva"); //$NON-NLS-1$
	}

	// =====================================================================
	// isSign(): true para firma, false para XML crudo / bytes arbitrarios
	// =====================================================================

	@Test
	@DisplayName("isSign() devuelve true para una firma generada por el propio signer")
	void testIsSignTrueForOwnOutput() throws Exception {
		final byte[] signed = sign(xmlBytes,
				AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPING,
				AOSignConstants.SIGN_MODE_IMPLICIT,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA);
		assertTrue(new AOXMLDSigSigner().isSign(signed));
	}

	@Test
	@DisplayName("isSign() devuelve false para el XML de entrada (sin firmar)")
	void testIsSignFalseForRawXml() {
		assertFalse(new AOXMLDSigSigner().isSign(xmlBytes),
				"El XML de fixture no contiene <Signature> y no debe identificarse como firma"); //$NON-NLS-1$
	}

	@Test
	@DisplayName("isSign() devuelve false para bytes no-XML (chequeo defensivo)")
	void testIsSignFalseForGarbageBytes() {
		final byte[] garbage = "no soy xml, soy basura arbitraria".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
		assertFalse(new AOXMLDSigSigner().isSign(garbage));
	}

	// =====================================================================
	// getData(): round-trip en modo IMPLICIT
	// =====================================================================

	@Test
	@DisplayName("getData() sobre firma DETACHED IMPLICIT recupera el XML original")
	void testGetDataRoundtripDetachedImplicit() throws Exception {
		final byte[] signed = sign(xmlBytes,
				AOSignConstants.SIGN_FORMAT_XMLDSIG_DETACHED,
				AOSignConstants.SIGN_MODE_IMPLICIT,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA);

		final byte[] recovered = new AOXMLDSigSigner().getData(signed);
		assertNotNull(recovered, "getData() no puede devolver null en modo IMPLICIT"); //$NON-NLS-1$
		assertTrue(recovered.length > 0, "getData() no puede devolver bytes vacíos"); //$NON-NLS-1$

		// El elemento raíz del XML recuperado debe coincidir con el del original (<CATALOG>).
		final Document originalDoc = parseXml(xmlBytes);
		final Document recoveredDoc = parseXml(recovered);
		assertEquals(originalDoc.getDocumentElement().getLocalName(),
				recoveredDoc.getDocumentElement().getLocalName(),
				"El root element recuperado debe coincidir con el del XML original"); //$NON-NLS-1$
	}

	// =====================================================================
	// getSignersStructure(): el árbol no es null y tiene al menos una raíz
	// =====================================================================

	@Test
	@DisplayName("getSignersStructure() devuelve un árbol no-null con la firma recién creada")
	void testGetSignersStructureReturnsNonNullTree() throws Exception {
		final byte[] signed = sign(xmlBytes,
				AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPING,
				AOSignConstants.SIGN_MODE_IMPLICIT,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA);

		final var tree = new AOXMLDSigSigner().getSignersStructure(signed, false);
		assertNotNull(tree, "getSignersStructure() no puede devolver null"); //$NON-NLS-1$
		assertNotNull(tree.getRoot(),
				"El árbol de signatarios debe tener una raíz"); //$NON-NLS-1$
	}

	// =====================================================================
	// encoding: el firmador no rompe XML UTF-8 ni ISO-8859-1
	// =====================================================================

	@Test
	@DisplayName("sign() preserva un XML UTF-8 con caracteres no-ASCII (áéíóúñ)")
	void testSignPreservesUtf8Content() throws Exception {
		final String xmlUtf8 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" //$NON-NLS-1$
				+ "<doc>caracteres acentuados: áéíóúñ €</doc>"; //$NON-NLS-1$
		final byte[] data = xmlUtf8.getBytes(StandardCharsets.UTF_8);

		final byte[] signed = sign(data,
				AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPING,
				AOSignConstants.SIGN_MODE_IMPLICIT,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA);

		assertTrue(new AOXMLDSigSigner().isSign(signed));
		final Document doc = parseXml(signed);
		assertEquals(1, doc.getElementsByTagNameNS(XMLDSIG_NS, "Signature").getLength()); //$NON-NLS-1$
	}

	@Test
	@DisplayName("sign() preserva un XML ISO-8859-1 con caracteres no-ASCII")
	void testSignPreservesIso88591Content() throws Exception {
		final String xmlIso = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>" //$NON-NLS-1$
				+ "<doc>acentos: áéíóúñ</doc>"; //$NON-NLS-1$
		final byte[] data = xmlIso.getBytes(StandardCharsets.ISO_8859_1);

		final byte[] signed = sign(data,
				AOSignConstants.SIGN_FORMAT_XMLDSIG_ENVELOPING,
				AOSignConstants.SIGN_MODE_IMPLICIT,
				AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA);

		assertTrue(new AOXMLDSigSigner().isSign(signed));
		final Document doc = parseXml(signed);
		assertEquals(1, doc.getElementsByTagNameNS(XMLDSIG_NS, "Signature").getLength()); //$NON-NLS-1$
	}

	// =====================================================================
	// helpers
	// =====================================================================

	private static byte[] sign(final byte[] data, final String format, final String mode,
			final String algorithm) throws Exception {
		final Properties extra = new Properties();
		extra.setProperty("format", format); //$NON-NLS-1$
		extra.setProperty("mode", mode); //$NON-NLS-1$
		return new AOXMLDSigSigner().sign(data, algorithm,
				pke.getPrivateKey(), pke.getCertificateChain(), extra);
	}

	private static int countSignatures(final byte[] xmlSign) throws Exception {
		return parseXml(xmlSign).getElementsByTagNameNS(XMLDSIG_NS, "Signature").getLength(); //$NON-NLS-1$
	}

	private static Document parseXml(final byte[] xml) throws Exception {
		final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		// Endurecido contra XXE en tests (defensa en profundidad; los fixtures son nuestros).
		factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); //$NON-NLS-1$
		factory.setFeature("http://xml.org/sax/features/external-general-entities", false); //$NON-NLS-1$
		factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false); //$NON-NLS-1$
		return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
	}
}
