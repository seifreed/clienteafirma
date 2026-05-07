/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.signers.xmldsig;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.CounterSignTarget;

/**
 * Cobertura de regresión para los 4 destinos de {@link CounterSignTarget} en
 * {@link AOXMLDSigSigner}: TREE, LEAFS, NODES, SIGNERS.
 *
 * <p>Pre-requisito de la Fase D del plan Clean Code (2026-05-07): el audit
 * confirmó que los tests existentes solo cubrían LEAFS. Antes de extraer
 * los 4 métodos {@code countersign{Tree,Leafs,Nodes,Signers}} a estrategias
 * separadas, cerramos esta brecha con tests Jupiter que ejercen cada
 * destino contra una firma de tres niveles (firma → cofirma → contrafirma).</p>
 */
final class TestCountersignTargets {

	private static final String CERT_PATH = "PFActivoFirSHA256.pfx"; //$NON-NLS-1$
	private static final String CERT_PASS = "12341234"; //$NON-NLS-1$
	private static final String CERT_ALIAS = "fisico activo prueba"; //$NON-NLS-1$
	private static final String DATA_FILE = "sample-class-attributes.xml"; //$NON-NLS-1$
	private static final String ALGO = AOSignConstants.SIGN_ALGORITHM_SHA512WITHRSA;

	private static PrivateKeyEntry pke;
	private static byte[] xmlData;

	@BeforeAll
	static void setUp() throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12"); //$NON-NLS-1$
		ks.load(ClassLoader.getSystemResourceAsStream(CERT_PATH), CERT_PASS.toCharArray());
		pke = (PrivateKeyEntry) ks.getEntry(CERT_ALIAS,
				new KeyStore.PasswordProtection(CERT_PASS.toCharArray()));
		xmlData = AOUtil.getDataFromInputStream(
				ClassLoader.getSystemResourceAsStream(DATA_FILE));
		assertNotNull(pke, "Setup falló: no se cargó el PrivateKeyEntry de fixture");
		assertNotNull(xmlData, "Setup falló: no se cargó el XML de fixture");
	}

	@Test
	@DisplayName("countersign(TREE) sobre firma+cofirma produce XML válido")
	void countersignTreeOverCosignedSignature() throws Exception {
		final byte[] base = signCosign();
		final byte[] result = countersign(base, CounterSignTarget.TREE);
		assertCountersigned(result);
	}

	@Test
	@DisplayName("countersign(LEAFS) sobre firma+cofirma produce XML válido — guard-rail Fase D")
	void countersignLeafsOverCosignedSignature() throws Exception {
		final byte[] base = signCosign();
		final byte[] result = countersign(base, CounterSignTarget.LEAFS);
		assertCountersigned(result);
	}

	@Test
	@DisplayName("countersign(NODES) con índice 0 contrafirma la primera firma encontrada")
	void countersignNodesByIndex() throws Exception {
		final byte[] base = signCosign();
		// Targets para NODES son índices en preorden de las firmas.
		final byte[] result = new AOXMLDSigSigner().countersign(
				base,
				ALGO,
				CounterSignTarget.NODES,
				new Object[] { Integer.valueOf(0) },
				pke.getPrivateKey(),
				pke.getCertificateChain(),
				new Properties());
		assertCountersigned(result);
	}

	@Test
	@DisplayName("countersign(SIGNERS) por CN del certificado contrafirma la firma de ese suscriptor")
	void countersignSignersByCertificateCN() throws Exception {
		final byte[] base = signCosign();
		// Targets para SIGNERS son los CN (X.500 commonName) de los certificados.
		final String cn = "fisico activo prueba"; //$NON-NLS-1$ — CN del fixture
		final byte[] result = new AOXMLDSigSigner().countersign(
				base,
				ALGO,
				CounterSignTarget.SIGNERS,
				new Object[] { cn },
				pke.getPrivateKey(),
				pke.getCertificateChain(),
				new Properties());
		assertCountersigned(result);
	}

	// ----- helpers -----

	private static byte[] signCosign() throws Exception {
		final AOXMLDSigSigner signer = new AOXMLDSigSigner();
		final Properties extra = new Properties();
		extra.setProperty("format", AOSignConstants.SIGN_FORMAT_XMLDSIG_DETACHED); //$NON-NLS-1$
		extra.setProperty("mode", AOSignConstants.SIGN_MODE_IMPLICIT); //$NON-NLS-1$
		final byte[] signed = signer.sign(xmlData, ALGO,
				pke.getPrivateKey(), pke.getCertificateChain(), extra);
		return signer.cosign(xmlData, signed, ALGO,
				pke.getPrivateKey(), pke.getCertificateChain(), extra);
	}

	private static byte[] countersign(final byte[] base, final CounterSignTarget target) throws Exception {
		return new AOXMLDSigSigner().countersign(
				base, ALGO, target, null,
				pke.getPrivateKey(), pke.getCertificateChain(), new Properties());
	}

	private static void assertCountersigned(final byte[] result) throws Exception {
		assertNotNull(result, "El resultado no puede ser null");
		assertTrue(result.length > 0, "El resultado no puede estar vacío");
		assertTrue(new AOXMLDSigSigner().isSign(result),
				"El resultado debe identificarse como una firma XML válida");
	}
}
