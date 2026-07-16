package es.gob.afirma.standalone.signdetails;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.core.signers.AdESPolicy;
import es.gob.afirma.core.util.tree.AOTreeModel;
import es.gob.afirma.core.util.tree.AOTreeNode;
import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.SignValidity.SIGN_DETAIL_TYPE;
import es.gob.afirma.signvalidation.SignValidity.VALIDITY_ERROR;
import es.gob.afirma.standalone.SimpleAfirmaMessages;

/** Pruebas de contratos de detalles de firma. */
public final class TestSignDetailsContracts {

	/** Comprueba getters y setters de los detalles basicos. */
	@Test
	public void testBasicDetailContainers() throws Exception {
		final DataObjectFormat dataObjectFormat = new DataObjectFormat("application/pdf"); //$NON-NLS-1$
		dataObjectFormat.setIdentifier("id"); //$NON-NLS-1$
		dataObjectFormat.setDescription("documento"); //$NON-NLS-1$
		dataObjectFormat.setEncoding("UTF-8"); //$NON-NLS-1$
		Assert.assertEquals("id", dataObjectFormat.getIdentifier()); //$NON-NLS-1$
		Assert.assertEquals("documento", dataObjectFormat.getDescription()); //$NON-NLS-1$
		Assert.assertEquals("application/pdf", dataObjectFormat.getMimeType()); //$NON-NLS-1$
		Assert.assertEquals("UTF-8", dataObjectFormat.getEncoding()); //$NON-NLS-1$
		dataObjectFormat.setMimeType("text/xml"); //$NON-NLS-1$
		Assert.assertEquals("text/xml", dataObjectFormat.getMimeType()); //$NON-NLS-1$

		final AdESPolicy adesPolicy = new AdESPolicy(
			"1.3.6.1.4.1.5734.3.7", //$NON-NLS-1$
			"AQIDBA==", //$NON-NLS-1$
			"SHA-256", //$NON-NLS-1$
			"https://example.test/policy.pdf" //$NON-NLS-1$
		);
		final SignaturePolicy signaturePolicy = new SignaturePolicy("Politica", adesPolicy); //$NON-NLS-1$
		Assert.assertEquals("Politica", signaturePolicy.getName()); //$NON-NLS-1$
		Assert.assertSame(adesPolicy, signaturePolicy.getPolicy());
		signaturePolicy.setName("Politica 2"); //$NON-NLS-1$
		signaturePolicy.setPolicy(SignDetails.POLICY_CADES_AGE_1_9);
		Assert.assertEquals("Politica 2", signaturePolicy.getName()); //$NON-NLS-1$
		Assert.assertSame(SignDetails.POLICY_CADES_AGE_1_9, signaturePolicy.getPolicy());

		final X509Certificate cert = loadCertificate("afirma-core/src/test/resources/CERES.cer"); //$NON-NLS-1$
		final CertificateDetails certDetails = new CertificateDetails(cert);
		Assert.assertNotNull(certDetails.getName());
		Assert.assertNotNull(certDetails.getIssuerName());
		Assert.assertNotNull(certDetails.getExpirationDate());
		Assert.assertNotNull(certDetails.getValidityResult());
		Assert.assertTrue(certDetails.getSubCertDetails().isEmpty());
		certDetails.setName("Titular"); //$NON-NLS-1$
		certDetails.setIssuerName("Emisor"); //$NON-NLS-1$
		certDetails.setExpirationDate("01-01-2030"); //$NON-NLS-1$
		final Properties validity = new Properties();
		validity.setProperty("clave", "valor"); //$NON-NLS-1$ //$NON-NLS-2$
		certDetails.setValidityResult(validity);
		Assert.assertEquals("Titular", certDetails.getName()); //$NON-NLS-1$
		Assert.assertEquals("Emisor", certDetails.getIssuerName()); //$NON-NLS-1$
		Assert.assertEquals("01-01-2030", certDetails.getExpirationDate()); //$NON-NLS-1$
		Assert.assertSame(validity, certDetails.getValidityResult());
	}

	/** Comprueba el formateo HTML con estructuras de detalle completas. */
	@Test
	public void testFormatterWithRealDetailObjects() throws Exception {
		final SignDetails detail = new SignDetails();
		detail.setSignProfile("EPES"); //$NON-NLS-1$
		detail.setAlgorithm("SHA256withRSA"); //$NON-NLS-1$
		detail.setSigningTime(new Date(0));
		detail.setDataIncluded(Boolean.TRUE);
		detail.setDataLocation("datos incluidos"); //$NON-NLS-1$
		detail.setCertificationLevel(2);
		detail.setCertificationSign(Boolean.TRUE);
		detail.setLastRevisionSign(Boolean.FALSE);

		final DataObjectFormat format = new DataObjectFormat("application/pdf"); //$NON-NLS-1$
		format.setDescription("Factura"); //$NON-NLS-1$
		format.setEncoding("UTF-8"); //$NON-NLS-1$
		detail.setDataObjectFormats(Arrays.asList(format, new DataObjectFormat("application/custom"))); //$NON-NLS-1$

		final Map<String, String> metadata = new HashMap<>();
		metadata.put("claimedRole.1", "firmante"); //$NON-NLS-1$ //$NON-NLS-2$
		metadata.put(SignDetailsFormatter.CITY_METADATA, "Madrid"); //$NON-NLS-1$
		metadata.put(SignDetailsFormatter.COUNTRY_METADATA, "ES"); //$NON-NLS-1$
		metadata.put(SignDetailsFormatter.SIGN_REASON_METADATA, "Aprobacion"); //$NON-NLS-1$
		detail.setMetadata(metadata);

		final AdESPolicy policy = new AdESPolicy(
			"1.3.6.1.4.1.5734.3.8", //$NON-NLS-1$
			"AQIDBA==", //$NON-NLS-1$
			"SHA-256", //$NON-NLS-1$
			"https://example.test/custom-policy.pdf" //$NON-NLS-1$
		);
		detail.setPolicy(new SignaturePolicy("Politica personalizada", policy)); //$NON-NLS-1$
		detail.setValidityResult(Arrays.asList(
			new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.NO_MATCH_DATA),
			new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.CERTIFICATE_EXPIRED)
		));

		final CertificateDetails signer = new CertificateDetails(loadCertificate("afirma-core/src/test/resources/CERES.cer")); //$NON-NLS-1$
		final Properties certValidity = new Properties();
		certValidity.setProperty(
			SimpleAfirmaMessages.getString("ValidationInfoDialog.68"), //$NON-NLS-1$
			SimpleAfirmaMessages.getString("ValidationInfoDialog.2") //$NON-NLS-1$
		);
		signer.setValidityResult(certValidity);
		detail.setSigner(signer);

		final AOTreeNode root = new AOTreeNode("raiz"); //$NON-NLS-1$
		final AOTreeNode first = new AOTreeNode("firmante 1"); //$NON-NLS-1$
		first.add(new AOTreeNode("cofirma")); //$NON-NLS-1$
		root.add(first);

		final String html = SignDetailsFormatter.formatToHTML(
			new FixedSignAnalyzer(Arrays.asList(detail), new AOTreeModel(root), "PAdES", "datos incluidos"), //$NON-NLS-1$ //$NON-NLS-2$
			Arrays.asList(
				new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.MODIFIED_DOCUMENT),
				new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.CERTIFICATE_PROBLEM)
			)
		);
		Assert.assertTrue(html.contains("PAdES")); //$NON-NLS-1$
		Assert.assertTrue(html.contains("SHA256withRSA")); //$NON-NLS-1$
		Assert.assertTrue(html.contains("Factura")); //$NON-NLS-1$
		Assert.assertTrue(html.contains("application/custom")); //$NON-NLS-1$
		Assert.assertTrue(html.contains("Politica personalizada")); //$NON-NLS-1$
		Assert.assertTrue(html.contains("firmante")); //$NON-NLS-1$
		Assert.assertTrue(html.contains("Madrid")); //$NON-NLS-1$
		Assert.assertTrue(html.contains("cofirma")); //$NON-NLS-1$

		final SignDetails facturaeDetail = new SignDetails();
		facturaeDetail.setValidityResult(Arrays.asList(new SignValidity(SIGN_DETAIL_TYPE.OK, null)));
		final String facturaeHtml = SignDetailsFormatter.formatToHTML(
			new FixedSignAnalyzer(Arrays.asList(facturaeDetail), null, FacturaESignAnalyzer.FACTURAE, null),
			Arrays.asList(new SignValidity(SIGN_DETAIL_TYPE.OK, null))
		);
		Assert.assertFalse(facturaeHtml.contains("<b>Perfil")); //$NON-NLS-1$
	}

	/** Comprueba analizadores reales con firmas XML de recursos. */
	@Test
	public void testRealXmlAnalyzersWithFixtures() throws Exception {
		final FacturaESignAnalyzer facturae = new FacturaESignAnalyzer(readTestResource("sample-factura-firmada-31.xml")); //$NON-NLS-1$
		Assert.assertEquals(FacturaESignAnalyzer.FACTURAE, facturae.getSignFormat());
		Assert.assertNull(facturae.getDataLocation());
		Assert.assertNotNull(facturae.getSignersTree());
		Assert.assertFalse(facturae.getAllSignDetails().isEmpty());

		final XAdESSignAnalyzer xades = new XAdESSignAnalyzer(readTestResource("samples/2_xml_signed.xsig")); //$NON-NLS-1$
		Assert.assertEquals("XAdES", xades.getSignFormat()); //$NON-NLS-1$
		Assert.assertNotNull(xades.getSignersTree());
		Assert.assertFalse(xades.getAllSignDetails().isEmpty());
	}

	/** Comprueba analizadores reales con firmas CAdES y PAdES de recursos. */
	@Test
	public void testRealBinaryAnalyzersWithFixtures() throws Exception {
		final CAdESSignAnalyzer cades = new CAdESSignAnalyzer(readTestResource("cades_explicit.csig")); //$NON-NLS-1$
		Assert.assertEquals("CAdES", cades.getSignFormat()); //$NON-NLS-1$
		Assert.assertNotNull(cades.getDataLocation());
		Assert.assertNotNull(cades.getSignersTree());
		Assert.assertFalse(cades.getAllSignDetails().isEmpty());
		Assert.assertNotNull(cades.getAllSignDetails().get(0).getSigner());

		final PAdESSignAnalyzer pades = new PAdESSignAnalyzer(readTestResource("DOSFIRMAS.pdf")); //$NON-NLS-1$
		Assert.assertEquals(PAdESSignAnalyzer.PADES, pades.getSignFormat());
		Assert.assertNull(pades.getDataLocation());
		Assert.assertNotNull(pades.getSignersTree());
		Assert.assertFalse(pades.getAllSignDetails().isEmpty());
		Assert.assertNotNull(pades.getAllSignDetails().get(0).getSigner());
	}

	private static X509Certificate loadCertificate(final String path) throws Exception {
		Path certPath = Paths.get(path);
		if (!Files.isRegularFile(certPath)) {
			certPath = Paths.get("..").resolve(path); //$NON-NLS-1$
		}
		try (FileInputStream fis = new FileInputStream(certPath.toFile())) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis); //$NON-NLS-1$
		}
	}

	private static byte[] readTestResource(final String resource) throws IOException {
		Path resourcePath = Paths.get("afirma-simple", "src", "test", "resources", resource); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		if (!Files.isRegularFile(resourcePath)) {
			resourcePath = Paths.get("src", "test", "resources", resource); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		}
		if (!Files.isRegularFile(resourcePath)) {
			resourcePath = Paths.get("..").resolve(Paths.get("afirma-simple", "src", "test", "resources", resource)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
		}
		return Files.readAllBytes(resourcePath);
	}

	private static final class FixedSignAnalyzer implements SignAnalyzer {

		private final List<SignDetails> details;
		private final AOTreeModel signersTree;
		private final String signFormat;
		private final String dataLocation;

		FixedSignAnalyzer(final List<SignDetails> details,
				          final AOTreeModel signersTree,
				          final String signFormat,
				          final String dataLocation) {
			this.details = details;
			this.signersTree = signersTree;
			this.signFormat = signFormat;
			this.dataLocation = dataLocation;
		}

		@Override
		public AOTreeModel getSignersTree() {
			return this.signersTree;
		}

		@Override
		public String getSignFormat() {
			return this.signFormat;
		}

		@Override
		public String getDataLocation() {
			return this.dataLocation;
		}

		@Override
		public List<SignDetails> getAllSignDetails() {
			return this.details;
		}
	}
}
