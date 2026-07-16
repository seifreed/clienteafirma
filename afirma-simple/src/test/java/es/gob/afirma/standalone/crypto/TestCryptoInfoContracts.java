package es.gob.afirma.standalone.crypto;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;

import javax.swing.ImageIcon;

import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.core.signers.AOTimestampInfo;
import es.gob.afirma.core.util.tree.AOTreeModel;
import es.gob.afirma.core.util.tree.AOTreeNode;

/** Pruebas de contratos de los contenedores de informacion criptografica. */
public final class TestCryptoInfoContracts {

	/** Comprueba que la informacion de certificado usa analizadores reales. */
	@Test
	public void testCertificateInformation() throws Exception {
		final X509Certificate genericCert = loadCertificate("afirma-core/src/test/resources/CERES.cer"); //$NON-NLS-1$
		final CertificateInfo genericInfo = CertAnalyzer.getCertInformation(genericCert);
		Assert.assertNotNull(genericInfo.getHolderName());
		Assert.assertNotNull(genericInfo.getIssuerName());
		Assert.assertNotNull(genericInfo.getIcon());
		Assert.assertNotNull(genericInfo.getIconTooltip());
		Assert.assertTrue(new GenericCertAnalyzer().isValidCert(genericCert));

		final X509Certificate dnieCert = loadCertificate("afirma-core/src/test/resources/DNIE01.cer"); //$NON-NLS-1$
		final DnieCertAnalyzer dnieAnalyzer = new DnieCertAnalyzer();
		Assert.assertTrue(dnieAnalyzer.isValidCert(dnieCert));
		Assert.assertFalse(dnieAnalyzer.isValidCert(null));
		Assert.assertFalse(dnieAnalyzer.isValidCert(genericCert));
		Assert.assertNotNull(dnieAnalyzer.analyzeCert(dnieCert).getHolderName());

		final ImageIcon icon = new ImageIcon(new byte[] { 1, 2, 3 });
		final CertificateInfo explicitInfo = new CertificateInfo(null, "Titular", icon, "Ayuda"); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals("Titular", explicitInfo.getHolderName()); //$NON-NLS-1$
		Assert.assertNull(explicitInfo.getIssuerName());
		Assert.assertSame(icon, explicitInfo.getIcon());
		Assert.assertEquals("Ayuda", explicitInfo.getIconTooltip()); //$NON-NLS-1$
	}

	/** Comprueba clonado, arboles y decodificacion de datos de firma. */
	@Test
	public void testCompleteSignInfoDefensiveCopiesAndTrees() throws Exception {
		final CompleteSignInfo info = new CompleteSignInfo();
		Assert.assertNull(info.getSignData());
		Assert.assertNull(info.getData());
		Assert.assertNull(info.getSignInfo());
		Assert.assertNull(info.getSignsTree());
		Assert.assertNull(info.getTimestampsInfo());
		Assert.assertNotNull(info.getTimestampsTree());

		final byte[] signData = new byte[] { 1, 2, 3 };
		info.setSignData(signData);
		signData[0] = 9;
		Assert.assertArrayEquals(new byte[] { 1, 2, 3 }, info.getSignData());
		final byte[] returnedSignData = info.getSignData();
		returnedSignData[1] = 9;
		Assert.assertArrayEquals(new byte[] { 1, 2, 3 }, info.getSignData());

		final byte[] data = new byte[] { 4, 5, 6 };
		info.setData(data);
		data[0] = 9;
		Assert.assertArrayEquals(new byte[] { 4, 5, 6 }, info.getData());
		final byte[] returnedData = info.getData();
		returnedData[1] = 9;
		Assert.assertArrayEquals(new byte[] { 4, 5, 6 }, info.getData());

		final byte[] png = new byte[] {
			(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n',
			0, 0, 0, 0, 'I', 'E', 'N', 'D'
		};
		info.setData(java.util.Base64.getEncoder().encode(png));
		Assert.assertArrayEquals(png, info.getData());
		info.setData(null);
		Assert.assertNull(info.getData());

		final AOTreeModel signsTree = new AOTreeModel(new AOTreeNode("raiz")); //$NON-NLS-1$
		info.setSignsTree(signsTree);
		Assert.assertSame(signsTree, info.getSignsTree());

		final X509Certificate cert = loadCertificate("afirma-core/src/test/resources/CERES.cer"); //$NON-NLS-1$
		final CompleteSignInfo timestampedInfo = new CompleteSignInfo();
		timestampedInfo.setTimestampsInfo(Collections.singletonList(new AOTimestampInfo(cert, new Date(0))));
		Assert.assertEquals(1, timestampedInfo.getTimestampsInfo().size());
		Assert.assertEquals(1, AOTreeModel.getChildCount((AOTreeNode) timestampedInfo.getTimestampsTree().getRoot()));
		Assert.assertTrue(TimestampsAnalyzer.getTimestamps(null).isEmpty());
		Assert.assertTrue(TimestampsAnalyzer.getTimestamps(null, new java.util.Properties()).isEmpty());
		Assert.assertTrue(TimestampsAnalyzer.getTimestamps("no-firma".getBytes()).isEmpty()); //$NON-NLS-1$
		Assert.assertNotNull(TimestampsAnalyzer.getTimestamps(readTestResource("TSA-2.pdf"))); //$NON-NLS-1$
		Assert.assertNotNull(TimestampsAnalyzer.getTimestamps(readTestResource("TSA-2.pdf"), new java.util.Properties())); //$NON-NLS-1$
		Assert.assertFalse(TimestampsAnalyzer.getTimestamps(readTestResource("CAdES-T.asn1")).isEmpty()); //$NON-NLS-1$
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
}
