package es.gob.afirma.signers.pkcs7;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.lang.reflect.Constructor;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.junit.jupiter.api.Test;

import es.gob.afirma.core.signers.AOSignConstants;

/** Pruebas locales de contratos PKCS#7 sin generar firmas. */
final class TestPkcs7LocalContracts {

	/** Comprueba parametros de firma, utilidades ASN.1 y excepciones locales. */
	@Test
	void localContractsExposeExpectedValues() throws Exception {
		final byte[] data = new byte[] { 1, 2, 3 };
		final P7ContentSignerParameters parameters = new P7ContentSignerParameters(data, null);
		data[0] = 9;
		assertArrayEquals(new byte[] { 1, 2, 3 }, parameters.getContent());
		parameters.getContent()[0] = 8;
		assertArrayEquals(new byte[] { 1, 2, 3 }, parameters.getContent());
		assertArrayEquals(new byte[0], parameters.getSignature());
		assertEquals(AOSignConstants.DEFAULT_SIGN_ALGO, parameters.getSignatureAlgorithm());
		assertEquals("SHA512withRSA", new P7ContentSignerParameters(null, "SHA512withRSA").getSignatureAlgorithm()); //$NON-NLS-1$ //$NON-NLS-2$

		final AlgorithmIdentifier algId = SigUtils.makeAlgId("1.2.840.113549.1.1.11"); //$NON-NLS-1$
		assertEquals("1.2.840.113549.1.1.11", algId.getAlgorithm().getId()); //$NON-NLS-1$
		assertEquals(2, SigUtils.createBerSetFromList(List.of(new DERUTF8String("a"), new DERUTF8String("b"))).size()); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(null, SigUtils.getAttributeSet(null));
		final Attribute attr = new Attribute(new ASN1ObjectIdentifier("1.2.3.4"), SigUtils.createBerSetFromList(List.of(new DERUTF8String("v")))); //$NON-NLS-1$ //$NON-NLS-2$
		final ASN1Set attrSet = SigUtils.getAttributeSet(new AttributeTable(attr));
		assertEquals(1, attrSet.size());

		final Exception cause = new Exception("causa"); //$NON-NLS-1$
		final ContainsNoDataException noData = new ContainsNoDataException("sin datos", cause); //$NON-NLS-1$
		assertEquals("sin datos", noData.getMessage()); //$NON-NLS-1$
		assertEquals(cause, noData.getCause());
		assertEquals(BinaryErrorCode.Functional.SIGNATURE_DOESNT_CONTAIN_DATA, noData.getErrorCode());

		final InvalidSpongyCastleException invalid = new InvalidSpongyCastleException("1", "2", cause); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("1", invalid.getExpectedVersion()); //$NON-NLS-1$
		assertEquals("2", invalid.getFoundVersion()); //$NON-NLS-1$
		assertEquals(cause, invalid.getCause());
		assertEquals("211001", BinaryErrorCode.Internal.UNKWNON_BINARY_SIGNING_ERROR.getCode()); //$NON-NLS-1$
		assertEquals("211002", BinaryErrorCode.Internal.INTERNAL_BINARY_SIGNING_ERROR.getCode()); //$NON-NLS-1$
		assertEquals("211003", BinaryErrorCode.Internal.GENERATING_TIMESTAMP_ERROR.getCode()); //$NON-NLS-1$

		final Constructor<SigUtils> constructor = SigUtils.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
		assertNotNull(new BinaryErrorCode());
		assertNotNull(new BinaryErrorCode.Internal());
		assertNotNull(new BinaryErrorCode.Functional());
		assertNotNull(new BinaryErrorCode.ThirdParty());
	}

	/** Comprueba estructuras ASN.1 PKCS#7 locales. */
	@Test
	void asn1StructuresRoundTrip() {
		final AlgorithmIdentifier digestAlgorithm = SigUtils.makeAlgId("1.3.14.3.2.26"); //$NON-NLS-1$
		final ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers.data, new DEROctetString(new byte[] { 1 }));
		final ASN1OctetString digest = new DEROctetString(new byte[] { 2 });
		final DigestedData digestedData = new DigestedData(digestAlgorithm, contentInfo, digest);
		assertEquals("0", digestedData.getVersion()); //$NON-NLS-1$
		assertEquals("1.3.14.3.2.26", digestedData.getDigestAlgorithm()); //$NON-NLS-1$
		assertEquals(CMSObjectIdentifiers.data.getId(), digestedData.getContentType());
		assertArrayEquals(new byte[] { 2 }, digestedData.getDigest().getOctets());
		assertNotNull(digestedData.toASN1Primitive());
		assertEquals("0", DigestedData.getInstance(ASN1Sequence.getInstance(digestedData.toASN1Primitive())).getVersion()); //$NON-NLS-1$
		assertEquals(digestedData, DigestedData.getInstance(digestedData));

		final ASN1Set emptySet = SigUtils.createBerSetFromList(List.of());
		final EncryptedContentInfo encryptedContentInfo = new EncryptedContentInfo(
			CMSObjectIdentifiers.data,
			SigUtils.makeAlgId("1.2.840.113549.3.7"), //$NON-NLS-1$
			new DEROctetString(new byte[] { 3 })
		);
		final SignedAndEnvelopedData signed = new SignedAndEnvelopedData(
			emptySet,
			emptySet,
			encryptedContentInfo,
			emptySet,
			null,
			emptySet
		);
		assertEquals(1, signed.getVersion().intValueExact());
		assertEquals(emptySet, signed.getRecipientInfos());
		assertEquals(emptySet, signed.getDigestAlgorithms());
		assertEquals(encryptedContentInfo, signed.getEncryptedContentInfo());
		assertEquals(emptySet, signed.getCertificates());
		assertEquals(emptySet, signed.getSignerInfos());
		assertNotNull(signed.toASN1Primitive());
		assertEquals(signed, SignedAndEnvelopedData.getInstance(signed));
		assertEquals(null, SignedAndEnvelopedData.getInstance(null));
	}
}
