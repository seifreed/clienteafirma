package es.gob.afirma.cert.signvalidation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.aowagie.text.pdf.PdfDictionary;
import com.aowagie.text.pdf.PdfName;
import com.aowagie.text.pdf.PdfReader;
import com.aowagie.text.pdf.PdfString;

import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AOSignerFactory;
import es.gob.afirma.signvalidation.InvalidSignatureException;
import es.gob.afirma.signvalidation.ISignatureFormatDetector;
import es.gob.afirma.signvalidation.PDFSignatureDictionary;
import es.gob.afirma.signvalidation.SignValiderFactory;
import es.gob.afirma.signvalidation.SignValidity;
import es.gob.afirma.signvalidation.SignValidity.SIGN_DETAIL_TYPE;
import es.gob.afirma.signvalidation.SignValidity.VALIDITY_ERROR;
import es.gob.afirma.signvalidation.SignatureFormatDetectorPadesCades;
import es.gob.afirma.signvalidation.SignatureFormatDetectorXades;
import es.gob.afirma.signvalidation.ValidationMessages;
import es.gob.afirma.signvalidation.ValidateBinarySignature;
import es.gob.afirma.signers.xml.Utils;

/** Pruebas de validaci&oacute;n de firmas.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public class TestSignatureValidation {

	private static final String CADES_IMPLICIT_FILE = "cades_implicit.csig"; //$NON-NLS-1$
	private static final String CADES_EXPLICIT_FILE = "cades_explicit.csig"; //$NON-NLS-1$
	private static final String DATA_TXT_FILE = "txt"; //$NON-NLS-1$
	private static final String PADES_FILE = "pades.pdf"; //$NON-NLS-1$
	private static final String PADES_EPES_FILE = "pades_epes.pdf"; //$NON-NLS-1$
	private static final String XADES_EPES_FILE = "xades_epes_detached.xsig"; //$NON-NLS-1$

	/** Prueba de validaci&oacute;n de firma CAdES.
	 * @throws Exception En cualquier error. */
	@Test
	public void testCadesImplicitValidation() throws Exception {
		try (
			final InputStream is = ClassLoader.getSystemResourceAsStream(CADES_IMPLICIT_FILE);
		) {
			final byte[] cades = AOUtil.getDataFromInputStream(is);
			System.out.println(new ValidateBinarySignature().validate(cades, false));
		}
	}

	/** Prueba de validaci&oacute;n de firma CAdES explicita sin datos.
	 * @throws Exception En cualquier error. */
	@Test
	public void testCadesExplicitValidationWithoutData() throws Exception {
		try (
			final InputStream is = ClassLoader.getSystemResourceAsStream(CADES_EXPLICIT_FILE);
		) {
			final byte[] cades = AOUtil.getDataFromInputStream(is);
			System.out.println(new ValidateBinarySignature().validate(cades, false));
		}
	}

	/** Prueba de validaci&oacute;n de firma CAdES expl&iacute;cita con los datos.
	 * @throws Exception En cualquier error. */
	@Test
	public void testCadesExplicitValidationWithData() throws Exception {
		try (
			final InputStream is = ClassLoader.getSystemResourceAsStream(CADES_EXPLICIT_FILE);
			final InputStream dataIs = ClassLoader.getSystemResourceAsStream(DATA_TXT_FILE);
		) {
			final byte[] cades = AOUtil.getDataFromInputStream(is);
			final byte[] data = AOUtil.getDataFromInputStream(dataIs);
			System.out.println(ValidateBinarySignature.validate(cades, data, false));
		}
	}

	/** Prueba de validaci&oacute;n de firma CAdES expl&iacute;cita con datos erroneos.
	 * @throws Exception En cualquier error. */
	@Test
	public void testCadesExplicitValidationWrongData() throws Exception {
		try (
			final InputStream is = ClassLoader.getSystemResourceAsStream(CADES_EXPLICIT_FILE);
		) {
			final byte[] cades = AOUtil.getDataFromInputStream(is);
			System.out.println(ValidateBinarySignature.validate(cades, "dummy2".getBytes(), false));
		}
	}

	/** Prueba de validaci&oacute;n de firma PAdES.
	 * @throws Exception En cualquier error. */
	@Test
	public void testPadesValidation() throws Exception {
		try (
			final InputStream is = ClassLoader.getSystemResourceAsStream(PADES_FILE);
		) {
			final byte[] pades = AOUtil.getDataFromInputStream(is);
			System.out.println(SignValiderFactory.getSignValider(pades).validate(pades, false));
		}
	}

	/** Prueba de validaci&oacute;n de firma PAdES-EPES.
	 * @throws Exception En cualquier error. */
	@Test
	public void testPadesEpesValidation() throws Exception {
		try (
			final InputStream is = ClassLoader.getSystemResourceAsStream(PADES_EPES_FILE);
		) {
			final byte[] pades = AOUtil.getDataFromInputStream(is);
			System.out.println(SignValiderFactory.getSignValider(pades).validate(pades, false));
		}
	}

	/** Prueba de validaci&oacute;n de firma PAdES-EPES.
	 * @throws Exception En cualquier error. */
	@Test
	public void testXadesEpesValidation() throws Exception {
		try (
			final InputStream is = ClassLoader.getSystemResourceAsStream(XADES_EPES_FILE);
		) {
			final byte[] signature = AOUtil.getDataFromInputStream(is);
			System.out.println(SignValiderFactory.getSignValider(signature).validate(signature, false));
		}
	}

	/** Prueba de detecci&oacute;n de formatos con firmas reales.
	 * @throws Exception En cualquier error. */
	@Test
	public void testSignatureFormatDetectorsWithFixtures() throws Exception {
		final byte[] pades = readResource(PADES_FILE);
		final byte[] padesEpes = readResource(PADES_EPES_FILE);
		final byte[] cades = readResource(CADES_IMPLICIT_FILE);
		final byte[] cadesExplicit = readResource(CADES_EXPLICIT_FILE);
		final byte[] xadesEpes = readResource(XADES_EPES_FILE);

		assertNotEquals(
			ISignatureFormatDetector.FORMAT_UNRECOGNIZED,
			SignatureFormatDetectorPadesCades.resolvePDFFormat(pades)
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_UNRECOGNIZED,
			SignatureFormatDetectorPadesCades.resolvePDFFormat(padesEpes)
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_B_LEVEL,
			SignatureFormatDetectorXades.getSignatureFormat(xadesEpes)
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_UNRECOGNIZED,
			SignatureFormatDetectorXades.getSignatureFormat("no es xml".getBytes()) //$NON-NLS-1$
		);
		assertTrue(!SignatureFormatDetectorPadesCades.isASN1Format(cades));
		assertTrue(!SignatureFormatDetectorPadesCades.isASN1Format(cadesExplicit));
		assertTrue(!SignatureFormatDetectorPadesCades.isASN1Format(pades));
		assertTrue(!SignatureFormatDetectorPadesCades.isASN1Format(null));
		assertNotEquals(
			ISignatureFormatDetector.FORMAT_UNRECOGNIZED,
			resolveFirstCadesSignerFormat(cadesExplicit)
		);
		assertTrue(SignatureFormatDetectorXades.isXAdESBaseline(ISignatureFormatDetector.FORMAT_XADES_B_LEVEL));
		assertTrue(!SignatureFormatDetectorXades.isXAdESBaseline(ISignatureFormatDetector.FORMAT_XADES_BES));
	}

	/** Prueba contratos p&uacute;blicos sobre diccionarios PDF de firma. */
	@Test
	public void testPdfSignatureDictionaryContracts() throws Exception {
		final PdfDictionary basicDictionary = new PdfDictionary();
		basicDictionary.put(PdfName.SUBFILTER, PdfName.ADBE_PKCS7_DETACHED);
		final PDFSignatureDictionary basic = new PDFSignatureDictionary(1, basicDictionary, "firma1"); //$NON-NLS-1$
		assertEquals(Integer.valueOf(1), basic.getRevision());
		assertEquals("firma1", basic.getName()); //$NON-NLS-1$
		assertTrue(SignatureFormatDetectorPadesCades.isPAdESBasic(basic));
		assertTrue(!SignatureFormatDetectorPadesCades.isPDF(basic));
		assertTrue(!SignatureFormatDetectorPadesCades.isPAdESEPES(basic));
		assertTrue(!SignatureFormatDetectorPadesCades.isPAdESBES(basic));

		final PdfDictionary pdfDictionary = new PdfDictionary();
		pdfDictionary.put(PdfName.SUBFILTER, new PdfName("adbe.x509.rsa_sha1")); //$NON-NLS-1$
		final PDFSignatureDictionary pdf = new PDFSignatureDictionary(2, pdfDictionary, "firma2"); //$NON-NLS-1$
		assertTrue(SignatureFormatDetectorPadesCades.isPDF(pdf));
		assertTrue(!SignatureFormatDetectorPadesCades.isPAdESBasic(pdf));

		final PdfDictionary invalidCadesDictionary = new PdfDictionary();
		invalidCadesDictionary.put(PdfName.SUBFILTER, SignatureFormatDetectorPadesCades.CADES_SUBFILTER_VALUE);
		invalidCadesDictionary.put(PdfName.M, new PdfString("D:20260101000000+01'00'")); //$NON-NLS-1$
		invalidCadesDictionary.put(PdfName.CONTENTS, new PdfString("no es CMS")); //$NON-NLS-1$
		final PDFSignatureDictionary invalidCades = new PDFSignatureDictionary(4, invalidCadesDictionary, "firma-cades"); //$NON-NLS-1$
		assertTrue(!SignatureFormatDetectorPadesCades.isPDF(invalidCades));
		assertTrue(!SignatureFormatDetectorPadesCades.isPAdESBasic(invalidCades));
		assertTrue(!SignatureFormatDetectorPadesCades.isPAdESEPES(invalidCades));
		assertTrue(!SignatureFormatDetectorPadesCades.isPAdESBES(invalidCades));
		assertThrows(Exception.class, () -> SignatureFormatDetectorPadesCades.getCMSSignature(invalidCades));
		assertEquals(-1, basic.compareTo(pdf));
		basic.setRevision(3);
		basic.setName("firma3"); //$NON-NLS-1$
		basic.setDictionary(pdfDictionary);
		assertEquals(Integer.valueOf(3), basic.getRevision());
		assertEquals("firma3", basic.getName()); //$NON-NLS-1$
		assertEquals(pdfDictionary, basic.getDictionary());

		final PdfReader reader = new PdfReader(readResource(PADES_FILE));
		final PDFSignatureDictionary latest = SignatureFormatDetectorPadesCades.obtainLatestSignatureFromPDF(reader);
		assertNotNull(latest);
		assertThrows(Exception.class, () -> SignatureFormatDetectorPadesCades.getCMSSignature(latest));
		reader.close();
	}

	/** Prueba de detecci&oacute;n XAdES sobre estructuras XML m&iacute;nimas. */
	@Test
	public void testSyntheticXadesFormatDetection() throws Exception {
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_BES,
			resolveSyntheticSignerFormat("", "") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_EPES,
			resolveSyntheticSignerFormat("<xades:SignaturePolicyIdentifier/>", "") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_B_LEVEL,
			resolveSyntheticSignerFormat(baselineSignedProperties("xades:SigningCertificate"), "") //$NON-NLS-1$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_T_LEVEL,
			resolveSyntheticSignerFormat(baselineSignedProperties("xades:SigningCertificate"), "<xades:SignatureTimeStamp/>") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_LT_LEVEL,
			resolveSyntheticSignerFormat(baselineSignedProperties("xades:SigningCertificate"), "<xades:SignatureTimeStamp/><xadesv141:TimeStampValidationData/>") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_LTA_LEVEL,
			resolveSyntheticSignerFormat(baselineSignedProperties("xades:SigningCertificate"), "<xades:SignatureTimeStamp/><xadesv141:TimeStampValidationData/><xades:ArchiveTimeStamp/>") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_A,
			resolveSyntheticSignerFormat("", "<xades:ArchiveTimeStamp/>") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_XL1,
			resolveSyntheticSignerFormat("", "<xades:SigAndRefsTimeStamp/><xades:CertificateValues/><xades:RevocationValues/>") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_XL2,
			resolveSyntheticSignerFormat("", "<xades:RefsOnlyTimeStamp/><xades:CertificateValues/><xades:RevocationValues/>") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_X1,
			resolveSyntheticSignerFormat("", "<xades:SigAndRefsTimeStamp/>") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_X2,
			resolveSyntheticSignerFormat("", "<xades:RefsOnlyTimeStamp/>") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_C,
			resolveSyntheticSignerFormat("", "<xades:CompleteCertificateRefs/><xades:CompleteRevocationRefs/>") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_XADES_T,
			resolveSyntheticSignerFormat("", "<xades:SignatureTimeStamp/>") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			ISignatureFormatDetector.FORMAT_UNRECOGNIZED,
			SignatureFormatDetectorXades.resolveSignerXAdESFormat(null)
		);
	}

	/** Prueba contratos locales de resultado y factor&iacute;a de validaci&oacute;n. */
	@Test
	public void testValidationLocalContracts() throws Exception {
		assertEquals("!missing.validation.key!", ValidationMessages.getString("missing.validation.key")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class, () -> SignValiderFactory.getSignValider(new byte[0]));
		assertNotNull(SignValiderFactory.getSignValider(AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_CADES)));
		assertNotNull(SignValiderFactory.getSignValider(AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_XADES_DETACHED)));
		assertNotNull(SignValiderFactory.getSignValider(AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_PDF)));
		assertNull(SignValiderFactory.getSignValider(AOSignerFactory.getSigner(AOSignConstants.SIGN_FORMAT_ODF)));

		final InvalidSignatureException exception = new InvalidSignatureException("firma invalida"); //$NON-NLS-1$
		assertEquals(exception.getErrorCode(), new InvalidSignatureException(new IllegalStateException()).getErrorCode());
		assertEquals(exception.getErrorCode(), new InvalidSignatureException("firma invalida", new IllegalStateException()).getErrorCode()); //$NON-NLS-1$
		assertNotNull(Class.forName("es.gob.afirma.signvalidation.ValidationErrorCode").getDeclaredConstructor().newInstance()); //$NON-NLS-1$
		final Field field = Class.forName("es.gob.afirma.signvalidation.ValidationErrorCode$Functional").getDeclaredField("INCOMPATIBLE_SIGNATURE"); //$NON-NLS-1$ //$NON-NLS-2$
		field.setAccessible(true);
		assertEquals("507001", ((ErrorCode) field.get(null)).getCode()); //$NON-NLS-1$
		final SignValidity valid = new SignValidity(SIGN_DETAIL_TYPE.OK, null);
		assertEquals(SIGN_DETAIL_TYPE.OK, valid.getValidity());
		assertNull(valid.getError());
		assertNull(valid.getErrorException());
		assertNull(valid.getErrorCode());
		assertNotNull(valid.toString());

		final SignValidity invalid = new SignValidity(SIGN_DETAIL_TYPE.KO, VALIDITY_ERROR.BAD_BUILD_SIGN, exception);
		assertEquals(VALIDITY_ERROR.BAD_BUILD_SIGN, invalid.getError());
		assertEquals(exception, invalid.getErrorException());
		assertEquals(exception.getErrorCode(), invalid.getErrorCode());
		assertNotNull(invalid.toString());

		for (final SIGN_DETAIL_TYPE type : SIGN_DETAIL_TYPE.values()) {
			assertNotNull(new SignValidity(type, null).validityTypeToString());
		}
		for (final VALIDITY_ERROR error : VALIDITY_ERROR.values()) {
			assertNotNull(new SignValidity(SIGN_DETAIL_TYPE.KO, error).toString());
		}
	}

	private static byte[] readResource(final String resource) throws Exception {
		try (InputStream is = ClassLoader.getSystemResourceAsStream(resource)) {
			assertNotNull(is);
			return AOUtil.getDataFromInputStream(is);
		}
	}

	private static String resolveFirstCadesSignerFormat(final byte[] signature) throws Exception {
		final CMSSignedData signedData = new CMSSignedData(signature);
		final SignerInformation signer = signedData.getSignerInfos().getSigners().iterator().next();
		return SignatureFormatDetectorPadesCades.resolveASN1Format(signedData, signer);
	}

	private static String resolveSyntheticSignerFormat(final String signedSignatureExtras, final String unsignedExtras) throws Exception {
		final byte[] xml = syntheticXades(signedSignatureExtras, unsignedExtras);
		final Document doc = Utils.getNewDocumentBuilder().parse(new ByteArrayInputStream(xml));
		final Element signature = SignatureFormatDetectorXades.getListSignatures(doc).get(0);
		assertEquals(SignatureFormatDetectorXades.resolveSignerXAdESFormat(signature), SignatureFormatDetectorXades.getSignatureFormat(xml));
		assertEquals(signedSignatureExtras.contains("SignaturePolicyIdentifier"), SignatureFormatDetectorXades.hasSignaturePolicyIdentifier(signature)); //$NON-NLS-1$
		return SignatureFormatDetectorXades.resolveSignerXAdESFormat(signature);
	}

	private static byte[] syntheticXades(final String signedSignatureExtras, final String unsignedExtras) {
		final String xml =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + //$NON-NLS-1$
			"<root xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" xmlns:xadesv141=\"http://uri.etsi.org/01903/v1.4.1#\">" + //$NON-NLS-1$
			"<ds:Signature><xades:QualifyingProperties><xades:SignedProperties>" + //$NON-NLS-1$
			"<xades:SignedSignatureProperties><xades:SigningTime/>" + signedSignatureExtras + "</xades:SignedSignatureProperties>" + //$NON-NLS-1$
			"<xades:SignedDataObjectProperties><xades:DataObjectFormat><xades:MimeType>text/plain</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties>" + //$NON-NLS-1$
			"</xades:SignedProperties><xades:UnsignedProperties><xades:UnsignedSignatureProperties>" + //$NON-NLS-1$
			unsignedExtras +
			"</xades:UnsignedSignatureProperties></xades:UnsignedProperties></xades:QualifyingProperties></ds:Signature></root>"; //$NON-NLS-1$
		return xml.getBytes(StandardCharsets.UTF_8);
	}

	private static String baselineSignedProperties(final String signingCertificateElement) {
		return "<" + signingCertificateElement + "/>"; //$NON-NLS-1$ //$NON-NLS-2$
	}
}

