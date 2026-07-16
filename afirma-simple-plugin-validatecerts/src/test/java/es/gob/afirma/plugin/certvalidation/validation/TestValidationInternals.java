package es.gob.afirma.plugin.certvalidation.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.io.OutputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.DigestCalculator;
import org.junit.jupiter.api.Test;

/** Pruebas internas de la validaci&oacute;n de certificados. */
final class TestValidationInternals {

	/** Comprueba la serializaci&oacute;n y el mapeo de excepciones de los resultados. */
	@Test
	void validationResultMapsToStatusAndException() throws Exception {
		assertTrue(ValidationResult.VALID.isValid());
		assertTrue(ValidationResult.VALID.toJsonString().contains("\"result\": \"OK\"")); //$NON-NLS-1$
		ValidationResult.VALID.check();

		final Map<ValidationResult, Class<? extends Exception>> expected = new LinkedHashMap<>();
		expected.put(ValidationResult.CORRUPT, CertificateEncodingException.class);
		expected.put(ValidationResult.CA_NOT_SUPPORTED, CertificateException.class);
		expected.put(ValidationResult.NOT_YET_VALID, CertificateNotYetValidException.class);
		expected.put(ValidationResult.EXPIRED, CertificateExpiredException.class);
		expected.put(ValidationResult.REVOKED, CertificateRevokedException.class);
		expected.put(ValidationResult.UNKNOWN, CertificateUnknownStatusException.class);
		expected.put(ValidationResult.SERVER_ERROR, CertificateServerErrorException.class);
		expected.put(ValidationResult.UNAUTHORIZED, CertificateUnauthorizedException.class);
		expected.put(ValidationResult.MALFORMED_REQUEST, CertificateMalformedOcspRequestException.class);
		expected.put(ValidationResult.SIG_REQUIRED, CertificateUnsignedOcspRequestException.class);
		expected.put(ValidationResult.CANNOT_DOWNLOAD_CRL, CertificateCannotDownloadCrlException.class);

		for (final Map.Entry<ValidationResult, Class<? extends Exception>> entry : expected.entrySet()) {
			final ValidationResult result = entry.getKey();
			assertFalse(result.isValid());
			assertTrue(result.toJsonString().contains("\"result\": \"KO\"")); //$NON-NLS-1$
			assertTrue(result.toJsonString().contains(result.toString()));
			assertThrows(entry.getValue(), result::check);
		}
	}

	/** Comprueba los mensajes localizados y su fallback. */
	@Test
	void messagesReturnBundleTextOrFallback() throws Exception {
		assertEquals("V&aacute;lido.", CertValidationMessages.getString("ValidationResult.0")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("!clave.inexistente!", CertValidationMessages.getString("clave.inexistente")); //$NON-NLS-1$ //$NON-NLS-2$

		final Constructor<CertValidationMessages> constructor = CertValidationMessages.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
	}

	/** Comprueba contratos locales de la factor&iacute;a. */
	@Test
	void factoryRejectsNullCertificatesAndKeepsPrivateConstructor() throws Exception {
		assertThrows(IllegalArgumentException.class, () -> CertificateVerifierFactory.getCertificateVerifier(null));
		assertNotNull(CertificateVerifierFactory.getCertificateVerifier(loadCertificate("/CERT_ATOS_TEST.cer"))); //$NON-NLS-1$

		final Constructor<CertificateVerifierFactory> constructor = CertificateVerifierFactory.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());

		assertEquals("descripcion", new CertificateVerifierFactoryException("descripcion").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		final Exception cause = new Exception("causa"); //$NON-NLS-1$
		final CertificateVerifierFactoryException exception = new CertificateVerifierFactoryException("descripcion", cause); //$NON-NLS-1$
		assertEquals("descripcion", exception.getMessage()); //$NON-NLS-1$
		assertEquals(cause, exception.getCause());
	}

	/** Comprueba selecci&oacute;n de responder OCSP sin red. */
	@Test
	void ocspResponderSelectionPrefersOcspUrls() throws Exception {
		assertEquals(
			"http://servicio/ocsp", //$NON-NLS-1$
			getBestResponder("http://servicio/base", "http://servicio/ocsp") //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertEquals(
			"http://servicio/base", //$NON-NLS-1$
			getBestResponder("http://servicio/base", "http://servicio/crl") //$NON-NLS-1$ //$NON-NLS-2$
		);

		final InvocationTargetException empty = assertThrows(
			InvocationTargetException.class,
			() -> invokeBestResponder(Arrays.<String>asList())
		);
		assertInstanceOf(IllegalArgumentException.class, empty.getCause());

		final InvocationTargetException nul = assertThrows(
			InvocationTargetException.class,
			() -> invokeBestResponder(null)
		);
		assertInstanceOf(IllegalArgumentException.class, nul.getCause());
	}

	/** Comprueba rutas locales de validadores sin hacer peticiones externas. */
	@Test
	void verifiersHandleLocalErrorPaths() throws Exception {
		final OcspCertificateVerifier ocsp = new OcspCertificateVerifier();
		ocsp.setValidationProperties(null);
		assertEquals(ValidationResult.CORRUPT, ocsp.validateCertificate(null));
		assertEquals(ValidationResult.SERVER_ERROR, ocsp.verifyRevocation(null));

		final CrlCertificateVerifier crl = new CrlCertificateVerifier();
		crl.setValidationProperties(null);
		assertEquals(ValidationResult.CORRUPT, crl.validateCertificate(null));
		assertThrows(IllegalArgumentException.class, () -> crl.setValidationProperties("/no-existe.properties")); //$NON-NLS-1$
		final X509Certificate certificate = loadCertificate("/CERT_ATOS_TEST.cer"); //$NON-NLS-1$
		crl.setSubjectCert(certificate);
		assertEquals(certificate, crl.getCertificate());
		crl.setIssuerCert(certificate);
		assertEquals(ValidationResult.EXPIRED, crl.validateCertificate());
	}

	/** Comprueba validaciones locales del ayudante OCSP. */
	@Test
	void ocspHelperHandlesLocalErrorsAndStatuses() throws Exception {
		assertThrows(IllegalArgumentException.class, () -> OcspHelper.getSignData(null, "pwd", "alias")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class, () -> OcspHelper.getSignData("ks.p12", null, "alias")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class, () -> OcspHelper.getSignData("ks.p12", "pwd", null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class, () -> OcspHelper.sendOcspRequest(null, new byte[] { 1 }));
		assertThrows(IllegalArgumentException.class, () -> OcspHelper.sendOcspRequest(new URL("http://localhost"), null)); //$NON-NLS-1$

		assertEquals(ValidationResult.UNAUTHORIZED, analyzeStatus(OCSPResp.UNAUTHORIZED));
		assertEquals(ValidationResult.SERVER_ERROR, analyzeStatus(OCSPResp.INTERNAL_ERROR));
		assertEquals(ValidationResult.SERVER_ERROR, analyzeStatus(OCSPResp.TRY_LATER));
		assertEquals(ValidationResult.MALFORMED_REQUEST, analyzeStatus(OCSPResp.MALFORMED_REQUEST));
		assertEquals(ValidationResult.SIG_REQUIRED, analyzeStatus(OCSPResp.SIG_REQUIRED));

		final Constructor<OcspHelper> constructor = OcspHelper.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());

		final Class<?> digestClass = Class.forName("es.gob.afirma.plugin.certvalidation.validation.OcspHelper$Sha1DigestCalculator"); //$NON-NLS-1$
		final Constructor<?> digestConstructor = digestClass.getDeclaredConstructor();
		digestConstructor.setAccessible(true);
		final DigestCalculator digestCalculator = (DigestCalculator) digestConstructor.newInstance();
		final OutputStream out = digestCalculator.getOutputStream();
		out.write(new byte[] { 1, 2, 3 });
		assertEquals(20, digestCalculator.getDigest().length);
		assertEquals(20, digestCalculator.getDigest().length);
		assertNotNull(digestCalculator.getAlgorithmIdentifier());
	}

	/** Comprueba validaciones locales del ayudante CRL. */
	@Test
	void crlHelperHandlesLocalErrors() throws Exception {
		assertEquals(ValidationResult.CORRUPT, CrlHelper.verifyCertificateCRLs(null, null, null));
		assertEquals(
			ValidationResult.CANNOT_DOWNLOAD_CRL,
			CrlHelper.verifyCertificateCRLs(loadCertificate("/CERT_ATOS_TEST.cer"), null, Arrays.asList("urn:crl")) //$NON-NLS-1$ //$NON-NLS-2$
		);

		final InvocationTargetException unsupported = assertThrows(
			InvocationTargetException.class,
			() -> invokeDownloadCrl("urn:crl") //$NON-NLS-1$
		);
		assertInstanceOf(CRLException.class, unsupported.getCause());

		final Constructor<CrlHelper> constructor = CrlHelper.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
	}

	private static ValidationResult analyzeStatus(final int status) throws Exception {
		return OcspHelper.analyzeOcspResponse(
			new OCSPResp(new OCSPResponse(new OCSPResponseStatus(status), null)).getEncoded()
		);
	}

	private static byte[] invokeDownloadCrl(final String url) throws Exception {
		final Method method = CrlHelper.class.getDeclaredMethod("downloadCrl", String.class); //$NON-NLS-1$
		method.setAccessible(true);
		return (byte[]) method.invoke(null, url);
	}

	private static X509Certificate loadCertificate(final String resource) throws Exception {
		return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate( //$NON-NLS-1$
			TestValidationInternals.class.getResourceAsStream(resource)
		);
	}

	private static String getBestResponder(final String... responders) throws Exception {
		return invokeBestResponder(Arrays.asList(responders));
	}

	private static String invokeBestResponder(final java.util.List<String> responders) throws Exception {
		final Method method = OcspCertificateVerifier.class.getDeclaredMethod("getBestResponder", java.util.List.class); //$NON-NLS-1$
		method.setAccessible(true);
		return (String) method.invoke(null, responders);
	}
}
