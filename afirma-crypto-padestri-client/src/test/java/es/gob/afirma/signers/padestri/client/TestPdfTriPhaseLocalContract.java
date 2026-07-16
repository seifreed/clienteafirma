package es.gob.afirma.signers.padestri.client;

import java.security.KeyPairGenerator;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.signers.pades.common.BadPdfPasswordException;
import es.gob.afirma.signers.pades.common.PdfExtraParams;
import es.gob.afirma.signers.pades.common.PdfIsCertifiedException;
import es.gob.afirma.signers.pades.common.PdfIsPasswordProtectedException;

/** Pruebas locales del contrato del cliente PAdES trif&aacute;sico. */
public final class TestPdfTriPhaseLocalContract {

	@Test
	public void testLocalHelpers() {
		final AOPDFTriPhaseSigner signer = new AOPDFTriPhaseSigner();
		Assert.assertFalse(signer.isSign(new byte[0]));
		Assert.assertFalse(signer.isSign(new byte[0], new Properties()));
		Assert.assertFalse(signer.isValidDataFile(null));
		Assert.assertFalse(signer.isValidDataFile("texto".getBytes())); //$NON-NLS-1$
		Assert.assertTrue(signer.isValidDataFile(minimalPdf()));
		Assert.assertEquals("signed.pdf", signer.getSignedName(null, null)); //$NON-NLS-1$
		Assert.assertEquals("doc-signed.pdf", signer.getSignedName("doc.pdf", "-signed")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		Assert.assertEquals("doc-signed.pdf", signer.getSignedName("doc", "-signed")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
	}

	@Test
	public void testUnsupportedAndInvalidSignatureOperations() {
		final AOPDFTriPhaseSigner signer = new AOPDFTriPhaseSigner();
		assertUnsupported(() -> signer.countersign(new byte[0], "SHA256withRSA", CounterSignTarget.TREE, null, null, null, new Properties())); //$NON-NLS-1$
		assertUnsupported(() -> signer.getSignersStructure(new byte[0], true));
		assertUnsupported(() -> signer.getSignersStructure(new byte[0], new Properties(), true));
		assertInvalidSignature(() -> signer.getData(new byte[0]));
		assertInvalidSignature(() -> signer.getData(new byte[0], new Properties()));
		assertIllegalArgument(() -> signer.getSignInfo(null));
		assertInvalidSignature(() -> signer.getSignInfo(new byte[0]));
		assertInvalidSignature(() -> signer.getSignInfo(new byte[0], new Properties()));
	}

	@Test
	public void testValidationBeforeNetwork() throws Exception {
		final AOPDFTriPhaseSigner signer = new AOPDFTriPhaseSigner();
		final Properties extraParams = new Properties();
		final var key = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate(); //$NON-NLS-1$

		assertIllegalArgument(() -> signer.sign(new byte[0], "SHA256withRSA", null, null, null)); //$NON-NLS-1$
		assertIllegalArgument(() -> signer.sign(new byte[0], "SHA256withRSA", null, null, extraParams)); //$NON-NLS-1$
		assertIllegalArgument(() -> signer.sign(new byte[0], "SHA256withRSA", key, null, extraParams)); //$NON-NLS-1$
	}

	@Test
	public void testTriPhaseUtilityLocalErrors() throws Exception {
		final Constructor<PDFTriPhaseSignerUtil> constructor = PDFTriPhaseSignerUtil.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		Assert.assertNotNull(constructor.newInstance());

		try {
			PDFTriPhaseSignerUtil.doSign("no-base64".getBytes(), "SHA256withRSA", null, null, new Properties()); //$NON-NLS-1$ //$NON-NLS-2$
			Assert.fail("Se esperaba error de prefirma malformada"); //$NON-NLS-1$
		}
		catch (final AOException e) {
			Assert.assertSame(ErrorCode.ThirdParty.MALFORMED_PRESIGN_RESPONSE, e.getErrorCode());
		}

		Assert.assertTrue(buildInternalException(
			"ERR-21:" + PdfIsCertifiedException.REQUESTOR_MSG_CODE + ":certificado", //$NON-NLS-1$ //$NON-NLS-2$
			new Properties(),
			true
		) instanceof PdfIsCertifiedException);

		Assert.assertTrue(buildInternalException(
			"ERR-21:" + PdfIsPasswordProtectedException.REQUESTOR_MSG_CODE + ":clave", //$NON-NLS-1$ //$NON-NLS-2$
			new Properties(),
			true
		) instanceof PdfIsPasswordProtectedException);

		final Properties withPassword = new Properties();
		withPassword.setProperty(PdfExtraParams.USER_PASSWORD_STRING, "x"); //$NON-NLS-1$
		Assert.assertTrue(buildInternalException(
			"ERR-21:" + PdfIsPasswordProtectedException.REQUESTOR_MSG_CODE + ":clave", //$NON-NLS-1$ //$NON-NLS-2$
			withPassword,
			true
		) instanceof BadPdfPasswordException);

		Assert.assertSame(
			ErrorCode.ThirdParty.TRI_SERVER_UNKNOWN_POSTSIGN_ERROR,
			buildInternalException("ERR-X:mensaje", new Properties(), false).getErrorCode() //$NON-NLS-1$
		);
	}

	private static byte[] minimalPdf() {
		final byte[] pdf = new byte[70];
		final byte[] header = "%PDF-".getBytes(); //$NON-NLS-1$
		System.arraycopy(header, 0, pdf, 0, header.length);
		return pdf;
	}

	private static void assertUnsupported(final ThrowingRunnable runnable) {
		try {
			runnable.run();
			Assert.fail("Se esperaba UnsupportedOperationException"); //$NON-NLS-1$
		}
		catch (final UnsupportedOperationException expected) {
			// Operacion no soportada por contrato.
		}
		catch (final Exception e) {
			throw new AssertionError(e);
		}
	}

	private static void assertIllegalArgument(final ThrowingRunnable runnable) {
		try {
			runnable.run();
			Assert.fail("Se esperaba IllegalArgumentException"); //$NON-NLS-1$
		}
		catch (final IllegalArgumentException expected) {
			// Validacion temprana.
		}
		catch (final Exception e) {
			throw new AssertionError(e);
		}
	}

	private static void assertInvalidSignature(final ThrowingRunnable runnable) {
		try {
			runnable.run();
			Assert.fail("Se esperaba excepcion de firma invalida"); //$NON-NLS-1$
		}
		catch (final es.gob.afirma.core.AOInvalidSignatureFormatException expected) {
			// Firma invalida esperada.
		}
		catch (final Exception e) {
			throw new AssertionError(e);
		}
	}

	private static AOException buildInternalException(
			final String msg,
			final Properties extraParams,
			final boolean presign) throws Exception {
		final Method method = PDFTriPhaseSignerUtil.class.getDeclaredMethod(
			"buildInternalException", String.class, Properties.class, Boolean.TYPE //$NON-NLS-1$
		);
		method.setAccessible(true);
		return (AOException) method.invoke(null, msg, extraParams, Boolean.valueOf(presign));
	}

	private interface ThrowingRunnable {
		void run() throws Exception;
	}
}
