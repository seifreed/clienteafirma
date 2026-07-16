package es.gob.afirma.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Pruebas de contratos locales de errores y excepciones base. */
final class TestCoreLocalContracts {

	/** Comprueba validaci&oacute;n y comparaci&oacute;n de c&oacute;digos de error. */
	@Test
	void errorCodesValidateExposeAndCompareValues() {
		final ErrorCode error = new ErrorCode("500001", "Cancelado"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("500001", error.getCode()); //$NON-NLS-1$
		assertEquals("Cancelado", error.getDescription()); //$NON-NLS-1$
		assertEquals("500001: Cancelado", error.toString()); //$NON-NLS-1$
		assertTrue(error.checkType(ErrorCode.ERROR_FUNCTIONAL));
		assertFalse(error.checkType(ErrorCode.ERROR_INTERNAL));
		assertEquals(error, new ErrorCode("500001")); //$NON-NLS-1$
		assertEquals(error.hashCode(), new ErrorCode("500001").hashCode()); //$NON-NLS-1$
		assertFalse(error.equals("500001")); //$NON-NLS-1$

		assertThrows(IllegalArgumentException.class, () -> new ErrorCode(null));
		assertThrows(IllegalArgumentException.class, () -> new ErrorCode("12345")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> new ErrorCode("12345A")); //$NON-NLS-1$

		assertEquals("200002", ErrorCode.Internal.LIBRARY_NOT_FOUND.getCode()); //$NON-NLS-1$
		assertEquals("300400", ErrorCode.ThirdParty.PRESIGN_HTTP_ERROR.getCode()); //$NON-NLS-1$
		assertEquals("400004", ErrorCode.Communication.INVALID_DOMAIN_SSL_CERTIFICATE_ERROR.getCode()); //$NON-NLS-1$
		assertEquals("500001", ErrorCode.Functional.CANCELLED_OPERATION.getCode()); //$NON-NLS-1$
		assertEquals("600009", ErrorCode.Request.UNSUPPORTED_CIPHER_KEY.getCode()); //$NON-NLS-1$
		assertNotNull(new ErrorCode.Internal());
		assertNotNull(new ErrorCode.ThirdParty());
		assertNotNull(new ErrorCode.Communication());
		assertNotNull(new ErrorCode.Functional());
		assertNotNull(new ErrorCode.Request());
	}

	/** Comprueba constructores de excepciones controladas. */
	@Test
	void controlledExceptionsPreserveCodeMessageAndCause() {
		final Throwable cause = new IllegalStateException("causa"); //$NON-NLS-1$
		final ErrorCode code = ErrorCode.Functional.CANCELLED_OPERATION;

		final AOException fromCode = new AOException(code);
		assertEquals(code.getDescription(), fromCode.getMessage());
		assertSame(code, fromCode.getErrorCode());
		assertTrue(fromCode.toString().contains(code.getCode()));

		assertSame(code, new AOException("mensaje", code).getErrorCode()); //$NON-NLS-1$
		assertSame(cause, new AOException(cause, code).getCause());
		assertSame(cause, new AOException("mensaje", cause, code).getCause()); //$NON-NLS-1$

		final AORuntimeException runtime = new AORuntimeException(code);
		assertEquals(code.getDescription(), runtime.getMessage());
		assertSame(code, runtime.getErrorCode());
		assertTrue(runtime.toString().contains(code.getCode()));
		assertSame(code, new AORuntimeException("mensaje", code).getErrorCode()); //$NON-NLS-1$
		assertSame(cause, new AORuntimeException(cause, code).getCause());
		assertSame(cause, new AORuntimeException("mensaje", cause, code).getCause()); //$NON-NLS-1$
	}

	/** Comprueba la excepci&oacute;n que solicita configuraci&oacute;n en tiempo de ejecuci&oacute;n. */
	@Test
	void runtimeConfigNeededKeepsRequestMetadata() {
		final RuntimeConfigNeededException ex = new RuntimeConfigRequest(
			"mensaje", RuntimeConfigNeededException.RequestType.CONFIRM, "texto", "param", //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			ErrorCode.Request.UNSUPPORTED_CIPHER_KEY
		);
		assertEquals(RuntimeConfigNeededException.RequestType.CONFIRM, ex.getRequestType());
		assertEquals("texto", ex.getRequestorText()); //$NON-NLS-1$
		assertEquals("param", ex.getParam()); //$NON-NLS-1$
		assertFalse(ex.isDenied());
		ex.setDenied(true);
		assertTrue(ex.isDenied());
		assertThrows(
			NullPointerException.class,
			() -> new RuntimeConfigRequest("mensaje", null, null, null, ErrorCode.Request.UNSUPPORTED_CIPHER_KEY) //$NON-NLS-1$
		);
	}

	private static final class RuntimeConfigRequest extends RuntimeConfigNeededException {

		private static final long serialVersionUID = 1L;

		RuntimeConfigRequest(
				final String msg,
				final RequestType requestType,
				final String requestorText,
				final String param,
				final ErrorCode errorCode) {
			super(msg, requestType, requestorText, param, errorCode);
		}
	}
}
