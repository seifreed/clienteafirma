package es.gob.afirma.core.misc.protocol;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/** Pruebas del parser de URI de invocaci&oacute;n del protocolo. */
final class TestProtocolInvocationUriParser {

	/** Una URI sin esquema debe rechazarse sin errores de rango internos. */
	@Test
	void testUriWithoutSchemaIsRejected() {
		assertThrows(
			IllegalArgumentException.class,
			() -> ProtocolInvocationUriParser.getParametersToSign("") //$NON-NLS-1$
		);
	}

	/** Una query antes del esquema debe rechazarse sin errores de rango internos. */
	@Test
	void testQueryBeforeSchemaIsRejected() {
		assertThrows(
			IllegalArgumentException.class,
			() -> ProtocolInvocationUriParser.getParametersToSign("/&?&://\u0013s") //$NON-NLS-1$
		);
	}

	/** Un JSON de cifrado invalido con clave legacy debe rechazarse de forma controlada. */
	@Test
	void testInvalidCipherWithLegacyKeyIsRejected() {
		final byte[] input = Base64.getDecoder().decode(
			"Oi8vFmF3JmtleT1+YTovLxZhdyZjaXBoZXI9AAAAAAAAAAAAAAAAAAAAcDovLxYAAAAAAGV5PX5hOi8vFmF3JmNpcGhlcj0AAAAAAAAAAAAAAAAAAABwOmEWYXc=" //$NON-NLS-1$
		);
		final String uri = new String(input, StandardCharsets.UTF_8);
		assertThrows(
			ParameterException.class,
			() -> ProtocolInvocationUriParser.getParametersToSign(uri)
		);
	}
}
