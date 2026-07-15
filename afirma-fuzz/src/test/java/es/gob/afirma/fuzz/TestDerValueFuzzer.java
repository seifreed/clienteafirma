package es.gob.afirma.fuzz;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;

/** Pruebas de regresi&oacute;n del harness ASN.1 DER. */
final class TestDerValueFuzzer {

	/** BC puede lanzar IllegalStateException con BIT STRING BER corruptos. */
	@Test
	void testEmptyConstructedBitStringDoesNotCrashHarness() {
		final byte[] crash = {
				0x78, (byte) 0x80, 0x23, 0x04, 0x03, 0x00, 0x00, 0x00,
				0x04, 0x03, 0x00, 0x00, 0x00, 0x06, 0x03, 0x00,
				0x06, 0x03, 0x00, (byte) 0x81, 0x2f
		};

		assertDoesNotThrow(() -> DerValueFuzzer.parseDerValue(crash));
	}
}
