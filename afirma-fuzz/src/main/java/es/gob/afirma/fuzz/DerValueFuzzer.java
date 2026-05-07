package es.gob.afirma.fuzz;

import java.io.IOException;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import es.gob.afirma.core.signers.der.DerValue;

/**
 * Harness Jazzer sobre {@link DerValue}, el parser ASN.1 DER del core.
 *
 * <p>Punto de entrada: {@link DerValue#DerValue(byte[])}. Es el sitio donde
 * cada firma binaria entra al cliente. Busca crashes ({@link Error},
 * {@link RuntimeException} no documentadas) — las {@link IOException} son
 * comportamiento esperado al ver bytes corruptos.</p>
 */
public final class DerValueFuzzer {

	private DerValueFuzzer() {
		// no-op
	}

	public static void fuzzerTestOneInput(final FuzzedDataProvider data) {
		final byte[] input = data.consumeRemainingAsBytes();
		try {
			new DerValue(input);
		}
		catch (final IOException expected) {
			// Bytes inválidos: el parser señaliza con IOException, OK.
		}
		catch (final IllegalArgumentException expected) {
			// Tag/longitud fuera de rango: también esperable.
		}
	}
}
