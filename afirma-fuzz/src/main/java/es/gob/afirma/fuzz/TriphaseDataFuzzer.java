package es.gob.afirma.fuzz;

import java.io.IOException;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import es.gob.afirma.core.signers.TriphaseData;

/**
 * Harness Jazzer sobre {@link TriphaseData#parser(byte[])}.
 *
 * <p>El XML que llega aquí viene del WAR triphase: cualquier fallo del
 * parser puede ser un vector remoto. Las excepciones documentadas
 * ({@link IOException}) son señalización válida; el harness sólo busca
 * crashes inesperados.</p>
 */
public final class TriphaseDataFuzzer {

	private TriphaseDataFuzzer() {
		// no-op
	}

	public static void fuzzerTestOneInput(final FuzzedDataProvider data) {
		final byte[] xml = data.consumeRemainingAsBytes();
		try {
			TriphaseData.parser(xml);
		}
		catch (final IOException expected) {
			// XML corrupto: comportamiento esperado.
		}
		catch (final IllegalArgumentException expected) {
			// Atributos fuera de rango: también señalización.
		}
	}
}
