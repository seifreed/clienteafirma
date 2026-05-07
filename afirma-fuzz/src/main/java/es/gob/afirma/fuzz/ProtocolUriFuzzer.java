package es.gob.afirma.fuzz;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.misc.protocol.ParameterException;
import es.gob.afirma.core.misc.protocol.ProtocolInvocationUriParser;

/**
 * Harness Jazzer sobre {@link ProtocolInvocationUriParser}: ambos camino
 * URI ({@code afirma://...}) y XML del intermedio.
 *
 * <p>Es la frontera más expuesta del cliente — cualquier navegador puede
 * lanzar URIs arbitrarias. Las rutas internas se nutren de
 * {@link ProtocolInvocationUriParser#getParametersToSign(String)} y la
 * sobrecarga {@code byte[]}.</p>
 */
public final class ProtocolUriFuzzer {

	private ProtocolUriFuzzer() {
		// no-op
	}

	public static void fuzzerTestOneInput(final FuzzedDataProvider data) {
		final boolean useUriPath = data.consumeBoolean();
		if (useUriPath) {
			final String uri = data.consumeRemainingAsString();
			try {
				ProtocolInvocationUriParser.getParametersToSign(uri);
			}
			catch (final ParameterException expected) {
				// Parámetros inválidos: señalización esperada.
			}
			catch (final IllegalArgumentException expected) {
				// URL malformada: el wrapper la convierte en IAE; OK.
			}
			return;
		}
		final byte[] xml = data.consumeRemainingAsBytes();
		try {
			ProtocolInvocationUriParser.getParametersToSign(xml);
		}
		catch (final AOException expected) {
			// XML inválido o atributos faltantes: señalización esperada.
		}
		catch (final IllegalArgumentException expected) {
			// OK también.
		}
	}
}
