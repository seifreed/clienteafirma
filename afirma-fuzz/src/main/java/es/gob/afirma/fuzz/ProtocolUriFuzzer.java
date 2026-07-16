package es.gob.afirma.fuzz;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

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
			if (hasRemoteDataParam(uri)) {
				return;
			}
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
			catch (final AOException | IllegalArgumentException expected) {
				// OK también.
			}
	}

	private static boolean hasRemoteDataParam(final String uri) {
		final int queryPos = uri.indexOf('?');
		if (queryPos == uri.length() - 1) {
			return false;
		}
		final String[] params = uri.substring(queryPos >= 0 ? queryPos + 1 : 0).split("&"); //$NON-NLS-1$
		for (final String param : params) {
			final int eqPos = param.indexOf('=');
			if (eqPos <= 0 || !"dat".equals(param.substring(0, eqPos))) { //$NON-NLS-1$
				continue;
			}
			try {
				final String dataSource = URLDecoder.decode(
					param.substring(eqPos + 1),
					StandardCharsets.UTF_8
				).trim().toLowerCase(Locale.ROOT);
				if (
					dataSource.startsWith("http://") || //$NON-NLS-1$
					dataSource.startsWith("https://") || //$NON-NLS-1$
					dataSource.startsWith("ftp://") //$NON-NLS-1$
				) {
					return true;
				}
			}
			catch (final IllegalArgumentException e) {
				return false;
			}
		}
		return false;
	}
}
