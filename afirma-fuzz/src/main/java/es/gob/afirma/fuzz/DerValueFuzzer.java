package es.gob.afirma.fuzz;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Primitive;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

/**
 * Harness Jazzer sobre el parser ASN.1 DER de BouncyCastle, sucesor del fork
 * Oracle {@code DerValue} (eliminado en Fase F del plan Clean Code).
 *
 * <p>Punto de entrada: {@link ASN1Primitive#fromByteArray(byte[])}. Es el sitio
 * donde cada firma binaria entra al cliente despu&eacute;s de la migraci&oacute;n.
 * Busca crashes ({@link Error}, {@link RuntimeException} no documentadas) — las
 * {@link IOException} y las {@link IllegalArgumentException} que BC lanza ante
 * tags/longitudes corruptas son comportamiento esperado.</p>
 *
 * <p>El nombre de la clase se mantiene por compatibilidad con
 * {@code scripts/run-fuzz.sh DerValueFuzzer 60} y con el corpus existente.</p>
 */
public final class DerValueFuzzer {

	private DerValueFuzzer() {
		// no-op
	}

	public static void fuzzerTestOneInput(final FuzzedDataProvider data) {
		final byte[] input = data.consumeRemainingAsBytes();
		try {
			ASN1Primitive.fromByteArray(input);
		}
		catch (final IOException expected) {
			// Bytes inválidos: el parser señaliza con IOException, OK.
		}
		catch (final IllegalArgumentException expected) {
			// Tag/longitud fuera de rango: BC lo señaliza así, OK.
		}
	}
}
