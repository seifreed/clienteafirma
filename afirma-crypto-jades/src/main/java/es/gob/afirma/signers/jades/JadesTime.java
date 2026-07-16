/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital
 * This file is part of "Cliente @Firma".
 */

package es.gob.afirma.signers.jades;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

/**
 * Formateo del claim {@code sigT} (signing time) según ETSI TS 119 182-1 §5.1.10:
 * timestamp ISO 8601 con resolución de segundo y zona UTC ({@code Z}).
 */
final class JadesTime {

	private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_INSTANT;

	private JadesTime() {
		// no-op
	}

	/** {@code sigT} para el momento actual. Resolución de segundo, UTC. */
	static String nowIso8601() {
		return ISO.format(Instant.now().truncatedTo(ChronoUnit.SECONDS).atOffset(ZoneOffset.UTC));
	}
}
