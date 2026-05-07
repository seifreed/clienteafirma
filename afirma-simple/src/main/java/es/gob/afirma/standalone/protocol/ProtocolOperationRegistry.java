/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 */

package es.gob.afirma.standalone.protocol;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Registro ordenado de {@link ProtocolOperationHandler}.
 *
 * <p>El orden de registro = orden de evaluación. La primera coincidencia
 * gana, igual que la cadena {@code if/else if} que sustituye en
 * {@link ProtocolInvocationLauncher#launch(String,
 * es.gob.afirma.core.misc.protocol.ProtocolVersion, boolean)}.</p>
 *
 * <p>Hilos: una vez {@link #register(ProtocolOperationHandler) registrados}
 * los handlers, el registro se consulta de forma read-only y es seguro
 * compartir entre hilos. Las modificaciones (registro y limpieza) deben
 * hacerse en la inicialización.</p>
 */
public final class ProtocolOperationRegistry {

	private final List<ProtocolOperationHandler> handlers = new ArrayList<>();

	/** Añade un handler al final de la lista. Devuelve {@code this} para encadenar. */
	public ProtocolOperationRegistry register(final ProtocolOperationHandler handler) {
		this.handlers.add(Objects.requireNonNull(handler, "handler")); //$NON-NLS-1$
		return this;
	}

	/**
	 * Devuelve el primer handler que reconoce la URL, o
	 * {@link Optional#empty()} si ninguno lo hace (la URL cae al dispatcher
	 * legacy o produce {@code UNSUPPORTED_OPERATION}).
	 */
	public Optional<ProtocolOperationHandler> resolve(final String url) {
		if (url == null) {
			return Optional.empty();
		}
		for (final ProtocolOperationHandler h : this.handlers) {
			if (h.handles(url)) {
				return Optional.of(h);
			}
		}
		return Optional.empty();
	}

	/** Total de handlers registrados (útil para tests). */
	public int size() {
		return this.handlers.size();
	}
}
