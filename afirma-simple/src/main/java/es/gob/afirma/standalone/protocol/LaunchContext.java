/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 */

package es.gob.afirma.standalone.protocol;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import es.gob.afirma.core.misc.protocol.ProtocolVersion;

/**
 * Contexto inmutable de una invocación por protocolo {@code afirma://...}.
 *
 * <p>Recoge los datos que <em>no</em> dependen del verbo y que cualquier
 * {@link ProtocolOperationHandler} necesita para procesar la URI: la versión
 * del protocolo negociada, el modo de transporte (socket vs servidor
 * intermedio), los parámetros parseados de la URL y el código de versión del
 * JavaScript invocador.</p>
 *
 * <p>Sustituye la noción de "estado de petición" que actualmente vive como
 * campos estáticos mutables en {@link ProtocolInvocationLauncher} (Fase A.1
 * del plan Clean Code, 2026-05-07). Ser un record inmutable con getters
 * estandarizados deja claro que cada handler recibe su propia foto del
 * contexto.</p>
 */
public record LaunchContext(
		ProtocolVersion version,
		boolean bySocket,
		Map<String, String> urlParams,
		int javascriptVersionCode) {

	public LaunchContext {
		Objects.requireNonNull(urlParams, "urlParams"); //$NON-NLS-1$
		// version puede ser null cuando el verbo es socket/websocket y la
		// versión se negocia desde la propia URL.
		urlParams = Collections.unmodifiableMap(urlParams);
	}
}
