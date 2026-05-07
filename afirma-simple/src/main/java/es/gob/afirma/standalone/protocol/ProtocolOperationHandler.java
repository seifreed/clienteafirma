/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 */

package es.gob.afirma.standalone.protocol;

/**
 * Contrato Strategy para los verbos del protocolo {@code afirma://}.
 *
 * <p>Cada implementación gestiona un único verbo (firma, lote, batch,
 * eudiw-present, etc.) y vive desacoplada del dispatcher central. El
 * {@link ProtocolOperationRegistry} consulta a los handlers en orden de
 * registro hasta encontrar uno cuyo {@link #handles(String)} responda
 * {@code true}.</p>
 *
 * <p>Introducido en la Fase A del plan Clean Code (2026-05-07) para extraer
 * el dispatch de {@link ProtocolInvocationLauncher#launch(String,
 * es.gob.afirma.core.misc.protocol.ProtocolVersion, boolean)} de la cadena
 * de {@code if (url.startsWith(...))} y permitir registrar nuevos verbos
 * sin tocar el dispatcher (M4 fase 2: cableado de
 * {@link EudiwProtocolHandler}).</p>
 */
public interface ProtocolOperationHandler {

	/**
	 * @param url URL completa de invocación (forma {@code afirma://verbo?...}).
	 * @return {@code true} si este handler reconoce el verbo y debe procesarlo.
	 */
	boolean handles(String url);

	/**
	 * Procesa la invocación y devuelve la respuesta destinada al cliente
	 * (navegador, servidor intermedio o socket).
	 *
	 * @param url URL completa.
	 * @param ctx Contexto inmutable de la invocación.
	 * @return Cadena con la respuesta serializada (mensaje de éxito,
	 *     mensaje de error formateado o {@code "OK"}).
	 * @throws Exception cualquier fallo no recuperable; el dispatcher decide
	 *     cómo notificarlo.
	 */
	String process(String url, LaunchContext ctx) throws Exception;
}
