/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 */

package es.gob.afirma.standalone.protocol;

import java.security.KeyStore.PrivateKeyEntry;
import java.util.concurrent.atomic.AtomicReference;

import es.gob.afirma.standalone.ui.tasks.LoadKeystoreTask;

/**
 * Estado <em>session-level</em> compartido por las invocaciones del protocolo
 * {@code afirma://}. Aísla los tres únicos campos que necesitan persistir
 * entre llamadas a {@link ProtocolInvocationLauncher#launch(String,
 * es.gob.afirma.core.misc.protocol.ProtocolVersion, boolean)}:
 *
 * <ul>
 *   <li>{@link #stickyKeyEntry()} — última clave/certificado fijado por el usuario
 *       (feature "recordar mi certificado" en operaciones sucesivas).</li>
 *   <li>{@link #activeWaitingThread()} — hilo de espera activa contra el servidor
 *       intermedio (creado por {@code requestWait()} y consumido por los handlers
 *       que envían respuesta).</li>
 *   <li>{@link #loadKeyStoreTask()} — tarea async de precarga del keystore por
 *       defecto, iniciada en background al detectar que la operación necesita
 *       firmar.</li>
 * </ul>
 *
 * <p>Anteriormente vivían como tres campos {@code private static} en
 * {@link ProtocolInvocationLauncher}; al concentrar el estado mutable en una
 * sola clase con accesores synchronized se elimina el <em>shared mutable
 * state</em> distribuido por la clase y se documenta explícitamente la
 * semántica de cada campo. Extraído en la Fase A.1 del plan Clean Code
 * (2026-05-07).</p>
 *
 * <p>Patrón <em>thread-safe singleton</em>: {@link AtomicReference} para los
 * tres campos garantiza visibilidad entre hilos sin necesidad de
 * sincronización pesada en getters. La inicialización del {@code loadKeyStoreTask}
 * usa {@code compareAndSet} para que múltiples llamadas a {@link #initLoadKeyStoreTask()}
 * no creen tareas duplicadas.</p>
 */
public final class ProtocolSessionState {

	/** Instancia única — el protocolo {@code afirma://} es VM-global. */
	public static final ProtocolSessionState INSTANCE = new ProtocolSessionState();

	private final AtomicReference<PrivateKeyEntry> stickyKey = new AtomicReference<>();
	private final AtomicReference<Thread> waitingThread = new AtomicReference<>();
	private final AtomicReference<LoadKeystoreTask> loadKeyStoreTask = new AtomicReference<>();

	private ProtocolSessionState() {
		// Singleton: usar INSTANCE.
	}

	/** Devuelve la entrada de clave fijada o {@code null} si no se definió. */
	public PrivateKeyEntry stickyKeyEntry() {
		return this.stickyKey.get();
	}

	/** Establece (o limpia, pasando {@code null}) la entrada de clave fijada. */
	public void stickyKeyEntry(final PrivateKeyEntry entry) {
		this.stickyKey.set(entry);
	}

	/** Devuelve el hilo de espera activa o {@code null}. */
	public Thread activeWaitingThread() {
		return this.waitingThread.get();
	}

	/** Establece el hilo de espera activa. Sustituye al previo si lo hubiera. */
	public void activeWaitingThread(final Thread thread) {
		this.waitingThread.set(thread);
	}

	/**
	 * Devuelve la tarea de precarga del keystore o {@code null} si nunca se inició.
	 */
	public LoadKeystoreTask loadKeyStoreTask() {
		return this.loadKeyStoreTask.get();
	}

	/**
	 * Inicia la tarea de precarga del keystore en background si todavía no
	 * existe. Idempotente: llamadas concurrentes no producen tareas duplicadas.
	 */
	public void initLoadKeyStoreTask() {
		final LoadKeystoreTask current = this.loadKeyStoreTask.get();
		if (current != null) {
			return;
		}
		final LoadKeystoreTask candidate = new LoadKeystoreTask();
		if (this.loadKeyStoreTask.compareAndSet(null, candidate)) {
			candidate.start();
		}
		// Si compareAndSet falló, otro hilo ganó la carrera. Descartamos la
		// instancia local sin arrancarla.
	}
}
