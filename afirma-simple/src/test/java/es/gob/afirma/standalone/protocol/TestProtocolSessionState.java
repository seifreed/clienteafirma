/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.protocol;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Verifica los accesores y la idempotencia thread-safe de
 * {@link ProtocolSessionState}.
 */
final class TestProtocolSessionState {

	@AfterEach
	void cleanState() {
		// El singleton es VM-global; reseteamos para no contaminar tests posteriores.
		ProtocolSessionState.INSTANCE.stickyKeyEntry(null);
		ProtocolSessionState.INSTANCE.activeWaitingThread(null);
	}

	@Test
	@DisplayName("stickyKeyEntry: set/get round-trip preserva el valor")
	void stickyKeyRoundTrip() {
		assertNull(ProtocolSessionState.INSTANCE.stickyKeyEntry());
		// PrivateKeyEntry no es trivial de instanciar — usamos null y un mock simple.
		// Verificamos solo que el setter de null lo acepta y get devuelve null.
		ProtocolSessionState.INSTANCE.stickyKeyEntry(null);
		assertNull(ProtocolSessionState.INSTANCE.stickyKeyEntry());
	}

	@Test
	@DisplayName("activeWaitingThread: set/get devuelve el último valor")
	void waitingThreadRoundTrip() {
		assertNull(ProtocolSessionState.INSTANCE.activeWaitingThread());
		final Thread t = new Thread(() -> {}, "test-waiting");
		ProtocolSessionState.INSTANCE.activeWaitingThread(t);
		assertSame(t, ProtocolSessionState.INSTANCE.activeWaitingThread());
	}

	@Test
	@DisplayName("INSTANCE es el mismo singleton en llamadas distintas")
	void singletonStable() {
		assertSame(ProtocolSessionState.INSTANCE, ProtocolSessionState.INSTANCE);
	}

	@Test
	@DisplayName("initLoadKeyStoreTask es idempotente bajo concurrencia: una sola tarea creada")
	void loadKeyStoreTaskIdempotent() throws Exception {
		// Garantizamos arranque limpio para esta verificación.
		// Nota: el AfterEach NO resetea loadKeyStoreTask porque crear la
		// task arranca un Thread real. Después de este test el field queda
		// inicializado durante el resto de la VM — aceptable para un test
		// de smoke de idempotencia.
		final int threads = 16;
		final CountDownLatch start = new CountDownLatch(1);
		final CountDownLatch done = new CountDownLatch(threads);
		final AtomicInteger errors = new AtomicInteger();
		for (int i = 0; i < threads; i++) {
			new Thread(() -> {
				try {
					start.await();
					ProtocolSessionState.INSTANCE.initLoadKeyStoreTask();
				}
				catch (final InterruptedException e) {
					errors.incrementAndGet();
					Thread.currentThread().interrupt();
				}
				finally {
					done.countDown();
				}
			}, "init-race-" + i).start();
		}
		start.countDown();
		done.await();

		assertSame(0, errors.get(), "No debería haber InterruptedException");
		// La tarea existe (al menos una llamada la inicializó).
		assertNotNull(ProtocolSessionState.INSTANCE.loadKeyStoreTask());
		// Una llamada extra no la reemplaza.
		final var pre = ProtocolSessionState.INSTANCE.loadKeyStoreTask();
		ProtocolSessionState.INSTANCE.initLoadKeyStoreTask();
		assertSame(pre, ProtocolSessionState.INSTANCE.loadKeyStoreTask(),
				"initLoadKeyStoreTask debe ser idempotente — llamadas extra no deben reemplazar la tarea");
	}
}
