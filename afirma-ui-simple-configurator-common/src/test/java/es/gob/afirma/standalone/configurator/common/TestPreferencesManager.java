/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.configurator.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import java.util.function.Supplier;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import es.gob.afirma.standalone.configurator.common.PreferencesManager.PreferencesSource;

/**
 * Caracterización de {@link PreferencesManager} (Oleada 9 Fase A, 2026-05-20).
 *
 * <p>Aprovecha el <em>seam</em> package-private introducido en el mismo commit
 * ({@code USER_ROOT_SUPPLIER}, {@code SYSTEM_ROOT_SUPPLIER},
 * {@code NODE_PATH_PREFIX}) para redirigir los accesos al árbol de
 * {@link Preferences} bajo un subnodo único por test
 * ({@code /afirma-test-prefs-<uuid>/...}). De este modo se ejerce el código
 * real sin polucionar las preferencias reales del usuario / sistema en la
 * máquina que corre los tests, y sin recurrir a mocks (prohibidos por
 * CLAUDE.md § "No mocks").</p>
 *
 * <p>Red de seguridad antes del split estructural a sub-managers temáticos
 * (signing/UI/network/keystore/proxy/…) — sesión futura.</p>
 */
final class TestPreferencesManager {

	/** Clave del catálogo de preferencias bloqueables —
	 * referenciada a {@code GeneralPreferenceKeys} para que los tests
	 * sobrevivan a renames. */
	private static final String PROTECTED_KEY =
			GeneralPreferenceKeys.UPDATECHECK;

	/** Una clave arbitraria que el usuario puede establecer libremente
	 * (no exclusiva de sistema, no protegida). */
	private static final String FREE_USER_KEY = "test.user.free.key"; //$NON-NLS-1$

	private String testPrefix;
	private Supplier<Preferences> originalUserSupplier;
	private Supplier<Preferences> originalSystemSupplier;

	@BeforeEach
	void redirectPreferencesToIsolatedSubtree() {
		this.originalUserSupplier = PreferencesManager.USER_ROOT_SUPPLIER;
		this.originalSystemSupplier = PreferencesManager.SYSTEM_ROOT_SUPPLIER;

		this.testPrefix = "afirma-test-prefs-" + UUID.randomUUID(); //$NON-NLS-1$
		// Tanto USER como SYSTEM redirigen a subárboles independientes bajo
		// userRoot (systemRoot suele ser write-protected en CI/dev y haría
		// los tests inestables). Los helpers relativize() del seam aseguran
		// que las rutas absolutas del código se interpreten como relativas
		// y aterricen DENTRO de estos subárboles.
		final Preferences capturedUser = Preferences.userRoot().node(this.testPrefix + "/u"); //$NON-NLS-1$
		final Preferences capturedSystem = Preferences.userRoot().node(this.testPrefix + "/s"); //$NON-NLS-1$
		PreferencesManager.USER_ROOT_SUPPLIER = () -> capturedUser;
		PreferencesManager.SYSTEM_ROOT_SUPPLIER = () -> capturedSystem;

		// init() es lazy y guardado por `initialized = true`. Forzamos un
		// reset entre tests para que cada uno parta con su subárbol limpio.
		resetInitializedFlag();
	}

	@AfterEach
	void cleanupAndRestore() throws BackingStoreException {
		try {
			final Preferences root = Preferences.userRoot();
			if (root.nodeExists(this.testPrefix)) {
				root.node(this.testPrefix).removeNode();
				root.flush();
			}
		}
		finally {
			PreferencesManager.USER_ROOT_SUPPLIER = this.originalUserSupplier;
			PreferencesManager.SYSTEM_ROOT_SUPPLIER = this.originalSystemSupplier;
			resetInitializedFlag();
		}
	}

	// =====================================================================
	// get() / put() — round-trip básico de String
	// =====================================================================

	@Test
	@DisplayName("get() devuelve null si la clave no existe ni en user, system ni defaults")
	void getReturnsNullForUnknownKey() {
		assertEquals(null, PreferencesManager.get("clave.que.no.existe.en.ningun.nivel")); //$NON-NLS-1$
	}

	@Test
	@DisplayName("put() + get() preservan el valor exacto en el almacén de usuario")
	void putAndGetUserPreferenceRoundtrip() {
		PreferencesManager.put(FREE_USER_KEY, "valor-arbitrario"); //$NON-NLS-1$
		assertEquals("valor-arbitrario", PreferencesManager.get(FREE_USER_KEY)); //$NON-NLS-1$
	}

	@Test
	@DisplayName("put() sobre clave existente la sobrescribe (last-write-wins)")
	void putOverwritesPreviousValue() {
		PreferencesManager.put(FREE_USER_KEY, "primero"); //$NON-NLS-1$
		PreferencesManager.put(FREE_USER_KEY, "segundo"); //$NON-NLS-1$
		assertEquals("segundo", PreferencesManager.get(FREE_USER_KEY)); //$NON-NLS-1$
	}

	// =====================================================================
	// getBoolean() / putBoolean()
	// =====================================================================

	@Test
	@DisplayName("getBoolean(USER) devuelve false cuando la clave no existe en el almacén de usuario")
	void getBooleanUserSourceReturnsFalseWhenAbsent() {
		assertFalse(PreferencesManager.getBoolean("clave.bool.ausente", PreferencesSource.USER)); //$NON-NLS-1$
	}

	@Test
	@DisplayName("putBoolean() + getBoolean(USER) preservan ambos valores en el almacén de usuario")
	void putAndGetBooleanRoundtripFromUserSource() {
		PreferencesManager.putBoolean("test.bool.true", true); //$NON-NLS-1$
		PreferencesManager.putBoolean("test.bool.false", false); //$NON-NLS-1$
		assertTrue(PreferencesManager.getBoolean("test.bool.true", PreferencesSource.USER)); //$NON-NLS-1$
		assertFalse(PreferencesManager.getBoolean("test.bool.false", PreferencesSource.USER)); //$NON-NLS-1$
	}

	// =====================================================================
	// remove() / clearAll()
	// =====================================================================

	@Test
	@DisplayName("remove() borra la clave del usuario; get() vuelve a devolver el default o null")
	void removeErasesUserKey() {
		PreferencesManager.put(FREE_USER_KEY, "presente"); //$NON-NLS-1$
		assertEquals("presente", PreferencesManager.get(FREE_USER_KEY)); //$NON-NLS-1$
		PreferencesManager.remove(FREE_USER_KEY);
		// Tras remove(), get() devuelve el valor por defecto del fichero
		// preferences.properties si existe, o null en otro caso. La clave
		// libre no está en defaults, así que esperamos null.
		assertEquals(null, PreferencesManager.get(FREE_USER_KEY));
	}

	@Test
	@DisplayName("clearAll() elimina TODAS las claves del usuario")
	void clearAllRemovesAllUserKeys() throws BackingStoreException {
		PreferencesManager.put("k1", "v1"); //$NON-NLS-1$ //$NON-NLS-2$
		PreferencesManager.put("k2", "v2"); //$NON-NLS-1$ //$NON-NLS-2$
		PreferencesManager.put("k3", "v3"); //$NON-NLS-1$ //$NON-NLS-2$
		PreferencesManager.clearAll();
		assertEquals(null, PreferencesManager.get("k1")); //$NON-NLS-1$
		assertEquals(null, PreferencesManager.get("k2")); //$NON-NLS-1$
		assertEquals(null, PreferencesManager.get("k3")); //$NON-NLS-1$
	}

	// =====================================================================
	// flush() — no excepción cuando hay/no hay datos pendientes
	// =====================================================================

	@Test
	@DisplayName("flush() sin escrituras previas no lanza excepción")
	void flushOnEmptyStoreDoesNotThrow() throws BackingStoreException {
		PreferencesManager.flush();
	}

	@Test
	@DisplayName("flush() después de put() persiste y es idempotente")
	void flushAfterPutIsIdempotent() throws BackingStoreException {
		PreferencesManager.put(FREE_USER_KEY, "persistente"); //$NON-NLS-1$
		PreferencesManager.flush();
		PreferencesManager.flush();
		assertEquals("persistente", PreferencesManager.get(FREE_USER_KEY)); //$NON-NLS-1$
	}

	// =====================================================================
	// putSystemPref() — ramificación user-vs-system
	// =====================================================================

	@Test
	@DisplayName("putSystemPref() escribe en la rama de sistema; get(SYSTEM) lo recupera")
	void putSystemPrefAndRetrieveFromSystemSource() {
		PreferencesManager.putSystemPref("test.system.key", "system-value"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("system-value", PreferencesManager.get("test.system.key", PreferencesSource.SYSTEM)); //$NON-NLS-1$ //$NON-NLS-2$
	}

	@Test
	@DisplayName("Si user y system tienen la misma clave, get() prioriza el valor de USUARIO")
	void userPreferenceShadowsSystemForSameKey() {
		PreferencesManager.putSystemPref("test.shadow.key", "system-value"); //$NON-NLS-1$ //$NON-NLS-2$
		PreferencesManager.put("test.shadow.key", "user-value"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("user-value", PreferencesManager.get("test.shadow.key")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("system-value", PreferencesManager.get("test.shadow.key", PreferencesSource.SYSTEM)); //$NON-NLS-1$ //$NON-NLS-2$
	}

	// =====================================================================
	// isProtectedPreference() — clave protegida vs clave libre
	// =====================================================================

	@Test
	@DisplayName("isProtectedPreference() devuelve true para una clave del catálogo SYSTEM_EXCLUSIVE_PREFERENCES")
	void isProtectedPreferenceTrueForKnownSystemKey() {
		assertNotNull(PROTECTED_KEY,
				"Setup: la clave protegida debe existir en PreferencesManager"); //$NON-NLS-1$
		assertTrue(PreferencesManager.isProtectedPreference(PROTECTED_KEY),
				"Una clave del catálogo SYSTEM_EXCLUSIVE_PREFERENCES debe protegerse"); //$NON-NLS-1$
	}

	@Test
	@DisplayName("isProtectedPreference() devuelve false para una clave arbitraria")
	void isProtectedPreferenceFalseForArbitraryKey() {
		assertFalse(PreferencesManager.isProtectedPreference("clave.que.no.es.exclusiva.de.sistema")); //$NON-NLS-1$
	}

	// =====================================================================
	// helpers privados
	// =====================================================================

	/** Resetea el guardado de {@code initialized} mediante reflexión.
	 *  Cada test parte con su subárbol limpio y necesita re-disparar
	 *  {@code init()} dentro de {@code PreferencesManager}. */
	private static void resetInitializedFlag() {
		try {
			final java.lang.reflect.Field f = PreferencesManager.class.getDeclaredField("initialized"); //$NON-NLS-1$
			f.setAccessible(true);
			f.setBoolean(null, false);
		}
		catch (final ReflectiveOperationException ex) {
			throw new AssertionError("No se pudo resetear el flag 'initialized' de PreferencesManager", ex); //$NON-NLS-1$
		}
	}
}
