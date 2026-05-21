/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.configurator.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Caracterización de {@link UpdateConfigurationManager} — fija el
 * comportamiento del dominio de actualización automática de configuración
 * antes de mover su implementación desde {@link PreferencesManager}.
 *
 * <p>Aprovecha el seam de {@link PreferencesManager} ({@code USER_ROOT_SUPPLIER},
 * {@code SYSTEM_ROOT_SUPPLIER}) para redirigir el árbol de
 * {@link Preferences} a un subárbol único por test, sin polucionar las
 * preferencias reales de la máquina y sin mocks.</p>
 *
 * <p><b>Invariante del dominio:</b> {@code setConfigFileInfo} y
 * {@code setConfigCheckDate} persisten en el árbol de {@code Preferences}
 * pero <em>no refrescan</em> la caché en memoria
 * ({@code INTERNAL_PREFERENCES_DATA}) — esa caché solo se carga en
 * {@code init()}. En producción no es un problema porque el escritor (el
 * configurador) y el lector (la aplicación) son procesos distintos: el
 * lector siempre arranca con un {@code init()} fresco. Los tests modelan
 * ese reinicio con {@link #reopen()} antes de cada lectura.</p>
 */
final class TestUpdateConfigurationManager {

	private String testPrefix;
	private Supplier<Preferences> originalUserSupplier;
	private Supplier<Preferences> originalSystemSupplier;

	@BeforeEach
	void redirectPreferencesToIsolatedSubtree() {
		this.originalUserSupplier = PreferencesManager.USER_ROOT_SUPPLIER;
		this.originalSystemSupplier = PreferencesManager.SYSTEM_ROOT_SUPPLIER;

		this.testPrefix = "afirma-test-updcfg-" + UUID.randomUUID(); //$NON-NLS-1$
		final Preferences capturedUser = Preferences.userRoot().node(this.testPrefix + "/u"); //$NON-NLS-1$
		final Preferences capturedSystem = Preferences.userRoot().node(this.testPrefix + "/s"); //$NON-NLS-1$
		PreferencesManager.USER_ROOT_SUPPLIER = () -> capturedUser;
		PreferencesManager.SYSTEM_ROOT_SUPPLIER = () -> capturedSystem;

		setInitializedFlag(false);
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
			setInitializedFlag(false);
		}
	}

	private static ConfigDataInfo configInfo(final String content) {
		return new ConfigDataInfo(content.getBytes(StandardCharsets.UTF_8));
	}

	/** Simula el arranque de un proceso lector nuevo: fuerza que la
	 *  siguiente operación re-ejecute {@code init()} y recargue la caché
	 *  {@code INTERNAL_PREFERENCES_DATA} desde el árbol de Preferences. */
	private static void reopen() {
		setInitializedFlag(false);
	}

	// =====================================================================
	// setConfigFileInfo / getConfigFileUrl
	// =====================================================================

	@Test
	@DisplayName("setConfigFileInfo persiste la URL y getConfigFileUrl la recupera tras reabrir")
	void setConfigFileInfoStoresUrlRecoverable() {
		UpdateConfigurationManager.setConfigFileInfo(
				"https://example.org/config.xml", true, configInfo("v1")); //$NON-NLS-1$
		reopen();
		assertEquals("https://example.org/config.xml", //$NON-NLS-1$
				UpdateConfigurationManager.getConfigFileUrl());
	}

	@Test
	@DisplayName("getConfigFileUrl devuelve null si nunca se configuró")
	void getConfigFileUrlNullWhenUnset() {
		assertNull(UpdateConfigurationManager.getConfigFileUrl());
	}

	// =====================================================================
	// needCheckConfigUpdates — lógica de política
	// =====================================================================

	@Test
	@DisplayName("needCheckConfigUpdates es false si la actualización automática no está permitida")
	void needCheckFalseWhenNotAllowed() {
		assertFalse(UpdateConfigurationManager.needCheckConfigUpdates());
	}

	@Test
	@DisplayName("needCheckConfigUpdates es true con flag activo, URL HTTPS y sin fecha previa")
	void needCheckTrueWhenAllowedHttpsAndNoDate() {
		UpdateConfigurationManager.setConfigFileInfo(
				"https://example.org/config.xml", true, configInfo("v1")); //$NON-NLS-1$
		reopen();
		assertTrue(UpdateConfigurationManager.needCheckConfigUpdates());
	}

	@Test
	@DisplayName("needCheckConfigUpdates es false con allowUpdates=false (no se habilita el flag)")
	void needCheckFalseWhenAllowUpdatesFalse() {
		UpdateConfigurationManager.setConfigFileInfo(
				"https://example.org/config.xml", false, configInfo("v1")); //$NON-NLS-1$
		reopen();
		assertFalse(UpdateConfigurationManager.needCheckConfigUpdates());
	}

	@Test
	@DisplayName("needCheckConfigUpdates es false con URL no-HTTPS aunque allowUpdates=true")
	void needCheckFalseWhenUrlNotHttps() {
		UpdateConfigurationManager.setConfigFileInfo(
				"http://example.org/config.xml", true, configInfo("v1")); //$NON-NLS-1$
		reopen();
		assertFalse(UpdateConfigurationManager.needCheckConfigUpdates());
	}

	@Test
	@DisplayName("needCheckConfigUpdates es false tras registrar la fecha de chequeo hoy")
	void needCheckFalseAfterCheckDateRecordedToday() {
		UpdateConfigurationManager.setConfigFileInfo(
				"https://example.org/config.xml", true, configInfo("v1")); //$NON-NLS-1$
		UpdateConfigurationManager.setConfigCheckDate();
		reopen();
		assertFalse(UpdateConfigurationManager.needCheckConfigUpdates(),
				"Con la fecha de chequeo puesta a hoy no debe tocar comprobar de nuevo"); //$NON-NLS-1$
	}

	// =====================================================================
	// setConfigCheckDate
	// =====================================================================

	@Test
	@DisplayName("setConfigCheckDate se ejecuta sin lanzar excepción")
	void setConfigCheckDateDoesNotThrow() {
		UpdateConfigurationManager.setConfigFileInfo(
				"https://example.org/config.xml", true, configInfo("v1")); //$NON-NLS-1$
		UpdateConfigurationManager.setConfigCheckDate();
	}

	// =====================================================================
	// isNewConfigFile — comparación de hashes SHA-256
	// =====================================================================

	@Test
	@DisplayName("isNewConfigFile es true cuando nunca se aplicó ninguna configuración")
	void isNewConfigFileTrueWhenNothingApplied() {
		assertTrue(UpdateConfigurationManager.isNewConfigFile(configInfo("cualquiera"))); //$NON-NLS-1$
	}

	@Test
	@DisplayName("isNewConfigFile es false para el mismo contenido ya aplicado")
	void isNewConfigFileFalseForSameContent() {
		UpdateConfigurationManager.setConfigFileInfo(
				"https://example.org/config.xml", true, configInfo("contenido-A")); //$NON-NLS-1$
		reopen();
		assertFalse(UpdateConfigurationManager.isNewConfigFile(configInfo("contenido-A"))); //$NON-NLS-1$
	}

	@Test
	@DisplayName("isNewConfigFile es true para contenido distinto del ya aplicado")
	void isNewConfigFileTrueForDifferentContent() {
		UpdateConfigurationManager.setConfigFileInfo(
				"https://example.org/config.xml", true, configInfo("contenido-A")); //$NON-NLS-1$
		reopen();
		assertTrue(UpdateConfigurationManager.isNewConfigFile(configInfo("contenido-B"))); //$NON-NLS-1$
	}

	// =====================================================================
	// helper
	// =====================================================================

	private static void setInitializedFlag(final boolean value) {
		try {
			final java.lang.reflect.Field f = PreferencesManager.class.getDeclaredField("initialized"); //$NON-NLS-1$
			f.setAccessible(true);
			f.setBoolean(null, value);
		}
		catch (final ReflectiveOperationException ex) {
			throw new AssertionError("No se pudo resetear el flag 'initialized' de PreferencesManager", ex); //$NON-NLS-1$
		}
	}
}
