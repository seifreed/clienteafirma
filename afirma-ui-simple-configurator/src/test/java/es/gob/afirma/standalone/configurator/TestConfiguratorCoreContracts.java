package es.gob.afirma.standalone.configurator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

/** Pruebas de contratos puros del configurador. */
final class TestConfiguratorCoreContracts {

	/** Comprueba parseo de argumentos del configurador grafico. */
	@Test
	void graphicConfigArgsParseAllSupportedOptions() throws Exception {
		final Object config = newConfigArgs(
			"es.gob.afirma.standalone.configurator.AutofirmaConfigurator$ConfigArgs", //$NON-NLS-1$
			new String[] {
				AutofirmaConfigurator.PARAMETER_UNINSTALL,
				AutofirmaConfigurator.PARAMETER_KEEP_OPEN,
				AutofirmaConfigurator.PARAMETER_HEADLESS,
				AutofirmaConfigurator.PARAMETER_JNLP_INSTANCE,
				AutofirmaConfigurator.PARAMETER_FIREFOX_SECURITY_ROOTS,
				AutofirmaConfigurator.PARAMETER_CERTIFICATE_PATH, "cert.cer", //$NON-NLS-1$
				AutofirmaConfigurator.PARAMETER_KEYSTORE_PATH, "store.p12", //$NON-NLS-1$
				AutofirmaConfigurator.CONFIG_PATH, "prefs.plist", //$NON-NLS-1$
				AutofirmaConfigurator.UPDATE_CONFIG,
				AutofirmaConfigurator.LANGUAGE_PATH, "lang.properties", //$NON-NLS-1$
				AutofirmaConfigurator.DEFAULT_LANGUAGE, "es_ES" //$NON-NLS-1$
			}
		);
		assertTrue((Boolean) invoke(config, "isUninstallation")); //$NON-NLS-1$
		assertTrue((Boolean) invoke(config, "isNeedKeep")); //$NON-NLS-1$
		assertTrue((Boolean) invoke(config, "isHeadless")); //$NON-NLS-1$
		assertTrue((Boolean) invoke(config, "isJnlpInstance")); //$NON-NLS-1$
		assertTrue((Boolean) invoke(config, "isFirefoxSecurityRoots")); //$NON-NLS-1$
		assertEquals("cert.cer", invoke(config, "getCertificatePath")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("store.p12", invoke(config, "getKeystorePath")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("prefs.plist", invoke(config, "getConfigPath")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue((Boolean) invoke(config, "getUpdateConfig")); //$NON-NLS-1$
		assertEquals("lang.properties", invoke(config, "getLanguagePath")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("es_ES", invoke(config, "getDefaultLanguage")); //$NON-NLS-1$ //$NON-NLS-2$

		final Object defaults = newConfigArgs(
			"es.gob.afirma.standalone.configurator.AutofirmaConfigurator$ConfigArgs", //$NON-NLS-1$
			null
		);
		assertFalse((Boolean) invoke(defaults, "isUninstallation")); //$NON-NLS-1$
		assertFalse((Boolean) invoke(defaults, "isNeedKeep")); //$NON-NLS-1$
		assertEquals("", invoke(defaults, "getCertificatePath")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Comprueba parseo de argumentos del configurador silencioso. */
	@Test
	void silentConfigArgsNormalizeHttpsConfigPath() throws Exception {
		final Object config = newConfigArgs(
			"es.gob.afirma.standalone.configurator.AutofirmaConfiguratorSilent$ConfigArgs", //$NON-NLS-1$
			new String[] {
				AutofirmaConfiguratorSilent.PARAMETER_UNINSTALL,
				AutofirmaConfiguratorSilent.PARAMETER_FIREFOX_SECURITY_ROOTS,
				AutofirmaConfiguratorSilent.PARAMETER_CERTIFICATE_PATH, "cert.cer", //$NON-NLS-1$
				AutofirmaConfiguratorSilent.PARAMETER_KEYSTORE_PATH, "store.p12", //$NON-NLS-1$
				AutofirmaConfiguratorSilent.CONFIG_PATH, "https:\\\\example.test\\prefs.plist", //$NON-NLS-1$
				AutofirmaConfiguratorSilent.UPDATE_CONFIG,
				AutofirmaConfiguratorSilent.LANGUAGE_PATH, "lang.properties", //$NON-NLS-1$
				AutofirmaConfiguratorSilent.DEFAULT_LANGUAGE, "gl_ES" //$NON-NLS-1$
			}
		);
		assertTrue((Boolean) invoke(config, "isUninstallation")); //$NON-NLS-1$
		assertTrue((Boolean) invoke(config, "isFirefoxSecurityRoots")); //$NON-NLS-1$
		assertEquals("cert.cer", invoke(config, "getCertificatePath")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("store.p12", invoke(config, "getKeystorePath")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("https://example.test/prefs.plist", invoke(config, "getConfigPath")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue((Boolean) invoke(config, "getUpdateConfig")); //$NON-NLS-1$
		assertEquals("lang.properties", invoke(config, "getLanguagePath")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("gl_ES", invoke(config, "getDefaultLanguage")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	/** Comprueba consola, mensajes, excepciones y utilidades sin mutar el sistema. */
	@Test
	void utilityContractsAreStable() throws Exception {
		assertNotNull(new DirectoryUtil());
		assertNotNull(new ConfiguratorMacUtils());
		assertNotNull(DirectoryUtil.getLanguagesDir());
		assertTrue(DirectoryUtil.getLanguagesDir().getName().contains("languages")); //$NON-NLS-1$

		final Console console = ConsoleManager.getConsole(null);
		assertNotNull(console);
		console.showConsole();
		assertNull(console.getParentComponent());
		console.dispose();

		final PrintStream originalOut = System.out;
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			System.setOut(new PrintStream(baos, true, StandardCharsets.UTF_8.name()));
			new PrintConsole().print("texto"); //$NON-NLS-1$
		}
		finally {
			System.setOut(originalOut);
		}
		final String printed = baos.toString(StandardCharsets.UTF_8.name());
		assertTrue(printed.contains("texto")); //$NON-NLS-1$

		assertThrows(IllegalArgumentException.class, () -> new IoConsole(null));
		assertNotNull(Messages.getString("AutofirmaConfigurator.2")); //$NON-NLS-1$
		assertEquals("!missing.key!", Messages.getString("missing.key")); //$NON-NLS-1$ //$NON-NLS-2$
		assertNotNull(Messages.getString("AutofirmaConfigurator.3", "param")); //$NON-NLS-1$ //$NON-NLS-2$
		Messages.updateLocale();

		final Exception cause = new Exception("causa"); //$NON-NLS-1$
		assertEquals("config", new ConfigurationException("config").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		assertSame(cause, new ConfigurationException("config", cause).getCause()); //$NON-NLS-1$
		assertEquals("keychain", new KeyChainException("keychain").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		assertSame(cause, new KeyChainException("keychain", cause).getCause()); //$NON-NLS-1$
		assertEquals("mozilla", new MozillaProfileNotFoundException("mozilla").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$

		final Path copiedCmd = WindowsCmdExecutor.copyCmdFromResources("windows/autofirma-addpath.cmd"); //$NON-NLS-1$
		try {
			assertTrue(Files.size(copiedCmd) > 0);
		}
		finally {
			Files.deleteIfExists(copiedCmd);
		}
		assertThrows(FileNotFoundException.class, () -> WindowsCmdExecutor.copyCmdFromResources("missing.cmd")); //$NON-NLS-1$
	}

	/** Comprueba utilidades locales que no modifican la instalaci&oacute;n. */
	@Test
	void localFileUtilitiesWorkOnTemporaryFiles() throws Exception {
		final Path script = Files.createTempFile("autofirma-test", ".sh"); //$NON-NLS-1$ //$NON-NLS-2$
		try {
			ConfiguratorMacUtils.writeScriptFile(new StringBuilder("linea1"), script.toFile(), false); //$NON-NLS-1$
			ConfiguratorMacUtils.writeScriptFile(new StringBuilder("linea2"), script.toFile(), true); //$NON-NLS-1$
			final String text = Files.readString(script, StandardCharsets.UTF_8);
			assertTrue(text.contains("linea1")); //$NON-NLS-1$
			assertTrue(text.contains("linea2")); //$NON-NLS-1$
			ConfiguratorMacUtils.addExexPermissionsToFile(script.toFile());
		}
		finally {
			Files.deleteIfExists(script);
		}

		final Path dir = Files.createTempDirectory("autofirma-test-dir"); //$NON-NLS-1$
		try {
			Files.writeString(dir.resolve("uno"), "1", StandardCharsets.UTF_8); //$NON-NLS-1$ //$NON-NLS-2$
			Files.writeString(dir.resolve("dos"), "2", StandardCharsets.UTF_8); //$NON-NLS-1$ //$NON-NLS-2$
			ConfiguratorMacUtils.addExexPermissionsToAllFilesOnDirectory(dir.toFile());
		}
		finally {
			Files.deleteIfExists(dir.resolve("uno")); //$NON-NLS-1$
			Files.deleteIfExists(dir.resolve("dos")); //$NON-NLS-1$
			Files.deleteIfExists(dir);
		}

		assertThrows(
			IOException.class,
			() -> WindowsCmdExecutor.executePathCmd(new File("missing.cmd").toPath(), 1) //$NON-NLS-1$
		);
	}

	private static Object newConfigArgs(final String className, final String[] args) throws Exception {
		final Class<?> configClass = Class.forName(className);
		final Constructor<?> constructor = configClass.getDeclaredConstructor(String[].class);
		constructor.setAccessible(true);
		return constructor.newInstance((Object) args);
	}

	private static Object invoke(final Object target, final String methodName) throws Exception {
		final Method method = target.getClass().getDeclaredMethod(methodName);
		method.setAccessible(true);
		return method.invoke(target);
	}
}
