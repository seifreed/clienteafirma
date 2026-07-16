package es.gob.afirma.standalone.configurator.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.misc.SecureXmlBuilder;
import es.gob.afirma.standalone.configurator.common.PreferencesPlistHandler.InvalidPreferencesFileException;

/** Pruebas de contratos locales de clases simples del configurador com&uacute;n. */
final class TestCommonLocalContracts {

	/** Comprueba DTOs y excepciones sin dependencias externas. */
	@Test
	void dataSignatureAndExceptionContractsAreStable() {
		final byte[] data = "abc".getBytes(StandardCharsets.UTF_8); //$NON-NLS-1$
		final ConfigDataInfo configData = new ConfigDataInfo(data);
		assertSame(data, configData.getData());
		assertEquals(64, configData.getHash().length());
		assertTrue(configData.getHash().matches("[0-9A-F]+")); //$NON-NLS-1$

		final X509Certificate[] chain = new X509Certificate[0];
		assertSame(chain, new SignatureInfo(chain).getSigningCertificateChain());

		final Throwable cause = new IllegalStateException("causa"); //$NON-NLS-1$
		assertEquals("mensaje", new InvalidSignatureException("mensaje").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$
		assertSame(cause, new InvalidSignatureException(cause).getCause());
		assertSame(cause, new InvalidSignatureException("mensaje", cause).getCause()); //$NON-NLS-1$
	}

	/** Comprueba claves p&uacute;blicas, c&oacute;digos de error y constructores privados. */
	@Test
	void preferenceKeysAndErrorCodesExposeExpectedValues() throws Exception {
		assertEquals("preferencesBlocked", GeneralPreferenceKeys.BLOCKED); //$NON-NLS-1$
		assertEquals("defaultKeystore", KeyStorePreferenceKeys.DEFAULT_STORE); //$NON-NLS-1$
		assertEquals("proxyHost", ProxyPreferenceKeys.PROXY_HOST); //$NON-NLS-1$
		assertEquals("xadesPolicyIdentifier", SignatureFormatPreferenceKeys.XADES_POLICY_IDENTIFIER); //$NON-NLS-1$
		assertEquals("padesVisibleSignature", SignatureFormatPreferenceKeys.PADES_VISIBLE); //$NON-NLS-1$
		assertEquals("522002", ConfiguratorErrorCode.Functional.INVALID_PREFERENCES_FILE_SIGNATURE.getCode()); //$NON-NLS-1$
		assertEquals("230302", ConfiguratorErrorCode.Internal.INVALID_XML_PREFERENCES_FILE.getCode()); //$NON-NLS-1$
		assertEquals("!clave.inexistente!", ConfiguratorCommonMessages.getString("clave.inexistente")); //$NON-NLS-1$ //$NON-NLS-2$

		assertPrivateConstructor(GeneralPreferenceKeys.class);
		assertPrivateConstructor(KeyStorePreferenceKeys.class);
		assertPrivateConstructor(ProxyPreferenceKeys.class);
		assertPrivateConstructor(SignatureFormatPreferenceKeys.class);
		assertPrivateConstructor(ConfiguratorCommonMessages.class);
	}

	/** Comprueba la carga local de preferencias en formato plist. */
	@Test
	void preferencesPlistHandlerLoadsXmlAndRejectsInvalidInputs() throws Exception {
		final byte[] preferences = (
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + //$NON-NLS-1$
			"<plist><dict>" + //$NON-NLS-1$
			"<key>texto</key><string>valor</string>" + //$NON-NLS-1$
			"<key>activo</key><true/>" + //$NON-NLS-1$
			"</dict></plist>" //$NON-NLS-1$
		).getBytes(StandardCharsets.UTF_8);
		final Map<String, Object> fromBytes = PreferencesPlistHandler.loadPreferencesFromXml(preferences);
		assertEquals("valor", fromBytes.get("texto")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(Boolean.TRUE, fromBytes.get("activo")); //$NON-NLS-1$

		final Document document = SecureXmlBuilder.getSecureDocumentBuilder().parse(new ByteArrayInputStream(preferences));
		final Map<String, Object> fromDocument = PreferencesPlistHandler.loadPreferencesFromXml(document, true);
		assertEquals(fromBytes, fromDocument);

		assertTrue(PreferencesPlistHandler.exportPreferencesToXml().startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\">")); //$NON-NLS-1$
		assertNotNull(new PreferencesPlistHandler());

		final InvalidPreferencesFileException invalidBytes = assertThrows(
			InvalidPreferencesFileException.class,
			() -> PreferencesPlistHandler.loadPreferencesFromXml("<root/>".getBytes(StandardCharsets.UTF_8)) //$NON-NLS-1$
		);
		assertTrue(invalidBytes.getMessage().contains("Error analizando")); //$NON-NLS-1$
		assertNotNull(invalidBytes.getCause());

		assertThrows(IllegalStateException.class, () -> PreferencesPlistHandler.importPreferences((String) null, null, true));
		assertThrows(IllegalStateException.class, () -> PreferencesPlistHandler.importPreferences((byte[]) null, null, true));
		final AOException invalidXml = assertThrows(
			AOException.class,
			() -> PreferencesPlistHandler.importPreferences("<plist>".getBytes(StandardCharsets.UTF_8), null, true) //$NON-NLS-1$
		);
		assertSame(ConfiguratorErrorCode.Internal.INVALID_XML_PREFERENCES_FILE, invalidXml.getErrorCode());
	}

	/** Comprueba la validaci&oacute;n local de los tipos permitidos en preferencias. */
	@Test
	void preferencesPlistHandlerValidatesSupportedPreferenceTypes() throws Exception {
		invokeCheckPreferences(Map.of("texto", "valor", "activo", Boolean.TRUE)); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

		final Map<String, Object> nullValue = new HashMap<>();
		nullValue.put("nula", null); //$NON-NLS-1$
		final InvalidPreferencesFileException nullError = assertThrows(
			InvalidPreferencesFileException.class,
			() -> invokeCheckPreferences(nullValue)
		);
		assertTrue(nullError.getMessage().contains("es nulo")); //$NON-NLS-1$

		final InvalidPreferencesFileException typeError = assertThrows(
			InvalidPreferencesFileException.class,
			() -> invokeCheckPreferences(Map.of("lista", List.of("valor"))) //$NON-NLS-1$ //$NON-NLS-2$
		);
		assertTrue(typeError.getMessage().contains("No se soporta el tipo")); //$NON-NLS-1$
	}

	private static void assertPrivateConstructor(final Class<?> clazz) throws Exception {
		final Constructor<?> constructor = clazz.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
	}

	private static void invokeCheckPreferences(final Map<String, Object> preferences) throws Exception {
		final Method method = PreferencesPlistHandler.class.getDeclaredMethod("checkPreferences", Map.class); //$NON-NLS-1$
		method.setAccessible(true);
		try {
			method.invoke(null, preferences);
		}
		catch (final InvocationTargetException e) {
			if (e.getCause() instanceof Exception) {
				throw (Exception) e.getCause();
			}
			throw e;
		}
	}
}
