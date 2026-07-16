package es.gob.afirma.keystores;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.core.MissingLibraryException;
import es.gob.afirma.core.misc.Platform;
import es.gob.afirma.keystores.callbacks.CachePasswordCallback;
import es.gob.afirma.keystores.callbacks.FirstEmptyThenPinUiPasswordCallback;
import es.gob.afirma.keystores.callbacks.NullPasswordCallback;
import es.gob.afirma.keystores.callbacks.UIPasswordCallback;

/** Pruebas offline de contratos b&aacute;sicos del m&oacute;dulo de almacenes. */
final class TestKeyStoreCoreContracts {

	/** Comprueba callbacks que no requieren interfaz gr&aacute;fica. */
	@Test
	void passwordCallbacksKeepTheirLocalContract() {
		final CachePasswordCallback cache = new CachePasswordCallback("clave".toCharArray()); //$NON-NLS-1$
		assertArrayEquals("clave".toCharArray(), cache.getPassword()); //$NON-NLS-1$
		assertTrue(cache.toString().contains("clave")); //$NON-NLS-1$

		assertSame(NullPasswordCallback.getInstance(), NullPasswordCallback.getInstance());
		assertNull(NullPasswordCallback.getInstance().getPassword());

		assertArrayEquals(new char[0], new FirstEmptyThenPinUiPasswordCallback("PIN").getPassword()); //$NON-NLS-1$

		final UIPasswordCallback ui = new UIPasswordCallback("PIN"); //$NON-NLS-1$
		ui.setParent(this);
		ui.setPrompt("Nuevo PIN"); //$NON-NLS-1$
		assertEquals("PIN", ui.getPrompt()); //$NON-NLS-1$
	}

	/** Comprueba metadatos de tipos de almac&eacute;n y configuraciones. */
	@Test
	void keyStoreTypesExposeMetadataAndDefaults() {
		assertEquals("PKCS#12 / PFX", AOKeyStore.PKCS12.getName()); //$NON-NLS-1$
		assertEquals("PKCS12", AOKeyStore.PKCS12.getProviderName()); //$NON-NLS-1$
		assertEquals(3, AOKeyStore.PKCS12.getOrdinal());
		assertEquals(AOKeyStore.PKCS12.getName(), AOKeyStore.PKCS12.toString());
		assertNotNull(AOKeyStore.PKCS12.getCertificatePasswordCallback(this));
		assertNotNull(AOKeyStore.PKCS12.getStorePasswordCallback(this, "Clave")); //$NON-NLS-1$

		assertEquals(AOKeyStore.WINDOWS, AOKeyStore.getDefaultKeyStoreTypeByOs(Platform.OS.WINDOWS));
		assertEquals(AOKeyStore.APPLE, AOKeyStore.getDefaultKeyStoreTypeByOs(Platform.OS.MACOSX));
		assertEquals(AOKeyStore.SHARED_NSS, AOKeyStore.getDefaultKeyStoreTypeByOs(Platform.OS.LINUX));
		assertEquals(AOKeyStore.MOZ_UNI, AOKeyStore.getDefaultKeyStoreTypeByOs(Platform.OS.SOLARIS));
		assertNull(AOKeyStore.getDefaultKeyStoreTypeByOs(Platform.OS.OTHER));
		assertNull(AOKeyStore.getDefaultKeyStoreTypeByOs(null));

		final KeyStoreConfiguration defaultName = new KeyStoreConfiguration(AOKeyStore.JAVA, null, null);
		assertEquals(AOKeyStore.JAVA, defaultName.getType());
		assertNull(defaultName.getLib());
		assertEquals(AOKeyStore.JAVA.getName(), defaultName.toString());

		final KeyStoreConfiguration named = new KeyStoreConfiguration(AOKeyStore.PKCS11, "Token", "/tmp/lib.so"); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals(AOKeyStore.PKCS11, named.getType());
		assertEquals("/tmp/lib.so", named.getLib()); //$NON-NLS-1$
		assertEquals("Token", named.toString()); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> new KeyStoreConfiguration(null, null, null));
	}

	/** Comprueba mensajes y c&oacute;digos de error locales. */
	@Test
	void messagesAndErrorCodesAreAvailable() throws Exception {
		assertTrue(KeyStoreMessages.getString("AOKeyStore.0").contains("PKCS")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(KeyStoreMessages.getString("AOKeyStore.15", "Token").contains("Token")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertEquals("!clave.inexistente!", KeyStoreMessages.getString("clave.inexistente")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("!clave.inexistente!", KeyStoreMessages.getString("clave.inexistente", "texto")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

		assertPrivateConstructor(KeyStoreMessages.class);

		assertEquals("102025", KeyStoreErrorCode.Hardware.SMARTCARD_LOCKED.getCode()); //$NON-NLS-1$
		assertEquals("201101", KeyStoreErrorCode.Internal.LOADING_KEYSTORE_INTERNAL_ERROR.getCode()); //$NON-NLS-1$
		assertEquals("300003", KeyStoreErrorCode.ThirdParty.SUN_MSCAPI_PROVIDER_NOT_FOUND.getCode()); //$NON-NLS-1$
		assertEquals("600011", KeyStoreErrorCode.Request.UNSUPPORTED_KEYSTORE.getCode()); //$NON-NLS-1$
	}

	/** Comprueba constructores de excepciones del m&oacute;dulo. */
	@Test
	void exceptionsPreserveMessageCauseAndErrorCode() {
		final Throwable cause = new IllegalStateException("causa"); //$NON-NLS-1$

		final AOCertificatesNotFoundException noCerts = new AOCertificatesNotFoundException("sin certificados", cause); //$NON-NLS-1$
		assertEquals("sin certificados", noCerts.getMessage()); //$NON-NLS-1$
		assertSame(cause, noCerts.getCause());
		assertSame(ErrorCode.Functional.CERTIFICATE_NEEDED, noCerts.getErrorCode());
		assertSame(ErrorCode.Functional.CERTIFICATE_NEEDED, new AOCertificatesNotFoundException().getErrorCode());
		assertEquals("mensaje", new AOCertificatesNotFoundException("mensaje").getMessage()); //$NON-NLS-1$ //$NON-NLS-2$

		final AOKeyStoreManagerException withMessage = new AOKeyStoreManagerException("error", KeyStoreErrorCode.Internal.LOADING_KEYSTORE_INTERNAL_ERROR); //$NON-NLS-1$
		assertEquals("error", withMessage.getMessage()); //$NON-NLS-1$
		assertSame(KeyStoreErrorCode.Internal.LOADING_KEYSTORE_INTERNAL_ERROR, withMessage.getErrorCode());
		assertSame(cause, new AOKeyStoreManagerException("error", (Exception) cause, KeyStoreErrorCode.Internal.LOADING_KEYSTORE_INTERNAL_ERROR).getCause()); //$NON-NLS-1$
		assertSame(cause, new AOKeyStoreManagerException((Exception) cause, KeyStoreErrorCode.Internal.LOADING_KEYSTORE_INTERNAL_ERROR).getCause());

		final KeystoreAlternativeException alternative = new KeystoreAlternativeException(AOKeyStore.JAVA, "alternativo", cause, KeyStoreErrorCode.Request.UNSUPPORTED_KEYSTORE); //$NON-NLS-1$
		assertEquals(AOKeyStore.JAVA, alternative.getAlternativeKsm());
		assertSame(cause, alternative.getCause());
		assertSame(AOKeyStore.PKCS12, new KeystoreAlternativeException(AOKeyStore.PKCS12, "alternativo", KeyStoreErrorCode.Request.UNSUPPORTED_KEYSTORE).getAlternativeKsm()); //$NON-NLS-1$

		final SmartCardException smartCard = new SmartCardException("tarjeta", cause, KeyStoreErrorCode.Hardware.SMARTCARD_LOCKED); //$NON-NLS-1$
		assertSame(cause, smartCard.getCause());
		assertSame(KeyStoreErrorCode.Hardware.SMARTCARD_LOCKED, smartCard.getErrorCode());
		assertSame(KeyStoreErrorCode.Hardware.SMARTCARD_LOCKED, new SmartCardException("tarjeta", KeyStoreErrorCode.Hardware.SMARTCARD_LOCKED).getErrorCode()); //$NON-NLS-1$
		assertSame(KeyStoreErrorCode.Hardware.SMARTCARD_LOCKED, new SmartCardLockedException("bloqueada").getErrorCode()); //$NON-NLS-1$
		assertSame(cause, new SmartCardLockedException("bloqueada", cause).getCause()); //$NON-NLS-1$

		assertSame(
			KeyStoreErrorCode.ThirdParty.SUN_MSCAPI_PROVIDER_NOT_FOUND,
			new MissingSunMSCAPIException((Exception) cause).getErrorCode()
		);
	}

	/** Comprueba filtros y selecci&oacute;n de almacenes basada en fichero. */
	@Test
	void filtersAndFileFactoryRejectInvalidInputs() throws Exception {
		final CertificateFilter acceptAll = new CertificateFilter() {
			@Override
			public boolean matches(final X509Certificate cert) {
				return true;
			}
		};
		final CertificateFilter rejectAll = new CertificateFilter() {
			@Override
			public boolean matches(final X509Certificate cert) {
				return false;
			}
		};

		assertTrue(acceptAll.matches(null));
		assertTrue(new MultipleCertificateFilter(new CertificateFilter[] { acceptAll }).matches(null));
		assertFalse(new MultipleCertificateFilter(new CertificateFilter[] { acceptAll, rejectAll }).matches(null));
		assertThrows(IllegalArgumentException.class, () -> new MultipleCertificateFilter(null));

		assertThrows(
			IllegalArgumentException.class,
			() -> FileBasedKeyStoreManagerFactory.getKeyStoreManager(null, this)
		);
		assertThrows(
			IOException.class,
			() -> FileBasedKeyStoreManagerFactory.getKeyStoreManager(new File("almacen-inexistente.p12"), this) //$NON-NLS-1$
		);
		final File unsupported = File.createTempFile("almacen", ".txt"); //$NON-NLS-1$ //$NON-NLS-2$
		unsupported.deleteOnExit();
		assertThrows(
			IllegalArgumentException.class,
			() -> FileBasedKeyStoreManagerFactory.getKeyStoreManager(unsupported, this)
		);
		assertPrivateConstructor(FileBasedKeyStoreManagerFactory.class);
		assertPrivateConstructor(AOKeyStoreManagerFactory.class);
	}

	/** Comprueba contratos locales de gestores y auxiliares de carga. */
	@Test
	void fileManagersAndHelpersExposeTheirLocalContract() throws Exception {
		assertEquals(AOKeyStore.JAVA, new JavaKeyStoreManager().getType());
		assertEquals(AOKeyStore.PKCS12, new Pkcs12KeyStoreManager().getType());

		assertThrows(
			IOException.class,
			() -> AOKeyStoreManagerHelperJava.initJava(null, null, AOKeyStore.JAVA)
		);
		final AOKeyStoreManagerException singleError = assertThrows(
			AOKeyStoreManagerException.class,
			() -> AOKeyStoreManagerHelperSingle.initSingle(null, null)
		);
		assertSame(KeyStoreErrorCode.Internal.LOADING_CERTIFICATE_ERROR, singleError.getErrorCode());
		assertPrivateConstructor(AOKeyStoreManagerHelperJava.class);
		assertPrivateConstructor(AOKeyStoreManagerHelperSingle.class);
	}

	/** Comprueba carga real de almacenes software vac&iacute;os y utilidades sin UI. */
	@Test
	void softwareKeyStoresAndUtilitiesUseRealFormats(@TempDir final Path tempDir) throws Exception {
		final byte[] jks = emptyKeyStore("JKS", "clave".toCharArray()); //$NON-NLS-1$ //$NON-NLS-2$
		final KeyStore loadedJks = AOKeyStoreManagerHelperJava.initJava(
			new ByteArrayInputStream(jks),
			new CachePasswordCallback("clave".toCharArray()), //$NON-NLS-1$
			AOKeyStore.JAVA
		);
		assertEquals("JKS", loadedJks.getType()); //$NON-NLS-1$

		final byte[] pkcs12 = emptyKeyStore("PKCS12", "clave".toCharArray()); //$NON-NLS-1$ //$NON-NLS-2$
		final Pkcs12KeyStoreManager pkcs12Manager = new Pkcs12KeyStoreManager();
		pkcs12Manager.init(
			AOKeyStore.PKCS12,
			new ByteArrayInputStream(pkcs12),
			new CachePasswordCallback("clave".toCharArray()), //$NON-NLS-1$
			null,
			false
		);
		assertTrue(pkcs12Manager.getAliases().length == 0);

		final Path jksFile = tempDir.resolve("almacen.jks"); //$NON-NLS-1$
		Files.write(jksFile, jks);
		final AggregatedKeyStoreManager jksManager = AOKeyStoreManagerFactory.getAOKeyStoreManager(
			AOKeyStore.JAVA,
			jksFile.toString(),
			null,
			new CachePasswordCallback("clave".toCharArray()), //$NON-NLS-1$
			null
		);
		assertEquals(AOKeyStore.JAVA, jksManager.getType());
		assertEquals(0, jksManager.getAliases().length);

		final String oldForceReset = System.getProperty(AOKeyStoreManagerFactory.FORCE_STORE_RESET);
		try {
			System.setProperty(AOKeyStoreManagerFactory.FORCE_STORE_RESET, Boolean.TRUE.toString());
			final AggregatedKeyStoreManager forcedJksManager = AOKeyStoreManagerFactory.getAOKeyStoreManager(
				AOKeyStore.JAVA,
				jksFile.toString(),
				null,
				new CachePasswordCallback("clave".toCharArray()), //$NON-NLS-1$
				null
			);
			assertEquals(AOKeyStore.JAVA, forcedJksManager.getType());
		}
		finally {
			if (oldForceReset != null) {
				System.setProperty(AOKeyStoreManagerFactory.FORCE_STORE_RESET, oldForceReset);
			}
			else {
				System.clearProperty(AOKeyStoreManagerFactory.FORCE_STORE_RESET);
			}
		}

		final Path pkcs12File = tempDir.resolve("almacen.p12"); //$NON-NLS-1$
		Files.write(pkcs12File, pkcs12);
		final AggregatedKeyStoreManager aggregatedPkcs12Manager = AOKeyStoreManagerFactory.getAOKeyStoreManager(
			AOKeyStore.PKCS12,
			pkcs12File.toString(),
			null,
			new CachePasswordCallback("clave".toCharArray()), //$NON-NLS-1$
			null
		);
		assertEquals(AOKeyStore.PKCS12, aggregatedPkcs12Manager.getType());
		assertEquals(0, aggregatedPkcs12Manager.getAliases().length);

		assertThrows(MissingLibraryException.class, () -> AOKeyStoreManagerFactory.getAOKeyStoreManager(
			AOKeyStore.SINGLE,
			testResourcePath("afirma-core/src/test/resources/CERES.cer").toString(), //$NON-NLS-1$
			null,
			NullPasswordCallback.getInstance(),
			null
		));

		final Path realPkcs12File = tempDir.resolve("anf.pfx"); //$NON-NLS-1$
		Files.copy(testResourcePath("afirma-core-keystores/src/test/resources/ANF_PF_Activo.pfx"), realPkcs12File); //$NON-NLS-1$
		final AggregatedKeyStoreManager realPkcs12Manager = AOKeyStoreManagerFactory.getAOKeyStoreManager(
			AOKeyStore.PKCS12,
			realPkcs12File.toString(),
			null,
			new CachePasswordCallback("12341234".toCharArray()), //$NON-NLS-1$
			null
		);
		assertTrue(realPkcs12Manager.getAliases().length > 0);
		assertNotNull(realPkcs12Manager.getCertificate("anf usuario activo")); //$NON-NLS-1$
		assertNotNull(realPkcs12Manager.getKeyEntry("anf usuario activo")); //$NON-NLS-1$
		final Map<String, String> realAliases = KeyStoreUtilities.getAliasesByFriendlyName(
			realPkcs12Manager.getAliases(),
			realPkcs12Manager,
			true,
			true,
			null
		);
		assertTrue(realAliases.containsKey("anf usuario activo")); //$NON-NLS-1$
		final Map<String, String> rejectedAliases = KeyStoreUtilities.getAliasesByFriendlyName(
			realPkcs12Manager.getAliases(),
			realPkcs12Manager,
			false,
			true,
			List.of(new CertificateFilter() {
				@Override
				public boolean matches(final X509Certificate cert) {
					return false;
				}
			})
		);
		assertTrue(rejectedAliases.isEmpty());

		assertThrows(IOException.class, () -> AOKeyStoreManagerFactory.getAOKeyStoreManager(
			AOKeyStore.PKCS11,
			tempDir.resolve("missing-pkcs11.so").toString(), //$NON-NLS-1$
			null,
			NullPasswordCallback.getInstance(),
			null
		));

		final String pkcs11 = KeyStoreUtilities.createPKCS11ConfigFile("UsrPkcs11.dll", "Token", Integer.valueOf(1)); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(pkcs11.contains("name=Token")); //$NON-NLS-1$
		assertTrue(pkcs11.contains("slot=1")); //$NON-NLS-1$
		assertTrue(pkcs11.contains("disabledMechanisms")); //$NON-NLS-1$
		final String genericPkcs11 = KeyStoreUtilities.createPKCS11ConfigFile("libgenerica.so", null, null); //$NON-NLS-1$
		assertTrue(genericPkcs11.contains("name=AFIRMA-PKCS11")); //$NON-NLS-1$
		assertFalse(genericPkcs11.contains("slot=")); //$NON-NLS-1$
		assertFalse(genericPkcs11.contains("disabledMechanisms")); //$NON-NLS-1$
		assertNull(KeyStoreUtilities.searchPathForFile(null));
		assertNull(KeyStoreUtilities.searchPathForFile(new String[0]));
		final File library = File.createTempFile("lib", ".so"); //$NON-NLS-1$ //$NON-NLS-2$
		library.deleteOnExit();
		assertEquals(library.getAbsolutePath(), KeyStoreUtilities.searchPathForFile(new String[] { library.getAbsolutePath() }));
		assertNull(KeyStoreUtilities.searchPathForFile(new String[] { "biblioteca-inexistente.so" })); //$NON-NLS-1$
		assertNull(KeyStoreUtilities.getWindowsShortName(null));

		final Method alternateStore = AOKeyStoreManagerFactory.class.getDeclaredMethod("getAlternateKeyStoreType", AOKeyStore.class); //$NON-NLS-1$
		alternateStore.setAccessible(true);
		assertNull(alternateStore.invoke(null, AOKeyStore.PKCS12));
		if (Platform.OS.WINDOWS.equals(Platform.getOS())) {
			assertEquals(AOKeyStore.WINDOWS, alternateStore.invoke(null, AOKeyStore.JAVA));
		}
		else if (Platform.OS.MACOSX.equals(Platform.getOS())) {
			assertEquals(AOKeyStore.APPLE, alternateStore.invoke(null, AOKeyStore.JAVA));
		}
		else {
			assertEquals(AOKeyStore.PKCS12, alternateStore.invoke(null, AOKeyStore.JAVA));
		}

		final String longAlias = "A".repeat(150); //$NON-NLS-1$
		final Map<String, String> aliases = KeyStoreUtilities.getAliasesByFriendlyName(
			new String[] { " alias ", longAlias }, //$NON-NLS-1$
			null,
			false,
			true,
			null
		);
		assertEquals("alias", aliases.get(" alias ")); //$NON-NLS-1$ //$NON-NLS-2$
		assertNotNull(aliases.get(longAlias));
		final String x500Alias = "CN=Nombre de Prueba, OU=Unidad, O=Organizacion, L=Madrid, ST=Madrid, C=ES, SERIALNUMBER=12345678Z, EMAILADDRESS=persona@example.com"; //$NON-NLS-1$
		assertEquals(
			"Nombre de Prueba", //$NON-NLS-1$
			KeyStoreUtilities.getAliasesByFriendlyName(new String[] { x500Alias }, null, false, true, null).get(x500Alias)
		);

		final String oldDnie = System.getProperty(KeyStoreUtilities.DISABLE_DNIE_NATIVE_DRIVER);
		final String oldCeres = System.getProperty(KeyStoreUtilities.DISABLE_CERES_NATIVE_DRIVER);
		final String oldSmartCafe = System.getProperty(KeyStoreUtilities.ENABLE_GYDSC_NATIVE_DRIVER);
		try {
			System.setProperty(KeyStoreUtilities.DISABLE_DNIE_NATIVE_DRIVER, Boolean.TRUE.toString());
			System.setProperty(KeyStoreUtilities.DISABLE_CERES_NATIVE_DRIVER, Boolean.TRUE.toString());
			System.clearProperty(KeyStoreUtilities.ENABLE_GYDSC_NATIVE_DRIVER);
			assertFalse(KeyStoreUtilities.addPreferredKeyStoreManagers(new AggregatedKeyStoreManager(), this));
		}
		finally {
			restoreProperty(KeyStoreUtilities.DISABLE_DNIE_NATIVE_DRIVER, oldDnie);
			restoreProperty(KeyStoreUtilities.DISABLE_CERES_NATIVE_DRIVER, oldCeres);
			restoreProperty(KeyStoreUtilities.ENABLE_GYDSC_NATIVE_DRIVER, oldSmartCafe);
		}
		assertPrivateConstructor(KeyStoreUtilities.class);
	}

	/** Comprueba el manejador de callbacks de contrase&ntilde;a sin mostrar interfaz gr&aacute;fica. */
	@Test
	void passwordCallbackHandlerHandlesLocalCallbacks() throws Exception {
		final KeyStoreUtilities.PasswordCallbackHandler handler = new KeyStoreUtilities.PasswordCallbackHandler(
			this,
			new CachePasswordCallback("clave".toCharArray()) //$NON-NLS-1$
		);
		final PasswordCallback passwordCallback = new PasswordCallback("PIN", false); //$NON-NLS-1$
		handler.handle(new Callback[] { passwordCallback });
		assertArrayEquals("clave".toCharArray(), passwordCallback.getPassword()); //$NON-NLS-1$
		assertFalse(handler.isCancelled());

		final Callback unsupported = new Callback() {
			// Tipo desconocido para el manejador.
		};
		final UnsupportedCallbackException unknownCallback = assertThrows(
			UnsupportedCallbackException.class,
			() -> handler.handle(new Callback[] { unsupported })
		);
		assertSame(unsupported, unknownCallback.getCallback());

		final KeyStoreUtilities.PasswordCallbackHandler cancelledHandler = new KeyStoreUtilities.PasswordCallbackHandler(
			this,
			NullPasswordCallback.getInstance()
		);
		final PasswordCallback cancelledPasswordCallback = new PasswordCallback("PIN", false); //$NON-NLS-1$
		cancelledHandler.handle(new Callback[] { cancelledPasswordCallback });
		assertNull(cancelledPasswordCallback.getPassword());
		assertFalse(cancelledHandler.isCancelled());
	}

	private static byte[] emptyKeyStore(final String type, final char[] password) throws Exception {
		final KeyStore keyStore = KeyStore.getInstance(type);
		keyStore.load(null, password);
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		keyStore.store(baos, password);
		return baos.toByteArray();
	}

	private static void assertPrivateConstructor(final Class<?> clazz) throws Exception {
		final Constructor<?> constructor = clazz.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertNotNull(constructor.newInstance());
	}

	private static void restoreProperty(final String key, final String value) {
		if (value == null) {
			System.clearProperty(key);
		}
		else {
			System.setProperty(key, value);
		}
	}

	private static Path testResourcePath(final String rootRelativePath) {
		final Path fromRoot = Path.of(rootRelativePath);
		if (Files.exists(fromRoot)) {
			return fromRoot;
		}
		return Path.of("..").resolve(rootRelativePath).normalize(); //$NON-NLS-1$
	}
}
