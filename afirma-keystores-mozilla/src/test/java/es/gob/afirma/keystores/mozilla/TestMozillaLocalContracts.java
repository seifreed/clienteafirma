package es.gob.afirma.keystores.mozilla;

import java.io.File;
import java.io.StringReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import es.gob.afirma.core.misc.Platform;
import es.gob.afirma.keystores.mozilla.AOSecMod.ModuleName;

/** Pruebas de contratos locales que no requieren una instalaci&oacute;n NSS real. */
public final class TestMozillaLocalContracts {

	/** Comprueba mensajes, constructores privados y m&oacute;dulos NSS simples. */
	@Test
	public void testMessagesAndSimpleContracts() throws Exception {
		Assert.assertTrue(
			FirefoxKeyStoreMessages.getString("MozillaUnifiedKeyStoreManager.0").contains("Firefox") //$NON-NLS-1$ //$NON-NLS-2$
		);
		Assert.assertEquals("!clave.inexistente!", FirefoxKeyStoreMessages.getString("clave.inexistente")); //$NON-NLS-1$ //$NON-NLS-2$

		final ModuleName module = new ModuleName("/usr/lib/libpkcs11.so", "Modulo"); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals("/usr/lib/libpkcs11.so", module.getLib()); //$NON-NLS-1$
		Assert.assertEquals("Modulo", module.getDescription()); //$NON-NLS-1$
		Assert.assertEquals("Modulo (EXTERNAL, /usr/lib/libpkcs11.so, slot 0)", module.toString()); //$NON-NLS-1$

		Assert.assertThrows(IllegalArgumentException.class, () -> AOSecMod.getModules(null));
		Assert.assertThrows(IllegalArgumentException.class, () -> AOSecMod.getModules("")); //$NON-NLS-1$

		assertPrivateConstructor(AOSecMod.class);
		assertPrivateConstructor(Pkcs11Txt.class);
		assertPrivateConstructor(FirefoxKeyStoreMessages.class);
		assertPrivateConstructor(BundledNssHelper.class);
		assertPrivateConstructor(MozillaKeyStoreUtilities.class);
	}

	/** Comprueba an&aacute;lisis de perfiles de Firefox con rutas relativas y absolutas. */
	@Test
	public void testProfilesIniParsing() throws Exception {
		final ProfilesIni profiles = new ProfilesIni(
			new File(TestMozillaLocalContracts.class.getResource("/profiles.ini").toURI()) //$NON-NLS-1$
		);
		Assert.assertEquals(3, profiles.getProfilesList().size());
		Assert.assertEquals(1, profiles.getGeneralInfo().getVersion());
		Assert.assertTrue(profiles.getGeneralInfo().isStartWithLastProfile());
		Assert.assertNull(profiles.getStateInfo());

		final File baseDir = Files.createTempDirectory("profiles").toFile(); //$NON-NLS-1$
		final File profileDir = new File(baseDir, "relativo"); //$NON-NLS-1$
		Assert.assertTrue(profileDir.mkdirs());
		Assert.assertTrue(new File(profileDir, "parent.lock").createNewFile()); //$NON-NLS-1$

		final File profilesIni = new File(baseDir, "profiles.ini"); //$NON-NLS-1$
		Files.writeString(
			profilesIni.toPath(),
			"[General]\nVersion=2\nStartWithLastProfile=0\n\n" + //$NON-NLS-1$
				"[Install123]\nDefault=relativo\nLocked=1\n\n" + //$NON-NLS-1$
				"[Profile0]\nName=relativo\nIsRelative=1\nPath=relativo\nDefault=1\n", //$NON-NLS-1$
			StandardCharsets.UTF_8
		);

		final ProfilesIni parsed = new ProfilesIni(profilesIni);
		Assert.assertEquals(2, parsed.getGeneralInfo().getVersion());
		Assert.assertFalse(parsed.getGeneralInfo().isStartWithLastProfile());
		Assert.assertEquals("relativo", parsed.getStateInfo().getDefaultProfilePath()); //$NON-NLS-1$
		Assert.assertTrue(parsed.getStateInfo().isLocked());
		Assert.assertTrue(parsed.getStateInfo().isLockedDeclared());
		Assert.assertEquals(1, parsed.getProfilesList().size());
		final ProfilesIni.FirefoxProfile profile = parsed.getProfilesList().get(0);
		Assert.assertEquals("relativo", profile.getName()); //$NON-NLS-1$
		Assert.assertTrue(profile.isRelative());
		Assert.assertTrue(profile.isDefault());
		Assert.assertTrue(profile.isLocked());
		Assert.assertTrue(profile.toString().contains("bloqueado")); //$NON-NLS-1$
	}

	/** Comprueba selecci&oacute;n del perfil activo de Firefox con un perfil v&aacute;lido. */
	@Test
	public void testNsPreferencesSelectsActiveProfile() throws Exception {
		final File baseDir = Files.createTempDirectory("profiles-active").toFile(); //$NON-NLS-1$
		final File profileDir = new File(baseDir, "activo"); //$NON-NLS-1$
		Assert.assertTrue(profileDir.mkdirs());
		for (int i = 0; i < 10; i++) {
			Assert.assertTrue(new File(profileDir, "f" + i).createNewFile()); //$NON-NLS-1$
		}
		Assert.assertTrue(new File(profileDir, "key4.db").createNewFile()); //$NON-NLS-1$
		Assert.assertTrue(new File(profileDir, "parent.lock").createNewFile()); //$NON-NLS-1$

		final File profilesIni = new File(baseDir, "profiles.ini"); //$NON-NLS-1$
		Files.writeString(
			profilesIni.toPath(),
			"[General]\nVersion=1\nStartWithLastProfile=1\n\n" + //$NON-NLS-1$
				"[Profile0]\nName=activo\nIsRelative=1\nPath=activo\nDefault=1\n", //$NON-NLS-1$
			StandardCharsets.UTF_8
		);

		Assert.assertEquals(
			profileDir.getCanonicalPath(),
			new File(NSPreferences.getFireFoxUserProfileDirectory(profilesIni)).getCanonicalPath()
		);
	}

	/** Comprueba variantes admitidas del fichero pkcs11.txt. */
	@Test
	public void testPkcs11TxtParserVariants() throws Exception {
		final List<ModuleName> modules = Pkcs11Txt.getModules(
			new StringReader(
				"library=/uno/libuno.so name=\"Uno\"\n\n" + //$NON-NLS-1$
					"name=Dos\nlibrary=/dos/libdos.so\n" //$NON-NLS-1$
			)
		);
		Assert.assertEquals(2, modules.size());
		Assert.assertEquals("/uno/libuno.so", modules.get(0).getLib()); //$NON-NLS-1$
		Assert.assertEquals("Uno", modules.get(0).getDescription()); //$NON-NLS-1$
		Assert.assertEquals("/dos/libdos.so", modules.get(1).getLib()); //$NON-NLS-1$
		Assert.assertEquals("Dos", modules.get(1).getDescription()); //$NON-NLS-1$
	}

	/** Comprueba que la validaci&oacute;n de rutas ZIP no permite escapar del directorio destino. */
	@Test
	public void testBundledNssParentCheck() throws Exception {
		final File parent = Files.createTempDirectory("nss").toFile(); //$NON-NLS-1$
		final File child = new File(parent, "sub/file.txt"); //$NON-NLS-1$
		final File outside = new File(parent.getParentFile(), "file.txt"); //$NON-NLS-1$
		final Method isParent = BundledNssHelper.class.getDeclaredMethod("isParent", File.class, File.class); //$NON-NLS-1$
		isParent.setAccessible(true);
		Assert.assertEquals(Boolean.TRUE, isParent.invoke(null, parent, child));
		Assert.assertEquals(Boolean.FALSE, isParent.invoke(null, parent, outside));
	}

	/** Comprueba utilidades locales de los m&oacute;dulos PKCS#11 de Mozilla. */
	@Test
	public void testMozillaKeyStoreUtilitiesLocalContracts() throws Exception {
		final String config = MozillaKeyStoreUtilities.createPKCS11NSSConfig("/perfil", "/nss"); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertTrue(config.contains("name=NSSCrypto-AFirma")); //$NON-NLS-1$
		Assert.assertTrue(config.contains("configdir='/perfil'")); //$NON-NLS-1$
		Assert.assertTrue(config.contains("flags='readOnly'")); //$NON-NLS-1$
		if (Platform.OS.WINDOWS.equals(Platform.getOS())) {
			Assert.assertTrue(config.contains("softokn3.dll")); //$NON-NLS-1$
		}
		else if (Platform.OS.MACOSX.equals(Platform.getOS())) {
			Assert.assertTrue(config.contains("libsoftokn3.dylib")); //$NON-NLS-1$
		}
		else {
			Assert.assertTrue(config.contains("libsoftokn3.so")); //$NON-NLS-1$
		}

		Assert.assertTrue(MozillaKeyStoreUtilities.getPkcs11ModulesFromModuleNames(null, false, false).isEmpty());
		final List<ModuleName> modules = List.of(
			new ModuleName("/usr/lib/opensc-pkcs11.dll", "DNIe"), //$NON-NLS-1$ //$NON-NLS-2$
			new ModuleName("/usr/lib/libnssckbi.so", "Raices"), //$NON-NLS-1$ //$NON-NLS-2$
			new ModuleName("/usr/lib/libuno.so", "Uno"), //$NON-NLS-1$ //$NON-NLS-2$
			new ModuleName("/usr/lib/LIBUNO.SO", "Uno duplicado"), //$NON-NLS-1$ //$NON-NLS-2$
			new ModuleName("/usr/lib/libdos.so", "Dos") //$NON-NLS-1$ //$NON-NLS-2$
		);
		final Map<String, String> filtered = MozillaKeyStoreUtilities.getPkcs11ModulesFromModuleNames(modules, false, true);
		Assert.assertFalse(filtered.containsKey("DNIe")); //$NON-NLS-1$
		Assert.assertFalse(filtered.containsKey("Raices")); //$NON-NLS-1$
		Assert.assertEquals("/usr/lib/libuno.so", filtered.get("Uno")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals("/usr/lib/LIBUNO.SO", filtered.get("Uno duplicado")); //$NON-NLS-1$ //$NON-NLS-2$
		Assert.assertEquals("/usr/lib/libdos.so", filtered.get("Dos")); //$NON-NLS-1$ //$NON-NLS-2$

		final String disableDnieNativeDriver = "es.gob.afirma.keystores.mozilla.disableDnieNativeDriver"; //$NON-NLS-1$
		final String previousDisableDnie = System.getProperty(disableDnieNativeDriver);
		try {
			System.setProperty(disableDnieNativeDriver, Boolean.TRUE.toString());
			final Map<String, String> includedDnie = MozillaKeyStoreUtilities.getPkcs11ModulesFromModuleNames(modules, false, true);
			Assert.assertEquals("/usr/lib/opensc-pkcs11.dll", includedDnie.get("DNIe")); //$NON-NLS-1$ //$NON-NLS-2$
		}
		finally {
			if (previousDisableDnie != null) {
				System.setProperty(disableDnieNativeDriver, previousDisableDnie);
			}
			else {
				System.clearProperty(disableDnieNativeDriver);
			}
		}

		final Method isModuleIncluded = MozillaKeyStoreUtilities.class.getDeclaredMethod("isModuleIncluded", Map.class, String.class); //$NON-NLS-1$
		isModuleIncluded.setAccessible(true);
		Assert.assertEquals(Boolean.TRUE, isModuleIncluded.invoke(null, filtered, "libdos.so")); //$NON-NLS-1$
		Assert.assertEquals(Boolean.FALSE, isModuleIncluded.invoke(null, filtered, "libtres.so")); //$NON-NLS-1$
		Assert.assertThrows(Exception.class, () -> isModuleIncluded.invoke(null, null, "libdos.so")); //$NON-NLS-1$

		final Method getSoftkn3Dependencies = MozillaKeyStoreUtilities.class.getDeclaredMethod("getSoftkn3Dependencies", String.class); //$NON-NLS-1$
		getSoftkn3Dependencies.setAccessible(true);
		Assert.assertEquals(0, ((String[]) getSoftkn3Dependencies.invoke(null, new Object[] { null })).length);
		MozillaKeyStoreUtilities.loadNSSDependencies(Files.createTempDirectory("nss-empty").toString()); //$NON-NLS-1$
	}

	private static void assertPrivateConstructor(final Class<?> clazz) throws Exception {
		final Constructor<?> constructor = clazz.getDeclaredConstructor();
		constructor.setAccessible(true);
		Assert.assertNotNull(constructor.newInstance());
	}
}
