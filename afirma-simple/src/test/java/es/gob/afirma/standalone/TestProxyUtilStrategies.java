package es.gob.afirma.standalone;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONException;
import org.junit.Test;

/** Regression contract for {@link ProxyUtil}'s proxy-vole strategy set.
 *
 * <p>Background: the project depends transitively on Mozilla Rhino through
 * proxy-vole &rarr; delight-rhino-sandbox. Rhino is only invoked when proxy-vole
 * is asked to evaluate a PAC (Proxy Auto-Config) JavaScript file, which happens
 * if (and only if) the caller registers {@code Strategy.JAVA}. The current code
 * registers only {@code OS_DEFAULT} and {@code BROWSER}, so Rhino is unused at
 * runtime. We override Rhino to a CVE-patched version anyway, but this test
 * locks the assumption: if anyone adds {@code Strategy.JAVA} in the future, the
 * build fails here so the rhino override and its CVE coverage can be re-checked.
 *
 * <p>The test deliberately does <em>not</em> exercise proxy-vole at runtime.
 * It reads the source of {@link ProxyUtil} and inspects the literal
 * {@code addStrategy(Strategy.X)} calls, because the contract we want to enforce
 * is on the source itself, independent of platform proxy state.
 */
public final class TestProxyUtilStrategies {

	private static final Path PROXY_UTIL_SRC = Paths.get(
		"src", "main", "java", "es", "gob", "afirma", "standalone", "ProxyUtil.java" //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$ //$NON-NLS-6$ //$NON-NLS-7$
	);

	/** Strategies the project is allowed to register. Add a strategy here only
	 * after re-evaluating the rhino override in the root pom.xml. */
	private static final Set<String> ALLOWED_STRATEGIES = new TreeSet<>();
	static {
		ALLOWED_STRATEGIES.add("OS_DEFAULT"); //$NON-NLS-1$
		ALLOWED_STRATEGIES.add("BROWSER"); //$NON-NLS-1$
	}

	@Test
	public void proxyUtilOnlyUsesAuditedStrategies() throws IOException {
		assertTrue(
			"ProxyUtil.java not found at expected path " + PROXY_UTIL_SRC.toAbsolutePath() //$NON-NLS-1$
				+ "; running tests from a non-module-root working directory?", //$NON-NLS-1$
			Files.isRegularFile(PROXY_UTIL_SRC)
		);

		final String source = new String(
			Files.readAllBytes(PROXY_UTIL_SRC),
			StandardCharsets.UTF_8
		);

		final Pattern strategyCall = Pattern.compile(
			"addStrategy\\s*\\(\\s*Strategy\\.([A-Z_]+)\\s*\\)" //$NON-NLS-1$
		);

		final Set<String> registered = new TreeSet<>();
		final Matcher m = strategyCall.matcher(source);
		while (m.find()) {
			registered.add(m.group(1));
		}

		assertEquals(
			"ProxyUtil registered strategies have changed. If you added a new" //$NON-NLS-1$
				+ " strategy, re-evaluate the rhino-runtime override in the root" //$NON-NLS-1$
				+ " pom.xml: Strategy.JAVA in particular activates Rhino-based" //$NON-NLS-1$
				+ " PAC evaluation, which means CVE coverage for" //$NON-NLS-1$
				+ " org.mozilla:rhino-runtime needs to remain pinned to a patched" //$NON-NLS-1$
				+ " version (currently 1.7.15.1, see CVE-2025-66453). Then update" //$NON-NLS-1$
				+ " ALLOWED_STRATEGIES in this test to reflect the new contract.", //$NON-NLS-1$
			ALLOWED_STRATEGIES,
			registered
		);
	}

	@Test
	public void proxyConfigPreservesValuesAndClonesPassword() {
		final ProxyConfig config = new ProxyConfig(ProxyConfig.ConfigType.CUSTOM);
		config.setHost("proxy.example"); //$NON-NLS-1$
		config.setPort("8080"); //$NON-NLS-1$
		config.setUsername("usuario"); //$NON-NLS-1$
		config.setExcludedUrls("localhost|*.local"); //$NON-NLS-1$
		final char[] password = "clave".toCharArray(); //$NON-NLS-1$
		config.setPassword(password);
		password[0] = 'X';

		assertEquals(ProxyConfig.ConfigType.CUSTOM, config.getConfigType());
		assertEquals("proxy.example", config.getHost()); //$NON-NLS-1$
		assertEquals("8080", config.getPort()); //$NON-NLS-1$
		assertEquals("usuario", config.getUsername()); //$NON-NLS-1$
		assertEquals("localhost|*.local", config.getExcludedUrls()); //$NON-NLS-1$
		assertEquals('c', config.getPassword()[0]);

		final char[] returnedPassword = config.getPassword();
		returnedPassword[0] = 'X';
		assertEquals('c', config.getPassword()[0]);

		config.setPassword(null);
		assertNull(config.getPassword());
	}

	@Test
	public void proxyPasswordCipherRoundtripAndNoProxySelector() throws GeneralSecurityException, JSONException, IOException {
		assertNull(ProxyUtil.cipherPassword(null));
		assertNull(ProxyUtil.cipherPassword(new char[0]));
		assertNull(ProxyUtil.decipherPassword(null));
		assertNull(ProxyUtil.decipherPassword("")); //$NON-NLS-1$

		final char[] password = "secreto".toCharArray(); //$NON-NLS-1$
		final String ciphered = ProxyUtil.cipherPassword(password);
		assertNotNull(ciphered);
		assertEquals("secreto", String.valueOf(ProxyUtil.decipherPassword(ciphered))); //$NON-NLS-1$

		final ProxyUtil.NoProxySelector selector = new ProxyUtil.NoProxySelector();
		final List<Proxy> proxies = selector.select(URI.create("https://firmaelectronica.gob.es/")); //$NON-NLS-1$
		assertEquals(1, proxies.size());
		assertSame(Proxy.NO_PROXY, proxies.get(0));
		selector.connectFailed(URI.create("https://firmaelectronica.gob.es/"), null, new IOException("sin red")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	@Test
	public void desktopUtilPureContracts() throws Exception {
		assertNotNull(DesktopUtil.getDefaultDialogsIcon());
		assertEquals(7, DesktopUtil.getIconImages().size());
		assertSame(DesktopUtil.getIconImages(), DesktopUtil.getIconImages());
		assertFalse(DesktopUtil.getAutoStartEnabled());
		DesktopUtil.setAutoStartEnabled(true);
		DesktopUtil.setAutoStartEnabled(false);
		assertNotNull(DesktopUtil.getApplicationDirectory());
		assertNotNull(DesktopUtil.getApplicationFilename());
		assertNotNull(DesktopUtil.getJNLPApplicationDirectory());
		assertNotNull(DesktopUtil.getLinuxAlternativeAppDir());
		assertNotNull(DesktopUtil.getMacOsXAlternativeAppDir());
		assertNotNull(DesktopUtil.getAlternativeDirectory());
		assertEquals(0, DesktopUtil.getDPI());

		final File currentDirectory = new File("."); //$NON-NLS-1$
		assertNull(DesktopUtil.getCommand(currentDirectory));

		final File jar = new File("Autofirma.jar"); //$NON-NLS-1$
		final List<String> jarCommand = DesktopUtil.getCommand(jar);
		assertNotNull(jarCommand);
		assertEquals("-jar", jarCommand.get(1)); //$NON-NLS-1$
		assertEquals(jar.getPath(), jarCommand.get(2));

		final File exe = new File("Autofirma.exe"); //$NON-NLS-1$
		final List<String> exeCommand = DesktopUtil.getCommand(exe);
		assertEquals(1, exeCommand.size());
		assertEquals(exe.getPath(), exeCommand.get(0));

		assertNull(DesktopUtil.getCommand(new File("Autofirma.txt"))); //$NON-NLS-1$
		assertEquals(new File(".").getCanonicalFile(), DesktopUtil.getCanonicalFile(new File("."))); //$NON-NLS-1$ //$NON-NLS-2$

		privateConstructor(ProxyUtil.class).newInstance();
		privateConstructor(DesktopUtil.class).newInstance();
	}

	private static Constructor<?> privateConstructor(final Class<?> clazz) throws NoSuchMethodException {
		final Constructor<?> constructor = clazz.getDeclaredConstructor();
		constructor.setAccessible(true);
		return constructor;
	}
}
