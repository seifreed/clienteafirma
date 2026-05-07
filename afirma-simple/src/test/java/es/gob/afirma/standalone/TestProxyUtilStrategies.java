package es.gob.afirma.standalone;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
}
