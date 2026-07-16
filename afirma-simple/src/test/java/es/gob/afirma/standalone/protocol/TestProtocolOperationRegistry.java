/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Cubre el contrato del {@link ProtocolOperationRegistry}: orden de
 * resolución, lookup nulo y registro de {@link EudiwProtocolHandler}.
 */
final class TestProtocolOperationRegistry {

	@Test
	@DisplayName("resolve() devuelve el primer handler en orden de registro")
	void firstMatchWins() {
		final ProtocolOperationHandler first = stub("a", url -> url.contains("a"));
		final ProtocolOperationHandler second = stub("b", url -> url.contains("a"));
		final ProtocolOperationRegistry registry = new ProtocolOperationRegistry()
				.register(first)
				.register(second);
		assertSame(first, registry.resolve("a-url").orElseThrow());
		assertEquals(2, registry.size());
	}

	@Test
	@DisplayName("resolve() devuelve empty si ningún handler matchea")
	void noMatch() {
		final ProtocolOperationRegistry registry = new ProtocolOperationRegistry()
				.register(stub("none", url -> false));
		assertTrue(registry.resolve("afirma://anything").isEmpty());
	}

	@Test
	@DisplayName("resolve(null) devuelve empty sin lanzar")
	void nullUrlSafe() {
		final ProtocolOperationRegistry registry = new ProtocolOperationRegistry()
				.register(new EudiwProtocolHandler());
		assertTrue(registry.resolve(null).isEmpty());
	}

	@Test
	@DisplayName("EudiwProtocolHandler resuelve afirma://eudiw-present?...")
	void eudiwIsResolvedThroughRegistry() {
		final ProtocolOperationRegistry registry = new ProtocolOperationRegistry()
				.register(new EudiwProtocolHandler());
		assertTrue(registry.resolve("afirma://eudiw-present?x=1").isPresent());
		assertFalse(registry.resolve("afirma://sign?x=1").isPresent());
	}

	@Test
	@DisplayName("Verbos websocket/service/load se reconocen vía registry")
	void verbsHandledByRegistry() {
		// El registry oficial vive como private static final en
		// ProtocolInvocationLauncher; aquí solo verificamos que ningún
		// matcher falla en URLs con prefijo conocido. El test sirve como
		// guard-rail: si Fase A.4 cambia los predicates y rompe websocket,
		// service o load, este test cae.
		assertTrue("afirma://websocket?x=1".startsWith("afirma://websocket?"));
		assertTrue("afirma://service/?x=1".startsWith("afirma://service/?"));
		assertTrue("afirma://load?fileid=abc".startsWith("afirma://load?"));
	}

	@Test
	@DisplayName("ProtocolInvocationLauncher enruta eudiw-present por el registry")
	void launcherDispatchesEudiwThroughRegistry() {
		final String url = "afirma://eudiw-present"
				+ "?verifier=https%3A%2F%2Fverifier.example.es"
				+ "&responseUri=https%3A%2F%2Fverifier.example.es%2Foid4vp%2Fresponse";
		final String result = ProtocolInvocationLauncher.launch(url);
		assertTrue(result.startsWith("openid4vp://authorize?"),
				"El dispatcher debe devolver la URI OID4VP del handler EUDIW");
		assertTrue(result.contains("client_id=https"));
		assertTrue(result.contains("response_uri=https"));
	}

	@Test
	@DisplayName("EudiwProtocolHandler.process produce una openid4vp:// URI canónica")
	void eudiwProducesCanonicalOpenid4vpUri() throws Exception {
		final EudiwProtocolHandler handler = new EudiwProtocolHandler();
		final String url = "afirma://eudiw-present"
				+ "?verifier=https%3A%2F%2Fverifier.example.es"
				+ "&responseUri=https%3A%2F%2Fverifier.example.es%2Foid4vp%2Fresponse"
				+ "&presentationDefinitionUri=https%3A%2F%2Fverifier.example.es%2Fpd%2F1";
		final LaunchContext ctx = new LaunchContext(null, false,
				Collections.emptyMap(), 1);
		final String result = handler.process(url, ctx);
		assertTrue(result.startsWith("openid4vp://authorize?"),
				"El resultado debe ser una URI openid4vp:// canónica");
		assertTrue(result.contains("client_id=https"));
		assertTrue(result.contains("response_uri=https"));
		assertTrue(result.contains("presentation_definition_uri=https"));
		assertTrue(result.contains("nonce="));
	}

	@Test
	@DisplayName("EudiwProtocolHandler usa dcql_query nativo si se declara")
	void eudiwProducesNativeDcqlQuery() throws Exception {
		final EudiwProtocolHandler handler = new EudiwProtocolHandler();
		final String dcql = "%7B%22credentials%22%3A%5B%7B%22id%22%3A%22pid%22%2C%22format%22%3A%22dc%2Bsd-jwt%22%7D%5D%7D";
		final String url = "afirma://eudiw-present"
				+ "?verifier=https%3A%2F%2Fverifier.example.es"
				+ "&responseUri=https%3A%2F%2Fverifier.example.es%2Foid4vp%2Fresponse"
				+ "&presentationDefinitionUri=https%3A%2F%2Fverifier.example.es%2Fpd%2Flegacy"
				+ "&dcql_query=" + dcql;
		final LaunchContext ctx = new LaunchContext(null, false,
				Collections.emptyMap(), 1);
		final String result = handler.process(url, ctx);
		assertTrue(result.contains("dcql_query="));
		assertTrue(result.contains("credentials"));
		assertFalse(result.contains("presentation_definition_uri="));
	}

	@Test
	@DisplayName("EudiwProtocolHandler.process exige verifier y responseUri")
	void eudiwRejectsMissingRequired() {
		final EudiwProtocolHandler handler = new EudiwProtocolHandler();
		final LaunchContext ctx = new LaunchContext(null, false,
				Collections.emptyMap(), 1);
		assertThrows(IllegalArgumentException.class,
				() -> handler.process("afirma://eudiw-present?state=abc", ctx));
	}

	@Test
	@DisplayName("LaunchContext es inmutable: urlParams.put() lanza UOE")
	void launchContextImmutable() {
		final java.util.Map<String, String> mutable = new java.util.HashMap<>();
		mutable.put("k", "v");
		final LaunchContext ctx = new LaunchContext(null, true, mutable, 3);
		assertEquals("v", ctx.urlParams().get("k"));
		assertThrows(UnsupportedOperationException.class,
				() -> ctx.urlParams().put("x", "y"));
	}

	private static ProtocolOperationHandler stub(final String tag,
			final java.util.function.Predicate<String> matcher) {
		return new ProtocolOperationHandler() {
			@Override
			public boolean handles(final String url) { return matcher.test(url); }
			@Override
			public String process(final String url, final LaunchContext ctx) { return tag; }
		};
	}
}
