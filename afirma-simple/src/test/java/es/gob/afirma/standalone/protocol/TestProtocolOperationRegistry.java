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
