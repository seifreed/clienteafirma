/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.standalone.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

final class TestEudiwProtocolHandler {

	@Test
	@DisplayName("handles() reconoce solo afirma://eudiw-present")
	void detectsScheme() {
		assertTrue(EudiwProtocolHandler.handles(URI.create("afirma://eudiw-present?x=1")));
		assertFalse(EudiwProtocolHandler.handles(URI.create("afirma://sign?x=1")));
		assertFalse(EudiwProtocolHandler.handles(URI.create("https://eudiw-present?x=1")));
		assertFalse(EudiwProtocolHandler.handles(null));
	}

	@Test
	@DisplayName("parseParameters decodifica los percent-encoded")
	void parsesQuery() {
		final URI uri = URI.create("afirma://eudiw-present"
				+ "?verifier=https%3A%2F%2Fverifier.example.es"
				+ "&responseUri=https%3A%2F%2Fverifier.example.es%2Foid4vp%2Fresponse"
				+ "&state=abc");
		final Map<String, String> p = EudiwProtocolHandler.parseParameters(uri);
		assertEquals("https://verifier.example.es", p.get("verifier"));
		assertEquals("https://verifier.example.es/oid4vp/response", p.get("responseUri"));
		assertEquals("abc", p.get("state"));
	}

	@Test
	@DisplayName("parseParameters lanza IAE si la URI no es eudiw-present")
	void rejectsWrongVerb() {
		assertThrows(IllegalArgumentException.class,
				() -> EudiwProtocolHandler.parseParameters(URI.create("afirma://sign?x=1")));
	}

	@Test
	@DisplayName("Sin query devuelve mapa vacío")
	void emptyQuery() {
		assertTrue(EudiwProtocolHandler.parseParameters(URI.create("afirma://eudiw-present")).isEmpty());
	}

	@Test
	@DisplayName("Claves duplicadas se rechazan (system boundary, prevención nonce-confusion)")
	void rejectsDuplicateKeys() {
		final URI uri = URI.create("afirma://eudiw-present?nonce=abc&state=s&nonce=zzz");
		assertThrows(IllegalArgumentException.class,
				() -> EudiwProtocolHandler.parseParameters(uri));
	}
}
