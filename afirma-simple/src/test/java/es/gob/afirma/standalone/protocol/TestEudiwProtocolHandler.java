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
		assertTrue(EudiwProtocolHandler.handles(URI.create("afirma://eudiw-present/?x=1")));
		assertTrue(new EudiwProtocolHandler().handles("AFIRMA://EUDIW-PRESENT?x=1"));
		assertFalse(EudiwProtocolHandler.handles(URI.create("afirma://sign?x=1")));
		assertFalse(EudiwProtocolHandler.handles(URI.create("afirma://eudiw-present/path?x=1")));
		assertFalse(new EudiwProtocolHandler().handles("AFIRMA://EUDIW-PRESENT/path?x=1"));
		assertFalse(EudiwProtocolHandler.handles(URI.create("https://eudiw-present?x=1")));
		assertFalse(EudiwProtocolHandler.handles((URI) null));
	}

	@Test
	@DisplayName("parseParameters decodifica los percent-encoded")
	void parsesQuery() {
		final URI uri = URI.create("afirma://eudiw-present"
				+ "?verifier=https%3A%2F%2Fverifier.example.es"
				+ "&responseUri=https%3A%2F%2Fverifier.example.es%2Foid4vp%2Fresponse"
				+ "&state=abc"
				+ "&format=dc+sd-jwt");
		final Map<String, String> p = EudiwProtocolHandler.parseParameters(uri);
		assertEquals("https://verifier.example.es", p.get("verifier"));
		assertEquals("https://verifier.example.es/oid4vp/response", p.get("responseUri"));
		assertEquals("abc", p.get("state"));
		assertEquals("dc+sd-jwt", p.get("format"));
	}

	@Test
	@DisplayName("parseParameters lanza IAE si la URI no es eudiw-present")
	void rejectsWrongVerb() {
		assertThrows(IllegalArgumentException.class,
				() -> EudiwProtocolHandler.parseParameters(URI.create("afirma://sign?x=1")));
		assertThrows(IllegalArgumentException.class,
				() -> EudiwProtocolHandler.parseParameters(URI.create("afirma://eudiw-present/path?x=1")));
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

	@Test
	@DisplayName("parseParameters rechaza claves vacías")
	void rejectsBlankKeys() {
		assertThrows(IllegalArgumentException.class,
				() -> EudiwProtocolHandler.parseParameters(URI.create("afirma://eudiw-present?=x")));
		assertThrows(IllegalArgumentException.class,
				() -> EudiwProtocolHandler.parseParameters(URI.create("afirma://eudiw-present?%20=x")));
		assertThrows(IllegalArgumentException.class,
				() -> EudiwProtocolHandler.parseParameters(URI.create("afirma://eudiw-present?%20state=x")));
		assertThrows(IllegalArgumentException.class,
				() -> EudiwProtocolHandler.parseParameters(URI.create("afirma://eudiw-present?sta%0Ate=x")));
		assertThrows(IllegalArgumentException.class,
				() -> EudiwProtocolHandler.parseParameters(URI.create("afirma://eudiw-present?state")));
		assertThrows(IllegalArgumentException.class,
				() -> EudiwProtocolHandler.parseParameters(URI.create("afirma://eudiw-present?state=a%0Ab")));
		assertThrows(IllegalArgumentException.class,
				() -> EudiwProtocolHandler.parseParameters(URI.create("afirma://eudiw-present?state=x#frag")));
	}

	@Test
	@DisplayName("process rechaza valores con controles en parámetros opcionales")
	void rejectsControlValues() {
		final String url = "afirma://eudiw-present" //$NON-NLS-1$
				+ "?verifier=https%3A%2F%2Fverifier.example.es" //$NON-NLS-1$
				+ "&responseUri=https%3A%2F%2Fverifier.example.es%2Foid4vp%2Fresponse" //$NON-NLS-1$
				+ "&dcqlQuery=%7B%22credentials%22%3A%5B%7B%22id%22%3A%22pid%22%2C%22format%22%3A%22dc%2Bsd-jwt%22%7D%5D%7D" //$NON-NLS-1$
				+ "&walletUri=eudiw%3A%2F%2Fpresent%0A"; //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new EudiwProtocolHandler().process(url, new LaunchContext(null, false, Map.of(), 0)));
	}
}
