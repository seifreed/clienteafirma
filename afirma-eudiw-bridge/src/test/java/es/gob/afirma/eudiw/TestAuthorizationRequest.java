/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import es.gob.afirma.eudiw.oid4vp.AuthorizationRequest;
import es.gob.afirma.eudiw.oid4vp.AuthorizationRequestBuilder;

final class TestAuthorizationRequest {

	@Test
	@DisplayName("Builder produce URI openid4vp:// con todos los parámetros obligatorios")
	void buildsCanonicalUri() {
		final AuthorizationRequest req = new AuthorizationRequestBuilder()
				.clientId("https://verifier.example.es")
				.responseUri(URI.create("https://verifier.example.es/oid4vp/response"))
				.presentationDefinitionUri(URI.create("https://verifier.example.es/oid4vp/pd/1"))
				.withFreshNonce()
				.withFreshState()
				.build();

		final URI uri = req.toUri();
		assertEquals("openid4vp", uri.getScheme());
		final String q = uri.getRawQuery();
		assertNotNull(q);
		assertTrue(q.contains("client_id=https"), "client_id presente");
		assertTrue(q.contains("response_type=vp_token"), "response_type fijo");
		assertTrue(q.contains("response_mode=direct_post"), "response_mode fijo");
		assertTrue(q.contains("response_uri=https"), "response_uri presente");
		assertTrue(q.contains("presentation_definition_uri="), "PD URI presente");
		assertTrue(q.contains("nonce="), "nonce presente");
		assertTrue(q.contains("state="), "state presente");
	}

	@Test
	@DisplayName("Cada build genera un nonce distinto (high-entropy)")
	void freshNoncesUnique() {
		final AuthorizationRequestBuilder base = new AuthorizationRequestBuilder()
				.clientId("c").responseUri(URI.create("https://x/r"));
		final String n1 = base.withFreshNonce().build().nonce();
		final String n2 = base.withFreshNonce().build().nonce();
		assertNotEquals(n1, n2, "Dos requests consecutivas deben usar nonces distintos");
		assertTrue(n1.length() >= 32, "Nonce debería tener al menos 32 chars base64url");
	}

	@Test
	@DisplayName("Faltar clientId/responseUri lanza NPE en construcción")
	void rejectsMissingFields() {
		assertThrows(NullPointerException.class,
				() -> new AuthorizationRequestBuilder().withFreshNonce().build());
	}

	@Test
	@DisplayName("EudiwClient rechaza entradas locales antes de enviar")
	void clientRejectsInvalidLocalInputs() {
		assertThrows(NullPointerException.class, () -> new EudiwClient(null));
		final EudiwClient client = new EudiwClient();
		assertThrows(NullPointerException.class, () -> client.postFormUrlencoded(null, "a=b"));
		assertThrows(NullPointerException.class, () -> client.postFormUrlencoded(URI.create("https://wallet.example"), null));
		assertThrows(IOException.class, () -> client.postFormUrlencoded(URI.create("http://wallet.example"), "a=b"));
	}
}
