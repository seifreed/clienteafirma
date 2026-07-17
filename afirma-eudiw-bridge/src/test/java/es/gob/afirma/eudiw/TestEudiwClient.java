/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.net.URI;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Pruebas del cliente HTTP EUDIW en sus validaciones locales. */
final class TestEudiwClient {

	@Test
	@DisplayName("postFormUrlencoded valida endpoint y body antes de enviar")
	void rejectsUnsafeEndpointAndBody() {
		final EudiwClient client = new EudiwClient();

		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("http://wallet.example/oid4vp"), "request=x")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://user@wallet.example/oid4vp"), "request=x")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp#frag"), "request=x")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp?request=old"), "request=x")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), " ")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), " request=x")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), "request=x\nstate=y")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), "request")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), "=x")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), "request=")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), "request=%20")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), "request=%0A")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), "request=x&request=y")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), "request=x&re%71uest=y")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), "re+quest=x")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), "re%0Aquest=x")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class,
				() -> client.postFormUrlencoded(URI.create("https://wallet.example/oid4vp"), "re%ZZquest=x")); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
