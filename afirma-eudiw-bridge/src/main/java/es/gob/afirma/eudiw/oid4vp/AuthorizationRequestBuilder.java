/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.oid4vp;

import java.net.URI;
import java.security.SecureRandom;
import java.util.Base64;

/** Constructor fluido para {@link AuthorizationRequest}; gestiona nonce y state seguros. */
public final class AuthorizationRequestBuilder {

	private static final SecureRandom RNG = new SecureRandom();

	private String clientId;
	private URI responseUri;
	private URI presentationDefinitionUri;
	private String nonce;
	private String state;

	public AuthorizationRequestBuilder clientId(final String value) {
		this.clientId = value;
		return this;
	}

	public AuthorizationRequestBuilder responseUri(final URI value) {
		this.responseUri = value;
		return this;
	}

	public AuthorizationRequestBuilder presentationDefinitionUri(final URI value) {
		this.presentationDefinitionUri = value;
		return this;
	}

	public AuthorizationRequestBuilder withFreshNonce() {
		this.nonce = randomToken(32);
		return this;
	}

	public AuthorizationRequestBuilder withFreshState() {
		this.state = randomToken(16);
		return this;
	}

	public AuthorizationRequestBuilder nonce(final String value) {
		this.nonce = value;
		return this;
	}

	public AuthorizationRequestBuilder state(final String value) {
		this.state = value;
		return this;
	}

	public AuthorizationRequest build() {
		if (this.nonce == null) {
			withFreshNonce();
		}
		return new AuthorizationRequest(
				this.clientId,
				this.responseUri,
				this.presentationDefinitionUri,
				this.nonce,
				this.state);
	}

	private static String randomToken(final int bytes) {
		final byte[] buf = new byte[bytes];
		RNG.nextBytes(buf);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
	}
}
