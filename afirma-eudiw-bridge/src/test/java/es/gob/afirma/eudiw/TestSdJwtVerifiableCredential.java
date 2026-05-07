/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.text.ParseException;
import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;

import es.gob.afirma.eudiw.sdjwt.SdJwtVerifiableCredential;

final class TestSdJwtVerifiableCredential {

	private static final String DISCLOSURE_JSON =
			"[\"r\u0301andom-salt\",\"family_name\",\"García\"]"; //$NON-NLS-1$

	@Test
	@DisplayName("Parser extrae issuer JWT + 1 disclosure + sin Key Binding")
	void parsesIssuerAndDisclosures() throws Exception {
		final String issuerJwt = makeUnsignedJwt();
		final String disclosure = Base64.getUrlEncoder().withoutPadding()
				.encodeToString(DISCLOSURE_JSON.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		// trailing '~' = sin Key Binding
		final String compact = issuerJwt + "~" + disclosure + "~";

		final SdJwtVerifiableCredential vc = SdJwtVerifiableCredential.parse(compact);
		assertEquals(JWSAlgorithm.HS256, vc.issuerSignedJwt().getHeader().getAlgorithm());
		assertEquals(1, vc.decodedDisclosures().size());
		assertTrue(vc.decodedDisclosures().get(0).contains("García"));
		assertFalse(vc.keyBindingJwt().isPresent(), "Sin Key Binding cuando termina en '~'");
	}

	@Test
	@DisplayName("Parser detecta Key Binding JWT al final cuando NO hay tilde de cierre")
	void parsesKeyBinding() throws Exception {
		final String issuerJwt = makeUnsignedJwt();
		final String kb = makeUnsignedJwt(); // misma forma para el test
		final String compact = issuerJwt + "~" + kb;

		final SdJwtVerifiableCredential vc = SdJwtVerifiableCredential.parse(compact);
		assertTrue(vc.keyBindingJwt().isPresent());
		assertEquals(0, vc.decodedDisclosures().size());
	}

	@Test
	@DisplayName("Parser rechaza entradas vacías o sin issuer JWT")
	void rejectsEmpty() {
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse(""));
		assertThrows(ParseException.class, () -> SdJwtVerifiableCredential.parse("~"));
		assertThrows(NullPointerException.class, () -> SdJwtVerifiableCredential.parse(null));
	}

	private static String makeUnsignedJwt() throws Exception {
		final byte[] secret = new byte[32];
		java.util.Arrays.fill(secret, (byte) 0x42);
		final JWSObject jws = new JWSObject(
				new JWSHeader.Builder(JWSAlgorithm.HS256).build(),
				new Payload("{\"sub\":\"test\"}"));
		jws.sign(new MACSigner(secret));
		return jws.serialize();
	}
}
