/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw.sdjwt;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import com.nimbusds.jwt.SignedJWT;

/**
 * Credencial Verificable SD-JWT (Selective Disclosure JWT,
 * IETF draft-ietf-oauth-selective-disclosure-jwt-16, mayo 2026).
 *
 * <p>Un SD-JWT VC se compone de:</p>
 *
 * <ol>
 *   <li>Un <strong>Issuer-signed JWT</strong> con claims tradicionales y un array
 *       {@code _sd} con los <em>digest hashes</em> de los claims selectivos.</li>
 *   <li>Cero o más <strong>Disclosures</strong> — cada una un JSON
 *       {@code [salt, claim_name, claim_value]} codificado en base64url.</li>
 *   <li>Opcionalmente un <strong>Key Binding JWT</strong> al final, firmado por la wallet.</li>
 * </ol>
 *
 * <p>Los componentes se concatenan con tildes ({@code ~}). Esta clase parsea
 * el formato sin verificar firmas — la verificación criptográfica se delega
 * en el Verifier que combina esto con la TSL del issuer.</p>
 *
 * <p>La verificación criptográfica completa vive en {@link SdJwtVerifier}.</p>
 */
public final class SdJwtVerifiableCredential {

	private static final String SEPARATOR = "~"; //$NON-NLS-1$

	private final SignedJWT issuerSignedJwt;
	private final List<String> disclosures;
	private final Optional<SignedJWT> keyBindingJwt;

	private SdJwtVerifiableCredential(final SignedJWT issuerSignedJwt,
			final List<String> disclosures, final Optional<SignedJWT> keyBindingJwt) {
		this.issuerSignedJwt = Objects.requireNonNull(issuerSignedJwt, "issuerSignedJwt");
		this.disclosures = List.copyOf(Objects.requireNonNull(disclosures, "disclosures"));
		this.keyBindingJwt = Objects.requireNonNull(keyBindingJwt, "keyBindingJwt");
	}

	/** Issuer-signed JWT: la parte que el emisor firma (RSA/ECDSA). */
	public SignedJWT issuerSignedJwt() {
		return this.issuerSignedJwt;
	}

	/** Disclosures decodificadas como cadenas JSON. */
	public List<String> decodedDisclosures() {
		final List<String> out = new ArrayList<>(this.disclosures.size());
		for (final String b64 : this.disclosures) {
			out.add(new String(Base64.getUrlDecoder().decode(b64),
					java.nio.charset.StandardCharsets.UTF_8));
		}
		return out;
	}

	/** Disclosures en su forma base64url original, usada para recomputar _sd. */
	public List<String> disclosures() {
		return this.disclosures;
	}

	/** Key Binding JWT (firmado por la wallet); presente solo en presentaciones. */
	public Optional<SignedJWT> keyBindingJwt() {
		return this.keyBindingJwt;
	}

	/**
	 * Parsea un SD-JWT VC en formato compact (separadores {@code ~}).
	 * No verifica firmas; ver {@link SdJwtVerifier} para hacerlo aparte.
	 */
	public static SdJwtVerifiableCredential parse(final String compact) throws ParseException {
		Objects.requireNonNull(compact, "compact");
		final String[] parts = compact.split(SEPARATOR);
		if (parts.length < 1 || parts[0].isBlank()) {
			throw new ParseException("Formato SD-JWT inválido: vacío o sin issuer JWT", 0); //$NON-NLS-1$
		}

		final SignedJWT issuerJwt = SignedJWT.parse(parts[0]);
		final boolean trailingSeparator = compact.endsWith(SEPARATOR);

		final List<String> disclosures = new ArrayList<>();
		Optional<SignedJWT> keyBinding = Optional.empty();

		for (int i = 1; i < parts.length; i++) {
			final String segment = parts[i];
			if (segment.isEmpty()) {
				continue;
			}
			// El último segmento, si NO termina en '~', es el Key Binding JWT;
			// si la cadena termina en '~', no hay Key Binding y todos los
			// segmentos son disclosures.
			final boolean isLast = i == parts.length - 1;
			if (isLast && !trailingSeparator && segment.indexOf('.') > 0) {
				keyBinding = Optional.of(SignedJWT.parse(segment));
			}
			else {
				disclosures.add(segment);
			}
		}

		return new SdJwtVerifiableCredential(issuerJwt, disclosures, keyBinding);
	}
}
