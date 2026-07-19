/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 */

package es.gob.afirma.signers.jades;

import java.io.IOException;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Logger;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSObjectJSON;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TimeStampToken;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.ErrorCode;
import es.gob.afirma.core.signers.AOSignConstants;
import es.gob.afirma.core.signers.AOSignInfo;
import es.gob.afirma.core.signers.AOSimpleSigner;
import es.gob.afirma.signers.tsp.pkcs7.CMSTimestamper;
import es.gob.afirma.signers.tsp.pkcs7.TsaParams;

/**
 * Firmador JAdES-B-B/JAdES-T (ETSI TS 119 182-1) sobre JWS.
 *
 * <p>JAdES es la transposición a JSON de XAdES y CAdES; usa JWS (RFC 7515)
 * como contenedor base y añade cabeceras protegidas obligatorias para
 * eIDAS:</p>
 *
 * <ul>
 *   <li>{@code x5t#S256} — hash SHA-256 del certificado firmante (RFC 7515 §4.1.8).</li>
 *   <li>{@code sigT} — fecha de firma reclamada (B-B baseline, ETSI EN 319 122-1 §5.2.1).</li>
 *   <li>{@code crit} — declara qué cabeceras nuevas son críticas.</li>
 * </ul>
 *
 * <p>El nivel B-B se emite tanto en compact JWS como en JWS JSON Serialization
 * flattened. El nivel T se activa en JSON Serialization cuando el llamador
 * configura una TSA RFC 3161 mediante {@code tsaURL} o aporta un token ya
 * emitido, que se serializa como cabecera no protegida {@code etsiU}. Los
 * niveles LT/LTA siguen pendientes de integración con {@code afirma-trust-tsl}.</p>
 *
 * <p>La política de TSA por defecto queda fuera de esta clase hasta que exista
 * una decisión CTT cerrada; si se declara {@code tsaURL}, se usa esa TSA
 * explícitamente configurada por el llamador.</p>
 */
public final class AOJadesSigner implements AOSimpleSigner {

	private static final Logger LOGGER = Logger.getLogger(AOJadesSigner.class.getName());
	private static final Set<String> JSON_SERIALIZATION_KEYS =
			Set.of("payload", "protected", "header", "signature", "signatures"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$

	/** Tipo MIME del payload firmado, propagado a la cabecera protegida {@code cty}. */
	public static final String EXTRA_PARAM_CONTENT_TYPE = "contentType";
	/** Si {@code true} (por defecto) la firma resultante es <em>detached</em>: el payload
	 *  no viaja dentro del JWS, solo su digest implícito. */
	public static final String EXTRA_PARAM_DETACHED = "detached";
	/** Si {@code true}, emite JWS JSON Serialization flattened en lugar de compact. */
	public static final String EXTRA_PARAM_JSON_SERIALIZATION = "jsonSerialization";
	/** URL de la TSA RFC 3161. Si se declara, el firmador genera el sello JAdES-T
	 *  sobre la firma JWS reci&eacute;n creada. */
	public static final String EXTRA_PARAM_TSA_URL = "tsaURL";
	/** Token RFC 3161 DER codificado en Base64 para emitir la cabecera JAdES-T {@code etsiU}.
	 *  Requiere {@link #EXTRA_PARAM_JSON_SERIALIZATION} en {@code true}. */
	public static final String EXTRA_PARAM_TIMESTAMP_TOKEN_BASE64 = "timestampTokenBase64";

	@Override
	public byte[] sign(final byte[] data,
			final String algorithm,
			final PrivateKey key,
			final Certificate[] certChain,
			final Properties extraParams) throws AOException, IOException {

		if (data == null || data.length == 0) {
			throw new AOException("No se han proporcionado datos para firmar", new ErrorCode(ErrorCode.ERROR_FUNCTIONAL)); //$NON-NLS-1$
		}
		if (key == null) {
			throw new AOException("No se ha proporcionado clave privada", new ErrorCode(ErrorCode.ERROR_FUNCTIONAL)); //$NON-NLS-1$
		}
		if (certChain == null || certChain.length == 0) {
			throw new AOException("No se ha proporcionado cadena de certificados", new ErrorCode(ErrorCode.ERROR_FUNCTIONAL)); //$NON-NLS-1$
		}

		final Properties params = extraParams != null ? extraParams : new Properties();
		final String detachedParam = params.getProperty(EXTRA_PARAM_DETACHED, "true"); //$NON-NLS-1$
		if (!detachedParam.equals(detachedParam.strip())
				|| detachedParam.chars().anyMatch(Character::isISOControl)) {
			throw new AOException("Parametro detached JAdES no normalizado", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		if (!isBoolean(detachedParam)) {
			throw new AOException("Parametro detached JAdES no es booleano", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		final String jsonSerializationParam = params.getProperty(EXTRA_PARAM_JSON_SERIALIZATION, "false"); //$NON-NLS-1$
		if (!jsonSerializationParam.equals(jsonSerializationParam.strip())
				|| jsonSerializationParam.chars().anyMatch(Character::isISOControl)) {
			throw new AOException("Parametro jsonSerialization JAdES no normalizado", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		if (!isBoolean(jsonSerializationParam)) {
			throw new AOException("Parametro jsonSerialization JAdES no es booleano", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		final boolean detached = !"false".equalsIgnoreCase( //$NON-NLS-1$
				detachedParam);
		final boolean jsonSerialization = Boolean.parseBoolean(jsonSerializationParam);
		final String timestampTokenBase64 = params.getProperty(EXTRA_PARAM_TIMESTAMP_TOKEN_BASE64);
		final String tsaUrl = params.getProperty(EXTRA_PARAM_TSA_URL);
		if (timestampTokenBase64 != null && timestampTokenBase64.isBlank()) {
			throw new AOException("Parametro timestampTokenBase64 JAdES vacio", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		if (tsaUrl != null && tsaUrl.isBlank()) {
			throw new AOException("Parametro tsaURL JAdES vacio", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		if (tsaUrl != null && (!tsaUrl.equals(tsaUrl.strip())
				|| tsaUrl.chars().anyMatch(Character::isISOControl))) {
			throw new AOException("Parametro tsaURL JAdES no normalizado", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		if (hasText(tsaUrl)) {
			validateTsaUrl(tsaUrl);
		}
		if (hasText(timestampTokenBase64) && hasText(tsaUrl)) {
			throw new AOException("JAdES-T no admite timestampTokenBase64 y tsaURL a la vez", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		final boolean timestampRequested = hasText(timestampTokenBase64) || hasText(tsaUrl);
		if (timestampRequested && !jsonSerialization) {
			throw new AOException("JAdES-T requiere JWS JSON Serialization para la cabecera no protegida etsiU", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}

		try {
			final JWSAlgorithm jwsAlg = mapAlgorithm(algorithm, key);
			if (!(certChain[0] instanceof X509Certificate signerCert)) {
				throw new AOException("El certificado firmante JAdES debe ser X.509", //$NON-NLS-1$
						ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
			}
			try {
				signerCert.checkValidity();
			}
			catch (final Exception e) {
				throw new AOException("El certificado firmante JAdES no esta vigente", e, //$NON-NLS-1$
						ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
			}
			assertKeyMatchesCertificate(algorithm, key, signerCert);

			final JWSHeader.Builder headerBuilder = new JWSHeader.Builder(jwsAlg)
					.type(JOSEObjectType.JOSE)
					.x509CertSHA256Thumbprint(thumbprintSha256(signerCert))
					.x509CertChain(buildX5cChain(certChain));

			final List<String> critical = new ArrayList<>();
			final Map<String, Object> jadesClaims = new HashMap<>();
			jadesClaims.put("sigT", JadesTime.nowIso8601()); //$NON-NLS-1$
			critical.add("sigT"); //$NON-NLS-1$

			final String contentType = params.getProperty(EXTRA_PARAM_CONTENT_TYPE);
			if (contentType != null) {
				if (contentType.isBlank()) {
					throw new AOException("Content-Type JAdES vacio", //$NON-NLS-1$
							ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
				}
				if (!contentType.equals(contentType.strip())) {
					throw new AOException("Content-Type JAdES no normalizado", //$NON-NLS-1$
							ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
				}
				if (contentType.chars().anyMatch(Character::isISOControl)) {
					throw new AOException("Content-Type JAdES contiene caracteres de control", //$NON-NLS-1$
							ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
				}
				headerBuilder.contentType(contentType);
			}

			headerBuilder.criticalParams(new HashSet<>(critical));
			for (final Map.Entry<String, Object> entry : jadesClaims.entrySet()) {
				headerBuilder.customParam(entry.getKey(), entry.getValue());
			}

			final JWSHeader header = headerBuilder.build();
			final Payload payload = new Payload(data);

			if (jsonSerialization) {
				final JWSObjectJSON jws = new JWSObjectJSON(payload);
				jws.sign(header, buildSigner(key));
				final Map<String, Object> json = jws.toFlattenedJSONObject();
				final String timestampToken = resolveTimestampToken(params, timestampTokenBase64, json);
				if (timestampToken != null) {
					json.put("header", buildUnprotectedHeader(timestampToken)); //$NON-NLS-1$
				}
				if (detached) {
					json.remove("payload"); //$NON-NLS-1$
				}
				final String level = timestampToken != null ? "JAdES-T" : "JAdES-B-B"; //$NON-NLS-1$ //$NON-NLS-2$
				LOGGER.fine(() -> level + " JSON firmado: alg=" + jwsAlg + ", detached=" + detached); //$NON-NLS-1$ //$NON-NLS-2$
				return JSONObjectUtils.toJSONString(json)
						.getBytes(java.nio.charset.StandardCharsets.UTF_8);
			}

			final JWSObject jws = new JWSObject(header, payload);
			jws.sign(buildSigner(key));

			final String compact = detached
					? jws.serialize(true)  // detached: omitir payload del compact form
					: jws.serialize(false);

			LOGGER.fine(() -> "JAdES-B-B firmado: alg=" + jwsAlg + ", detached=" + detached); //$NON-NLS-1$ //$NON-NLS-2$
			return compact.getBytes(java.nio.charset.StandardCharsets.UTF_8);
		}
		catch (final JOSEException e) {
			throw new AOException("Error firmando JAdES: " + e.getMessage(), e, new ErrorCode(ErrorCode.ERROR_FUNCTIONAL)); //$NON-NLS-1$
		}
	}

	private static String resolveTimestampToken(final Properties params,
			final String timestampTokenBase64,
			final Map<String, Object> json) throws AOException, IOException {
		final Object signature = json.get("signature"); //$NON-NLS-1$
		if (!(signature instanceof String signatureBase64Url) || signatureBase64Url.isBlank()) {
			throw new AOException("No se pudo extraer la firma JWS para sellarla en JAdES-T", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		final byte[] signatureBytes = Base64URL.from(signatureBase64Url).decode();
		if (hasText(timestampTokenBase64)) {
			return normalizeTimestampToken(timestampTokenBase64, signatureBytes);
		}
		if (!hasText(params.getProperty(EXTRA_PARAM_TSA_URL))) {
			return null;
		}

		final TsaParams tsaParams;
		try {
			tsaParams = new TsaParams(params);
		}
		catch (final IllegalArgumentException e) {
			throw new AOException("Configuracion TSA no valida para JAdES-T: " + e.getMessage(), e, //$NON-NLS-1$
					ErrorCode.Request.INVALID_TIMESTAMP_HASH_ALGORITHM);
		}
		final byte[] imprint = digest(signatureBytes, tsaParams.getTsaHashAlgorithm());
		final byte[] token = new CMSTimestamper(tsaParams).getTimeStampToken(
				imprint,
				tsaParams.getTsaHashAlgorithm(),
				Calendar.getInstance());
		return normalizeTimestampToken(Base64.getEncoder().encodeToString(token), signatureBytes);
	}

	private static String normalizeTimestampToken(final String timestampTokenBase64,
			final byte[] signatureBytes) throws AOException {
		if (!timestampTokenBase64.equals(timestampTokenBase64.strip())
				|| timestampTokenBase64.chars().anyMatch(Character::isWhitespace)
				|| timestampTokenBase64.chars().anyMatch(Character::isISOControl)) {
			throw new AOException("El token RFC 3161 de JAdES-T no esta normalizado", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		final String token = timestampTokenBase64;
		final byte[] der;
		try {
			der = Base64.getDecoder().decode(token);
		}
		catch (final IllegalArgumentException e) {
			throw new AOException("El token RFC 3161 de JAdES-T no esta codificado en Base64 valido", e, //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		try {
			final TimeStampToken tst = new TimeStampToken(new CMSSignedData(der));
			validateTimestampTokenSignature(tst);
			final String digestAlgorithm = digestAlgorithmName(
					tst.getTimeStampInfo().getHashAlgorithm().getAlgorithm());
			final byte[] expectedImprint = digest(signatureBytes, digestAlgorithm);
			if (!MessageDigest.isEqual(expectedImprint,
					tst.getTimeStampInfo().getMessageImprintDigest())) {
				throw new AOException("El token JAdES-T no sella la firma JWS", //$NON-NLS-1$
						ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
			}
		}
		catch (final AOException e) {
			throw e;
		}
		catch (final Exception e) {
			throw new AOException("El token JAdES-T no es un RFC 3161 valido", e, //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		return token;
	}

	private static void validateTimestampTokenSignature(final TimeStampToken tst) throws Exception {
		final Collection<X509CertificateHolder> certificates = tst.getCertificates().getMatches(tst.getSID());
		if (certificates.isEmpty()) {
			throw new AOException("El token JAdES-T no incluye certificado TSA", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		final X509CertificateHolder tsaHolder = certificates.iterator().next();
		final X509Certificate tsaCert = new JcaX509CertificateConverter().getCertificate(tsaHolder);
		tsaCert.checkValidity();
		final List<String> eku = tsaCert.getExtendedKeyUsage();
		if (eku == null || !eku.contains(KeyPurposeId.id_kp_timeStamping.getId())) {
			throw new AOException("El certificado TSA de JAdES-T no permite sellado de tiempo", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		tst.validate(new JcaSimpleSignerInfoVerifierBuilder().build(tsaHolder));
	}

	private static String digestAlgorithmName(final ASN1ObjectIdentifier oid) throws AOException {
		if (NISTObjectIdentifiers.id_sha256.equals(oid)) {
			return "SHA-256"; //$NON-NLS-1$
		}
		if (NISTObjectIdentifiers.id_sha384.equals(oid)) {
			return "SHA-384"; //$NON-NLS-1$
		}
		if (NISTObjectIdentifiers.id_sha512.equals(oid)) {
			return "SHA-512"; //$NON-NLS-1$
		}
		throw new AOException("Algoritmo de huella RFC 3161 no soportado: " + oid, //$NON-NLS-1$
				ErrorCode.Request.INVALID_TIMESTAMP_HASH_ALGORITHM);
	}

	private static Map<String, Object> buildUnprotectedHeader(final String timestampTokenBase64) {
		final Map<String, Object> tstToken = Map.of("val", timestampTokenBase64); //$NON-NLS-1$
		final Map<String, Object> tstContainer = Map.of("tstTokens", List.of(tstToken)); //$NON-NLS-1$
		return Map.of("etsiU", List.of(tstContainer)); //$NON-NLS-1$
	}

	private static byte[] digest(final byte[] data, final String algorithm) throws AOException {
		try {
			return MessageDigest.getInstance(algorithm).digest(data);
		}
		catch (final NoSuchAlgorithmException e) {
			throw new AOException("Algoritmo de huella TSA no soportado para JAdES-T: " + algorithm, e, //$NON-NLS-1$
					ErrorCode.Request.INVALID_TIMESTAMP_HASH_ALGORITHM);
		}
	}

	private static boolean hasText(final String value) {
		return value != null && !value.isBlank();
	}

	private static void validateTsaUrl(final String tsaUrl) throws AOException {
		final URI uri;
		try {
			uri = URI.create(tsaUrl);
		}
		catch (final IllegalArgumentException e) {
			throw new AOException("Parametro tsaURL JAdES no es una URI valida", e, //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		final String scheme = uri.getScheme();
		final String host = uri.getHost();
		if (host == null || host.isBlank()
				|| uri.getRawUserInfo() != null
				|| uri.getRawQuery() != null
				|| uri.getRawFragment() != null) {
			throw new AOException("Parametro tsaURL JAdES no es un endpoint TSA valido", //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		if ("https".equalsIgnoreCase(scheme)) { //$NON-NLS-1$
			return;
		}
		if ("http".equalsIgnoreCase(scheme) && isLoopbackHost(host)) { //$NON-NLS-1$
			return;
		}
		throw new AOException("Parametro tsaURL JAdES exige HTTPS fuera de loopback", //$NON-NLS-1$
				ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
	}

	private static boolean isLoopbackHost(final String host) {
		return "localhost".equalsIgnoreCase(host) //$NON-NLS-1$
				|| "127.0.0.1".equals(host) //$NON-NLS-1$
				|| "::1".equals(host) //$NON-NLS-1$
				|| "[::1]".equals(host); //$NON-NLS-1$
	}

	private static boolean isBoolean(final String value) {
		return Boolean.TRUE.toString().equalsIgnoreCase(value)
				|| Boolean.FALSE.toString().equalsIgnoreCase(value);
	}

	private static void assertKeyMatchesCertificate(final String algorithm, final PrivateKey key,
			final X509Certificate cert) throws AOException {
		final String signatureAlgorithm = algorithm == null ? AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA : algorithm;
		try {
			final Signature signature = Signature.getInstance(signatureAlgorithm);
			final byte[] probe = "JAdES".getBytes(java.nio.charset.StandardCharsets.US_ASCII); //$NON-NLS-1$
			signature.initSign(key);
			signature.update(probe);
			final byte[] signed = signature.sign();
			signature.initVerify(cert);
			signature.update(probe);
			if (!signature.verify(signed)) {
				throw new AOException("La clave privada JAdES no corresponde al certificado firmante", //$NON-NLS-1$
						ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
			}
		}
		catch (final AOException e) {
			throw e;
		}
		catch (final Exception e) {
			throw new AOException("No se pudo comprobar la clave privada JAdES contra el certificado", e, //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
	}

	private static JWSAlgorithm mapAlgorithm(final String algorithm, final PrivateKey key) throws AOException {
		final String alg = algorithm == null ? AOSignConstants.SIGN_ALGORITHM_SHA256WITHRSA : algorithm;
		final String upper = alg.toUpperCase();

		final boolean isRsaAlg = upper.endsWith("WITHRSA"); //$NON-NLS-1$
		final boolean isEcAlg = upper.endsWith("WITHECDSA"); //$NON-NLS-1$

		if (isRsaAlg && !(key instanceof RSAPrivateKey)) {
			throw new AOException("Algoritmo " + alg + " requiere clave RSA", //$NON-NLS-1$ //$NON-NLS-2$
					new ErrorCode(ErrorCode.ERROR_FUNCTIONAL));
		}
		if (isEcAlg && !(key instanceof ECPrivateKey)) {
			throw new AOException("Algoritmo " + alg + " requiere clave EC", //$NON-NLS-1$ //$NON-NLS-2$
					new ErrorCode(ErrorCode.ERROR_FUNCTIONAL));
		}

		switch (upper) {
			case "SHA256WITHRSA":   return JWSAlgorithm.RS256; //$NON-NLS-1$
			case "SHA384WITHRSA":   return JWSAlgorithm.RS384; //$NON-NLS-1$
			case "SHA512WITHRSA":   return JWSAlgorithm.RS512; //$NON-NLS-1$
			case "SHA256WITHECDSA": return JWSAlgorithm.ES256; //$NON-NLS-1$
			case "SHA384WITHECDSA": return JWSAlgorithm.ES384; //$NON-NLS-1$
			case "SHA512WITHECDSA": return JWSAlgorithm.ES512; //$NON-NLS-1$
			default:
				throw new AOException("Algoritmo no soportado para JAdES: " + alg, //$NON-NLS-1$
						new ErrorCode(ErrorCode.ERROR_FUNCTIONAL));
		}
	}

	private static JWSSigner buildSigner(final PrivateKey key) throws JOSEException, AOException {
		if (key instanceof RSAPrivateKey rsa) {
			return new RSASSASigner(rsa);
		}
		if (key instanceof ECPrivateKey ec) {
			return new ECDSASigner(ec);
		}
		throw new AOException("Tipo de clave no soportado: " + key.getClass(), new ErrorCode(ErrorCode.ERROR_FUNCTIONAL)); //$NON-NLS-1$
	}

	private static Base64URL thumbprintSha256(final X509Certificate cert) throws AOException {
		try {
			final java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256"); //$NON-NLS-1$
			return Base64URL.encode(md.digest(cert.getEncoded()));
		}
		catch (final Exception e) {
			throw new AOException("No se pudo calcular x5t#S256", e, new ErrorCode(ErrorCode.ERROR_FUNCTIONAL)); //$NON-NLS-1$
		}
	}

	private static List<com.nimbusds.jose.util.Base64> buildX5cChain(final Certificate[] certChain) throws AOException {
		final List<com.nimbusds.jose.util.Base64> x5c = new ArrayList<>(certChain.length);
		try {
			X509Certificate previousCert = null;
			for (final Certificate c : certChain) {
				if (!(c instanceof X509Certificate)) {
					throw new AOException("La cadena JAdES x5c debe contener solo certificados X.509", //$NON-NLS-1$
							ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
				}
				final X509Certificate cert = (X509Certificate) c;
				cert.checkValidity();
				if (previousCert != null) {
					if (!previousCert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
						throw new AOException("La cadena JAdES x5c no esta enlazada", //$NON-NLS-1$
								ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
					}
					previousCert.verify(cert.getPublicKey());
				}
				x5c.add(com.nimbusds.jose.util.Base64.encode(c.getEncoded()));
				previousCert = cert;
			}
		}
		catch (final AOException e) {
			throw e;
		}
		catch (final java.security.cert.CertificateExpiredException
				| java.security.cert.CertificateNotYetValidException e) {
			throw new AOException("La cadena JAdES x5c contiene certificados no vigentes", e, //$NON-NLS-1$
					ErrorCode.Functional.SIGNING_MALFORMED_SIGNATURE);
		}
		catch (final java.security.GeneralSecurityException e) {
			throw new AOException("Error codificando cadena de certificados", e, new ErrorCode(ErrorCode.ERROR_FUNCTIONAL)); //$NON-NLS-1$
		}
		return x5c;
	}

	/** {@link AOSignInfo} mínimo para que el detector de formato reconozca un compact JWS. */
	public AOSignInfo getSignInfo(final byte[] signData) {
		final AOSignInfo info = new AOSignInfo("JAdES"); //$NON-NLS-1$
		info.setVariant("B-B"); //$NON-NLS-1$
		return info;
	}

	/** Heurística rápida: tres segmentos base64url separados por puntos = compact JWS. */
	public boolean isSign(final byte[] data) {
		if (data == null || data.length < 5) {
			return false;
		}
		final String s = new String(data, java.nio.charset.StandardCharsets.UTF_8);
		if (s.startsWith("{")) { //$NON-NLS-1$
			try {
				final Map<String, Object> json = JSONObjectUtils.parse(s);
				return isValidJsonSerialization(json);
			}
			catch (final java.text.ParseException e) {
				return false;
			}
		}
		int dots = 0;
		for (final byte b : data) {
			if (b == '.') {
				dots++;
			}
			else if (b == '\n' || b == '\r' || b == ' ') {
				return false;
			}
		}
		if (dots != 2) {
			return false;
		}
		final int firstDot = s.indexOf('.');
		final int lastDot = s.lastIndexOf('.');
		if (firstDot <= 0 || lastDot <= firstDot || lastDot == s.length() - 1) {
			return false;
		}
		final String payload = s.substring(firstDot + 1, lastDot);
		if (!isBase64Url(s.substring(0, firstDot))
				|| !payload.isEmpty() && !isBase64Url(payload)
				|| !isBase64Url(s.substring(lastDot + 1))) {
			return false;
		}
		try {
			final JWSHeader header = JWSHeader.parse(Base64URL.from(s.substring(0, firstDot)));
			if (!isJadesHeader(header)) {
				return false;
			}
			return Base64URL.from(s.substring(lastDot + 1)).decode().length > 0;
		}
		catch (final java.text.ParseException | IllegalArgumentException e) {
			return false;
		}
	}

	private static boolean isValidJsonSerialization(final Map<String, Object> json) {
		if (!JSON_SERIALIZATION_KEYS.containsAll(json.keySet())) {
			return false;
		}
		final Object payload = json.get("payload"); //$NON-NLS-1$
		if (payload != null && (!(payload instanceof String payloadText)
				|| payloadText.isBlank() || !isBase64Url(payloadText))) {
			return false;
		}
		if (json.get("signatures") instanceof List<?> signatures) { //$NON-NLS-1$
			for (final Object signature : signatures) {
				if (signature instanceof Map<?, ?> signatureJson
						&& isValidJsonSignature(signatureJson)) {
					return true;
				}
			}
			return false;
		}
		return isValidJsonSignature(json);
	}

	private static boolean isValidJsonSignature(final Map<?, ?> json) {
		if (!(json.get("protected") instanceof String protectedHeader) || protectedHeader.isBlank() //$NON-NLS-1$
				|| !(json.get("signature") instanceof String signature) || signature.isBlank()) { //$NON-NLS-1$
			return false;
		}
		if (json.containsKey("header") && !(json.get("header") instanceof Map<?, ?>)) { //$NON-NLS-1$ //$NON-NLS-2$
			return false;
		}
		if (!isBase64Url(protectedHeader) || !isBase64Url(signature)) {
			return false;
		}
		try {
			final JWSHeader header = JWSHeader.parse(Base64URL.from(protectedHeader));
			if (!isJadesHeader(header)) {
				return false;
			}
			if (json.get("header") instanceof Map<?, ?> unprotectedHeader) { //$NON-NLS-1$
				if (!java.util.Collections.disjoint(unprotectedHeader.keySet(), header.toJSONObject().keySet())
						|| !isValidUnprotectedHeader(unprotectedHeader)) {
					return false;
				}
			}
			return Base64URL.from(signature).decode().length > 0;
		}
		catch (final Exception e) {
			return false;
		}
	}

	private static boolean isValidUnprotectedHeader(final Map<?, ?> header) {
		if (header.size() != 1 || !header.containsKey("etsiU")) { //$NON-NLS-1$
			return false;
		}
		if (!(header.get("etsiU") instanceof List<?> etsiU) || etsiU.isEmpty()) { //$NON-NLS-1$
			return false;
		}
		for (final Object component : etsiU) {
			if (!(component instanceof Map<?, ?> componentJson)) {
				return false;
			}
			if (componentJson.size() != 1 || !componentJson.containsKey("tstTokens")) { //$NON-NLS-1$
				return false;
			}
			if (!isValidTimestampTokens(componentJson.get("tstTokens"))) { //$NON-NLS-1$
				return false;
			}
		}
		return true;
	}

	private static boolean isValidTimestampTokens(final Object value) {
		if (!(value instanceof List<?> tokens) || tokens.isEmpty()) {
			return false;
		}
		for (final Object token : tokens) {
			if (!(token instanceof Map<?, ?> tokenJson)
					|| !(tokenJson.get("val") instanceof String tokenBase64) || tokenBase64.isBlank()) { //$NON-NLS-1$
				return false;
			}
			if (tokenJson.size() != 1) {
				return false;
			}
			if (!tokenBase64.equals(tokenBase64.strip())
					|| tokenBase64.chars().anyMatch(Character::isWhitespace)
					|| tokenBase64.chars().anyMatch(Character::isISOControl)) {
				return false;
			}
			try {
				new TimeStampToken(new CMSSignedData(java.util.Base64.getDecoder().decode(tokenBase64)));
			}
			catch (final Exception e) {
				return false;
			}
		}
		return true;
	}

	private static boolean isJadesHeader(final JWSHeader header) {
		return (JWSAlgorithm.Family.RSA.contains(header.getAlgorithm())
				|| JWSAlgorithm.Family.EC.contains(header.getAlgorithm()))
				&& header.getJWKURL() == null
				&& header.getX509CertURL() == null
				&& header.getX509CertSHA256Thumbprint() != null
				&& header.getX509CertChain() != null && !header.getX509CertChain().isEmpty()
				&& thumbprintMatchesChain(header)
				&& header.getCustomParam("sigT") instanceof String sigT && !sigT.isBlank() //$NON-NLS-1$
				&& sigT.equals(sigT.strip())
				&& isJadesSigningTime(sigT)
				&& header.getCriticalParams() != null
				&& header.getCriticalParams().size() == 1
				&& header.getCriticalParams().contains("sigT"); //$NON-NLS-1$
	}

	private static boolean thumbprintMatchesChain(final JWSHeader header) {
		try {
			X509Certificate cert = null;
			X509Certificate previousCert = null;
			final CertificateFactory cf = CertificateFactory.getInstance("X.509"); //$NON-NLS-1$
			for (final com.nimbusds.jose.util.Base64 encoded : header.getX509CertChain()) {
				final X509Certificate current = (X509Certificate) cf.generateCertificate(
						new java.io.ByteArrayInputStream(encoded.decode()));
				current.checkValidity();
				if (previousCert != null) {
					if (!previousCert.getIssuerX500Principal().equals(current.getSubjectX500Principal())) {
						return false;
					}
					previousCert.verify(current.getPublicKey());
				}
				if (cert == null) {
					cert = current;
				}
				previousCert = current;
			}
			if (cert == null) {
				return false;
			}
			return header.getX509CertSHA256Thumbprint().equals(Base64URL.encode(
					MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()))); //$NON-NLS-1$
		}
		catch (final Exception e) {
			return false;
		}
	}

	private static boolean isJadesSigningTime(final String sigT) {
		if (!sigT.endsWith("Z") || sigT.contains(".")) { //$NON-NLS-1$ //$NON-NLS-2$
			return false;
		}
		try {
			Instant.parse(sigT);
			return true;
		}
		catch (final RuntimeException e) {
			return false;
		}
	}

	private static boolean isBase64Url(final String value) {
		for (int i = 0; i < value.length(); i++) {
			final char c = value.charAt(i);
			if (!(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z')
					&& !(c >= '0' && c <= '9') && c != '-' && c != '_') {
				return false;
			}
		}
		return true;
	}

	/** Helper visible solo dentro del paquete (incluido el test): decodifica
	 *  el header protegido sin verificar firma. NO es API estable. */
	static String decodeProtectedHeader(final byte[] jws) {
		final String s = new String(jws, java.nio.charset.StandardCharsets.UTF_8);
		final int firstDot = s.indexOf('.');
		if (firstDot <= 0) {
			throw new IllegalArgumentException("No es un compact JWS"); //$NON-NLS-1$
		}
		return new String(Base64.getUrlDecoder().decode(s.substring(0, firstDot)),
				java.nio.charset.StandardCharsets.UTF_8);
	}
}
