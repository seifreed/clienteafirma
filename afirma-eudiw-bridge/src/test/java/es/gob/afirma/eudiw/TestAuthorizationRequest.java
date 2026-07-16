/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.eudiw;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import es.gob.afirma.eudiw.oid4vp.AuthorizationRequest;
import es.gob.afirma.eudiw.oid4vp.AuthorizationRequestBuilder;
import es.gob.afirma.eudiw.oid4vp.JarmAuthorizationResponse;

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
	@DisplayName("Builder serializa dcql_query nativo y valida JSON")
	void buildsDcqlQueryUri() {
		final String dcql = "{\"credentials\":[{\"id\":\"pid\",\"format\":\"dc+sd-jwt\"}]}";
		final AuthorizationRequest req = new AuthorizationRequestBuilder()
				.clientId("https://verifier.example.es")
				.responseUri(URI.create("https://verifier.example.es/oid4vp/response"))
				.presentationDefinitionUri(URI.create("https://verifier.example.es/oid4vp/pd/legacy"))
				.dcqlQuery(dcql)
				.nonce("nonce")
				.build();

		final String q = req.toUri().getRawQuery();
		assertNotNull(q);
		assertTrue(q.contains("dcql_query="), "DCQL presente");
		assertTrue(q.contains("credentials"), "JSON DCQL codificado");
		assertFalse(q.contains("presentation_definition_uri="),
				"DCQL sustituye al presentation_definition_uri legacy");
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequestBuilder().dcqlQuery("not-json"));
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequestBuilder().dcqlQuery(" ")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequestBuilder().dcqlQuery(" " + dcql)); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequestBuilder().dcqlQuery("{}")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequestBuilder().dcqlQuery(
						"{\"credentials\":[\"pid\"]}")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequestBuilder().dcqlQuery(
						"{\"credentials\":[{\"id\":\"pid\"}]}")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequestBuilder().dcqlQuery(
						"{\"credentials\":[{\"id\":\" \",\"format\":\"dc+sd-jwt\"}]}")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequestBuilder().dcqlQuery(
						"{\"credentials\":[{\"id\":\" pid\",\"format\":\"dc+sd-jwt\"}]}")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequestBuilder().dcqlQuery(
						"{\"credentials\":[{\"id\":\"pid\",\"format\":\"dc+sd-jwt\"},{\"id\":\"pid\",\"format\":\"mso_mdoc\"}]}")); //$NON-NLS-1$
	}

	@Test
	@DisplayName("Builder genera Request Object JAR firmado")
	void buildsSignedRequestObject() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final KeyPair kp = kpg.generateKeyPair();
		final AuthorizationRequest req = new AuthorizationRequestBuilder()
				.clientId("https://verifier.example.es")
				.responseUri(URI.create("https://verifier.example.es/oid4vp/response"))
				.dcqlQuery("{\"credentials\":[{\"id\":\"pid\",\"format\":\"dc+sd-jwt\"}]}")
				.nonce("nonce")
				.state("state")
				.build();

		final SignedJWT jar = req.toSignedRequestObject(
				new RSASSASigner(kp.getPrivate()), JWSAlgorithm.RS256,
				"kid-1", "openid4vp://wallet"); //$NON-NLS-1$ //$NON-NLS-2$

		assertTrue(jar.verify(new RSASSAVerifier(
				(java.security.interfaces.RSAPublicKey) kp.getPublic())));
		assertEquals(new JOSEObjectType("oauth-authz-req+jwt"), jar.getHeader().getType()); //$NON-NLS-1$
		assertEquals("kid-1", jar.getHeader().getKeyID()); //$NON-NLS-1$
		assertEquals("https://verifier.example.es", jar.getJWTClaimsSet().getIssuer()); //$NON-NLS-1$
		assertNotNull(jar.getJWTClaimsSet().getIssueTime());
		assertTrue(jar.getJWTClaimsSet().getExpirationTime().after(new Date()));
		assertEquals("https://verifier.example.es", //$NON-NLS-1$
				jar.getJWTClaimsSet().getStringClaim("client_id")); //$NON-NLS-1$
		assertEquals("vp_token", jar.getJWTClaimsSet().getStringClaim("response_type")); //$NON-NLS-1$ //$NON-NLS-2$
		assertEquals("nonce", jar.getJWTClaimsSet().getStringClaim("nonce")); //$NON-NLS-1$ //$NON-NLS-2$
		assertTrue(jar.getJWTClaimsSet().getAudience().contains("openid4vp://wallet")); //$NON-NLS-1$
		assertTrue(req.toUriWithRequestObject(jar).getRawQuery().contains("request=")); //$NON-NLS-1$

		final SignedJWT unsignedJar = new SignedJWT(
				jarHeader(),
				jar.getJWTClaimsSet());
		assertThrows(IllegalArgumentException.class, () -> req.toUriWithRequestObject(unsignedJar));
		final SignedJWT untypedJar = new SignedJWT(
				new com.nimbusds.jose.JWSHeader.Builder(JWSAlgorithm.RS256).build(),
				jar.getJWTClaimsSet());
		untypedJar.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(IllegalArgumentException.class, () -> req.toUriWithRequestObject(untypedJar));
		final SignedJWT mismatchedJar = new SignedJWT(
				jarHeader(),
				new JWTClaimsSet.Builder(jar.getJWTClaimsSet())
						.claim("client_id", "https://otro-verifier.example.es") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		mismatchedJar.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(IllegalArgumentException.class, () -> req.toUriWithRequestObject(mismatchedJar));
		final SignedJWT mismatchedIssuerJar = new SignedJWT(
				jarHeader(),
				new JWTClaimsSet.Builder(jar.getJWTClaimsSet())
						.issuer("https://otro-verifier.example.es") //$NON-NLS-1$
						.build());
		mismatchedIssuerJar.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(IllegalArgumentException.class, () -> req.toUriWithRequestObject(mismatchedIssuerJar));
		final SignedJWT noExpirationJar = new SignedJWT(
				jarHeader(),
				new JWTClaimsSet.Builder(jar.getJWTClaimsSet())
						.expirationTime(null)
						.build());
		noExpirationJar.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(IllegalArgumentException.class, () -> req.toUriWithRequestObject(noExpirationJar));
		final SignedJWT expiredJar = new SignedJWT(
				jarHeader(),
				new JWTClaimsSet.Builder(jar.getJWTClaimsSet())
						.expirationTime(Date.from(Instant.now().minus(Duration.ofMinutes(1))))
						.build());
		expiredJar.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(IllegalArgumentException.class, () -> req.toUriWithRequestObject(expiredJar));
		final SignedJWT futureIatJar = new SignedJWT(
				jarHeader(),
				new JWTClaimsSet.Builder(jar.getJWTClaimsSet())
						.issueTime(Date.from(Instant.now().plus(Duration.ofMinutes(1))))
						.build());
		futureIatJar.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(IllegalArgumentException.class, () -> req.toUriWithRequestObject(futureIatJar));
		final SignedJWT futureNbfJar = new SignedJWT(
				jarHeader(),
				new JWTClaimsSet.Builder(jar.getJWTClaimsSet())
						.notBeforeTime(Date.from(Instant.now().plus(Duration.ofMinutes(1))))
						.build());
		futureNbfJar.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(IllegalArgumentException.class, () -> req.toUriWithRequestObject(futureNbfJar));
		assertThrows(IllegalArgumentException.class, () -> req.toSignedRequestObject(
				new RSASSASigner(kp.getPrivate()), JWSAlgorithm.RS256, null, " ")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> req.toSignedRequestObject(
				new RSASSASigner(kp.getPrivate()), JWSAlgorithm.RS256, " ", null)); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> req.toSignedRequestObject(
				new RSASSASigner(kp.getPrivate()), JWSAlgorithm.RS256, null, " wallet")); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> req.toSignedRequestObject(
				new RSASSASigner(kp.getPrivate()), JWSAlgorithm.RS256, " kid-1", null)); //$NON-NLS-1$
	}

	@Test
	@DisplayName("Builder permite solicitar response_mode direct_post.jwt")
	void buildsJarmResponseMode() {
		final AuthorizationRequest req = new AuthorizationRequestBuilder()
				.clientId("https://verifier.example.es") //$NON-NLS-1$
				.responseUri(URI.create("https://verifier.example.es/oid4vp/response")) //$NON-NLS-1$
				.dcqlQuery("{\"credentials\":[{\"id\":\"pid\",\"format\":\"dc+sd-jwt\"}]}") //$NON-NLS-1$
				.directPostJwtResponse()
				.nonce("nonce") //$NON-NLS-1$
				.build();
		assertTrue(req.toUri().getRawQuery().contains("response_mode=direct_post.jwt")); //$NON-NLS-1$
	}

	@Test
	@DisplayName("JARM response valida firma, audience y state")
	void verifiesJarmResponse() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final KeyPair kp = kpg.generateKeyPair();
		final SignedJWT jwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder()
						.issuer("https://wallet.example.es") //$NON-NLS-1$
						.audience("https://verifier.example.es") //$NON-NLS-1$
						.expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
						.claim("state", "state-1") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("vp_token", "vp") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("presentation_submission", "{\"id\":\"ps-1\"}") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		jwt.sign(new RSASSASigner(kp.getPrivate()));

		final RSASSAVerifier verifier = new RSASSAVerifier(
				(java.security.interfaces.RSAPublicKey) kp.getPublic());
		final JarmAuthorizationResponse response = JarmAuthorizationResponse.verify(
				jwt.serialize(), verifier, "https://verifier.example.es", "state-1", //$NON-NLS-1$ //$NON-NLS-2$
				"https://wallet.example.es"); //$NON-NLS-1$
		assertEquals("vp", response.vpToken()); //$NON-NLS-1$
		assertEquals("state-1", response.state()); //$NON-NLS-1$
		assertEquals("{\"id\":\"ps-1\"}", response.presentationSubmission()); //$NON-NLS-1$
		final SignedJWT objectVpTokenJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder(jwt.getJWTClaimsSet())
						.claim("vp_token", Map.of("format", "dc+sd-jwt")) //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						.build());
		objectVpTokenJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertEquals("{\"format\":\"dc+sd-jwt\"}", JarmAuthorizationResponse.verify( //$NON-NLS-1$
				objectVpTokenJwt.serialize(), verifier,
				"https://verifier.example.es", "state-1").vpToken()); //$NON-NLS-1$ //$NON-NLS-2$
		final SignedJWT emptyObjectVpTokenJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder(jwt.getJWTClaimsSet())
						.claim("vp_token", Map.of()) //$NON-NLS-1$
						.build());
		emptyObjectVpTokenJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				emptyObjectVpTokenJwt.serialize(), verifier,
				"https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final SignedJWT emptyArrayVpTokenJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder(jwt.getJWTClaimsSet())
						.claim("vp_token", List.of()) //$NON-NLS-1$
						.build());
		emptyArrayVpTokenJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				emptyArrayVpTokenJwt.serialize(), verifier,
				"https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final SignedJWT unnormalizedTextVpTokenJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder(jwt.getJWTClaimsSet())
						.claim("vp_token", " vp") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		unnormalizedTextVpTokenJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				unnormalizedTextVpTokenJwt.serialize(), verifier,
				"https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final SignedJWT objectSubmissionJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder(jwt.getJWTClaimsSet())
						.claim("presentation_submission", Map.of("id", "ps-1")) //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						.build());
		objectSubmissionJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertEquals("{\"id\":\"ps-1\"}", JarmAuthorizationResponse.verify( //$NON-NLS-1$
				objectSubmissionJwt.serialize(), verifier,
				"https://verifier.example.es", "state-1").presentationSubmission()); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				jwt.serialize(), verifier, "https://verifier.example.es", "other")); //$NON-NLS-1$ //$NON-NLS-2$
		final SignedJWT emptySubmissionJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder(jwt.getJWTClaimsSet())
						.claim("presentation_submission", "{}") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		emptySubmissionJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				emptySubmissionJwt.serialize(), verifier,
				"https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$
		final SignedJWT emptyObjectSubmissionJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder(jwt.getJWTClaimsSet())
						.claim("presentation_submission", Map.of()) //$NON-NLS-1$
						.build());
		emptyObjectSubmissionJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				emptyObjectSubmissionJwt.serialize(), verifier,
				"https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				jwt.serialize(), verifier, " ", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				jwt.serialize(), verifier, "https://verifier.example.es", " ")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				jwt.serialize(), verifier, " https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				jwt.serialize(), verifier, "https://verifier.example.es", " state-1")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				jwt.serialize(), verifier, "https://verifier.example.es", "state-1", //$NON-NLS-1$ //$NON-NLS-2$
				"https://otra-wallet.example.es")); //$NON-NLS-1$
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				jwt.serialize(), verifier, "https://verifier.example.es", "state-1", " ")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

		final SignedJWT untypedJwt = new SignedJWT(
				new com.nimbusds.jose.JWSHeader.Builder(JWSAlgorithm.RS256).build(),
				jwt.getJWTClaimsSet());
		untypedJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				untypedJwt.serialize(), verifier, "https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final SignedJWT noExpirationJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder()
						.issuer("https://wallet.example.es") //$NON-NLS-1$
						.audience("https://verifier.example.es") //$NON-NLS-1$
						.claim("state", "state-1") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("vp_token", "vp") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		noExpirationJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				noExpirationJwt.serialize(), verifier, "https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final SignedJWT futureIatJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder()
						.issuer("https://wallet.example.es") //$NON-NLS-1$
						.audience("https://verifier.example.es") //$NON-NLS-1$
						.issueTime(Date.from(Instant.now().plus(Duration.ofMinutes(1))))
						.expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
						.claim("state", "state-1") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("vp_token", "vp") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		futureIatJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				futureIatJwt.serialize(), verifier, "https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final SignedJWT futureNbfJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder()
						.issuer("https://wallet.example.es") //$NON-NLS-1$
						.audience("https://verifier.example.es") //$NON-NLS-1$
						.notBeforeTime(Date.from(Instant.now().plus(Duration.ofMinutes(1))))
						.expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
						.claim("state", "state-1") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("vp_token", "vp") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		futureNbfJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				futureNbfJwt.serialize(), verifier, "https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final SignedJWT expiredJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder()
						.issuer("https://wallet.example.es") //$NON-NLS-1$
						.audience("https://verifier.example.es") //$NON-NLS-1$
						.expirationTime(Date.from(Instant.now().minus(Duration.ofMinutes(1))))
						.claim("state", "state-1") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("vp_token", "vp") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		expiredJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				expiredJwt.serialize(), verifier, "https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final SignedJWT noAudienceJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder()
						.issuer("https://wallet.example.es") //$NON-NLS-1$
						.expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
						.claim("state", "state-1") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("vp_token", "vp") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		noAudienceJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				noAudienceJwt.serialize(), verifier, null, "state-1")); //$NON-NLS-1$

		final SignedJWT noStateJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder()
						.issuer("https://wallet.example.es") //$NON-NLS-1$
						.audience("https://verifier.example.es") //$NON-NLS-1$
						.expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
						.claim("vp_token", "vp") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		noStateJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				noStateJwt.serialize(), verifier, "https://verifier.example.es", null)); //$NON-NLS-1$

		final SignedJWT noIssuerJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder()
						.audience("https://verifier.example.es") //$NON-NLS-1$
						.expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
						.claim("state", "state-1") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("vp_token", "vp") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		noIssuerJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				noIssuerJwt.serialize(), verifier, "https://verifier.example.es", "state-1", null)); //$NON-NLS-1$ //$NON-NLS-2$

		final SignedJWT unnormalizedIssuerJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder(jwt.getJWTClaimsSet())
						.issuer(" https://wallet.example.es") //$NON-NLS-1$
						.build());
		unnormalizedIssuerJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				unnormalizedIssuerJwt.serialize(), verifier,
				"https://verifier.example.es", "state-1", null)); //$NON-NLS-1$ //$NON-NLS-2$

		final SignedJWT unnormalizedAudienceJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder(jwt.getJWTClaimsSet())
						.audience(" https://verifier.example.es") //$NON-NLS-1$
						.build());
		unnormalizedAudienceJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				unnormalizedAudienceJwt.serialize(), verifier, null, "state-1")); //$NON-NLS-1$

		final SignedJWT unnormalizedStateJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder(jwt.getJWTClaimsSet())
						.claim("state", " state-1") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		unnormalizedStateJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				unnormalizedStateJwt.serialize(), verifier, "https://verifier.example.es", null)); //$NON-NLS-1$

		final SignedJWT malformedSubmissionJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder()
						.issuer("https://wallet.example.es") //$NON-NLS-1$
						.audience("https://verifier.example.es") //$NON-NLS-1$
						.expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
						.claim("state", "state-1") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("vp_token", "vp") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("presentation_submission", "not-json") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		malformedSubmissionJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				malformedSubmissionJwt.serialize(), verifier,
				"https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final SignedJWT blankSubmissionJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder()
						.issuer("https://wallet.example.es") //$NON-NLS-1$
						.audience("https://verifier.example.es") //$NON-NLS-1$
						.expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
						.claim("state", "state-1") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("vp_token", "vp") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("presentation_submission", " ") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		blankSubmissionJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				blankSubmissionJwt.serialize(), verifier,
				"https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$

		final SignedJWT unnormalizedSubmissionJwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder()
						.issuer("https://wallet.example.es") //$NON-NLS-1$
						.audience("https://verifier.example.es") //$NON-NLS-1$
						.expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
						.claim("state", "state-1") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("vp_token", "vp") //$NON-NLS-1$ //$NON-NLS-2$
						.claim("presentation_submission", " {}") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		unnormalizedSubmissionJwt.sign(new RSASSASigner(kp.getPrivate()));
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				unnormalizedSubmissionJwt.serialize(), verifier,
				"https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	@Test
	@DisplayName("JARM response exige vp_token")
	void rejectsJarmWithoutVpToken() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		final KeyPair kp = kpg.generateKeyPair();
		final SignedJWT jwt = new SignedJWT(
				jarmHeader(),
				new JWTClaimsSet.Builder()
						.issuer("https://wallet.example.es") //$NON-NLS-1$
						.audience("https://verifier.example.es") //$NON-NLS-1$
						.expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(5))))
						.claim("state", "state-1") //$NON-NLS-1$ //$NON-NLS-2$
						.build());
		jwt.sign(new RSASSASigner(kp.getPrivate()));

		final RSASSAVerifier verifier = new RSASSAVerifier(
				(java.security.interfaces.RSAPublicKey) kp.getPublic());
		assertThrows(JOSEException.class, () -> JarmAuthorizationResponse.verify(
				jwt.serialize(), verifier, "https://verifier.example.es", "state-1")); //$NON-NLS-1$ //$NON-NLS-2$
	}

	private static com.nimbusds.jose.JWSHeader jarHeader() {
		return new com.nimbusds.jose.JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(new JOSEObjectType("oauth-authz-req+jwt")) //$NON-NLS-1$
				.build();
	}

	private static com.nimbusds.jose.JWSHeader jarmHeader() {
		return new com.nimbusds.jose.JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(new JOSEObjectType("oauth-authz-resp+jwt")) //$NON-NLS-1$
				.build();
	}

	@Test
	@DisplayName("Cada build genera un nonce distinto (high-entropy)")
	void freshNoncesUnique() {
		final AuthorizationRequestBuilder base = new AuthorizationRequestBuilder()
				.clientId("https://verifier.example.es")
				.responseUri(URI.create("https://x/r")) //$NON-NLS-1$
				.presentationDefinitionUri(URI.create("https://x/pd")); //$NON-NLS-1$
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
		assertThrows(IllegalArgumentException.class, () -> new AuthorizationRequestBuilder()
				.clientId("http://c").responseUri(URI.create("https://x/r")).build()); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class, () -> new AuthorizationRequestBuilder()
				.clientId("https:/c").responseUri(URI.create("https://x/r")).build()); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class, () -> new AuthorizationRequestBuilder()
				.clientId("https://c").responseUri(URI.create("http://x/r")).build()); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class, () -> new AuthorizationRequestBuilder()
				.clientId("https://c").responseUri(URI.create("https:/r")).build()); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class, () -> new AuthorizationRequestBuilder()
				.clientId("https://c").responseUri(URI.create("https://x/r")) //$NON-NLS-1$ //$NON-NLS-2$
				.presentationDefinitionUri(URI.create("http://x/pd")).build()); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> new AuthorizationRequestBuilder()
				.clientId("https://c").responseUri(URI.create("https://x/r")) //$NON-NLS-1$ //$NON-NLS-2$
				.presentationDefinitionUri(URI.create("https:/pd")).build()); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> new AuthorizationRequestBuilder()
				.clientId("https://c#fragmento").responseUri(URI.create("https://x/r")) //$NON-NLS-1$ //$NON-NLS-2$
				.presentationDefinitionUri(URI.create("https://x/pd")).build()); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> new AuthorizationRequestBuilder()
				.clientId("https://user@c").responseUri(URI.create("https://x/r")) //$NON-NLS-1$ //$NON-NLS-2$
				.presentationDefinitionUri(URI.create("https://x/pd")).build()); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> new AuthorizationRequestBuilder()
				.clientId("https://c").responseUri(URI.create("https://x/r#fragmento")) //$NON-NLS-1$ //$NON-NLS-2$
				.presentationDefinitionUri(URI.create("https://x/pd")).build()); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> new AuthorizationRequestBuilder()
				.clientId("https://c").responseUri(URI.create("https://user@x/r")) //$NON-NLS-1$ //$NON-NLS-2$
				.presentationDefinitionUri(URI.create("https://x/pd")).build()); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class, () -> new AuthorizationRequestBuilder()
				.clientId("https://c").responseUri(URI.create("https://x/r")) //$NON-NLS-1$ //$NON-NLS-2$
				.presentationDefinitionUri(URI.create("https://x/pd#fragmento")).build()); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequest("https://c", URI.create("https://x/r"), //$NON-NLS-1$ //$NON-NLS-2$
						"fragment", null, null, "n", null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequest("https://c", URI.create("https://x/r"), //$NON-NLS-1$ //$NON-NLS-2$
						" direct_post", null, null, "n", null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequest(" ", URI.create("https://x/r"), //$NON-NLS-1$ //$NON-NLS-2$
						"direct_post", null, null, "n", null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequest("https://c", URI.create("https://x/r"), //$NON-NLS-1$ //$NON-NLS-2$
						"direct_post", null, null, " ", null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequest("https://c", URI.create("https://x/r"), //$NON-NLS-1$ //$NON-NLS-2$
						"direct_post", null, null, " n", null)); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequest("https://c", URI.create("https://x/r"), //$NON-NLS-1$ //$NON-NLS-2$
						"direct_post", null, null, "n", " ")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertThrows(IllegalArgumentException.class,
				() -> new AuthorizationRequest("https://c", URI.create("https://x/r"), //$NON-NLS-1$ //$NON-NLS-2$
						"direct_post", null, null, "n", " state")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		assertThrows(IllegalArgumentException.class, () -> new AuthorizationRequestBuilder()
				.clientId("https://c").responseUri(URI.create("https://x/r")).nonce("n").build()); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
	}

	@Test
	@DisplayName("EudiwClient rechaza entradas locales antes de enviar")
	void clientRejectsInvalidLocalInputs() {
		assertThrows(NullPointerException.class, () -> new EudiwClient(null));
		final EudiwClient client = new EudiwClient();
		assertThrows(NullPointerException.class, () -> client.postFormUrlencoded(null, "a=b"));
		assertThrows(NullPointerException.class, () -> client.postFormUrlencoded(URI.create("https://wallet.example"), null));
		assertThrows(IOException.class, () -> client.postFormUrlencoded(URI.create("http://wallet.example"), "a=b"));
		assertThrows(IOException.class, () -> client.postFormUrlencoded(URI.create("https:/request"), "a=b")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class, () -> client.postFormUrlencoded(URI.create("https://user@wallet.example/request"), "a=b")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class, () -> client.postFormUrlencoded(URI.create("https://wallet.example/request#frag"), "a=b")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class, () -> client.postFormUrlencoded(URI.create("https://wallet.example"), " ")); //$NON-NLS-1$ //$NON-NLS-2$
		assertThrows(IOException.class, () -> client.postFormUrlencoded(URI.create("https://wallet.example"), " a=b")); //$NON-NLS-1$ //$NON-NLS-2$
	}
}
