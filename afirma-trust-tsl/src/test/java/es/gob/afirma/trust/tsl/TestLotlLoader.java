/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Document;

/** Pruebas del loader LOTL con cache persistida. */
final class TestLotlLoader {

	private static final String LOTL = """
		<?xml version="1.0" encoding="UTF-8"?>
		<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">
		  <SchemeInformation>
		    <SchemeOperatorName><Name>European Commission</Name></SchemeOperatorName>
		    <SchemeTerritory>EU</SchemeTerritory>
		  </SchemeInformation>
		</TrustServiceStatusList>
		""";
	private static final String NOT_A_TSL = LOTL
			.replace("<TrustServiceStatusList", "<NotTrustServiceStatusList") //$NON-NLS-1$ //$NON-NLS-2$
			.replace("</TrustServiceStatusList>", "</NotTrustServiceStatusList>"); //$NON-NLS-1$ //$NON-NLS-2$

	@TempDir
	Path temp;

	@Test
	@DisplayName("LotlLoader verifica firma XMLDSig y persiste cache")
	void verifiesSignatureAndWritesCache() throws Exception {
		final KeyPair kp = rsa();
		final byte[] signed = sign(LOTL, kp);
		final Path cache = this.temp.resolve("eu-lotl.xml"); //$NON-NLS-1$

		final TslDocument doc = new LotlLoader(() -> signed, kp.getPublic(), cache).load();

		assertEquals("EU", doc.territory()); //$NON-NLS-1$
		assertTrue(doc.signed());
		assertTrue(Files.size(cache) > 0);
	}

	@Test
	@DisplayName("LotlLoader reutiliza cache fresca verificada sin descargar")
	void reusesFreshVerifiedCache() throws Exception {
		final KeyPair kp = rsa();
		final byte[] signed = sign(LOTL, kp);
		final Path cache = this.temp.resolve("eu-lotl.xml"); //$NON-NLS-1$
		Files.write(cache, signed);

		final LotlLoader loader = new LotlLoader(() -> {
			throw new AssertionError("No debe descargar con cache LOTL fresca"); //$NON-NLS-1$
		}, kp.getPublic(), cache);

		assertEquals("EU", loader.load().territory()); //$NON-NLS-1$
	}

	@Test
	@DisplayName("LotlLoader refresca cache LOTL antigua")
	void refreshesStaleCache() throws Exception {
		final KeyPair kp = rsa();
		final byte[] signed = sign(LOTL, kp);
		final Path cache = this.temp.resolve("eu-lotl.xml"); //$NON-NLS-1$
		Files.write(cache, signed);
		Files.setLastModifiedTime(cache,
				FileTime.from(Instant.now().minus(Duration.ofHours(25))));
		final AtomicBoolean downloaded = new AtomicBoolean();

		final LotlLoader loader = new LotlLoader(() -> {
			downloaded.set(true);
			return signed;
		}, kp.getPublic(), cache);

		assertEquals("EU", loader.load().territory()); //$NON-NLS-1$
		assertTrue(downloaded.get());
	}

	@Test
	@DisplayName("LotlLoader refresca cache LOTL con fecha futura")
	void refreshesFutureDatedCache() throws Exception {
		final KeyPair kp = rsa();
		final byte[] signed = sign(LOTL, kp);
		final Path cache = this.temp.resolve("eu-lotl.xml"); //$NON-NLS-1$
		Files.write(cache, signed);
		Files.setLastModifiedTime(cache,
				FileTime.from(Instant.now().plus(Duration.ofHours(1))));
		final AtomicBoolean downloaded = new AtomicBoolean();

		final LotlLoader loader = new LotlLoader(() -> {
			downloaded.set(true);
			return signed;
		}, kp.getPublic(), cache);

		assertEquals("EU", loader.load().territory()); //$NON-NLS-1$
		assertTrue(downloaded.get());
	}

	@Test
	@DisplayName("LotlLoader rechaza LOTL sin firma válida")
	void rejectsUnsignedLotl() throws Exception {
		final KeyPair kp = rsa();
		final LotlLoader loader = new LotlLoader(
				() -> LOTL.getBytes(StandardCharsets.UTF_8), kp.getPublic(), null);
		assertThrows(TslException.class, loader::load);
	}

	@Test
	@DisplayName("LotlLoader rechaza URI LOTL insegura")
	void rejectsUnsafeLotlUri() {
		assertThrows(IllegalArgumentException.class,
				() -> new LotlLoader.HttpTslXmlSource(URI.create("http://ec.europa.eu/lotl.xml"))); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new LotlLoader.HttpTslXmlSource(URI.create("https://user@ec.europa.eu/lotl.xml"))); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new LotlLoader.HttpTslXmlSource(URI.create("https://ec.europa.eu/lotl.xml#frag"))); //$NON-NLS-1$
		assertThrows(IllegalArgumentException.class,
				() -> new LotlLoader.HttpTslXmlSource(URI.create("https://ec.europa.eu/lotl.xml?x=1"))); //$NON-NLS-1$
	}

	@Test
	@DisplayName("LotlLoader rechaza XML firmado que no es una TSL")
	void rejectsSignedNonTslRoot() throws Exception {
		final KeyPair kp = rsa();
		final byte[] signed = sign(NOT_A_TSL, kp);
		final LotlLoader loader = new LotlLoader(
				() -> signed, kp.getPublic(), null);
		assertThrows(TslException.class, loader::load);
		final TslException e = assertThrows(TslException.class,
				() -> new TslVerifier().verify(signed, kp.getPublic()));
		assertEquals("La raíz XML no es TrustServiceStatusList", e.getMessage()); //$NON-NLS-1$
	}

	@Test
	@DisplayName("LotlLoader rechaza LOTL firmada caducada")
	void rejectsExpiredSignedLotl() throws Exception {
		final KeyPair kp = rsa();
		final byte[] signed = sign(LOTL.replace("</SchemeInformation>", //$NON-NLS-1$
				"<NextUpdate><dateTime>2026-01-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation>"), kp); //$NON-NLS-1$
		final LotlLoader loader = new LotlLoader(
				() -> signed, kp.getPublic(), null);

		assertThrows(TslException.class, loader::load);
	}

	@Test
	@DisplayName("LotlLoader usa cache verificada si falla la fuente")
	void fallsBackToVerifiedCache() throws Exception {
		final KeyPair kp = rsa();
		final byte[] signed = sign(LOTL, kp);
		final Path cache = this.temp.resolve("eu-lotl.xml"); //$NON-NLS-1$
		Files.write(cache, signed);

		final LotlLoader loader = new LotlLoader(() -> {
			throw new IOException("sin red"); //$NON-NLS-1$
		}, kp.getPublic(), cache);

		assertEquals("EU", loader.load().territory()); //$NON-NLS-1$
	}

	@Test
	@DisplayName("LotlLoader no usa cache antigua si falla la fuente")
	void rejectsStaleFallbackCache() throws Exception {
		final KeyPair kp = rsa();
		final byte[] signed = sign(LOTL, kp);
		final Path cache = this.temp.resolve("eu-lotl.xml"); //$NON-NLS-1$
		Files.write(cache, signed);
		Files.setLastModifiedTime(cache,
				FileTime.from(Instant.now().minus(Duration.ofHours(25))));

		final LotlLoader loader = new LotlLoader(() -> {
			throw new IOException("sin red"); //$NON-NLS-1$
		}, kp.getPublic(), cache);

		assertThrows(TslException.class, loader::load);
	}

	@Test
	@DisplayName("LotlLoader usa cache verificada si la descarga no valida")
	void fallsBackToVerifiedCacheOnBadDownload() throws Exception {
		final KeyPair kp = rsa();
		final byte[] signed = sign(LOTL, kp);
		final Path cache = this.temp.resolve("eu-lotl.xml"); //$NON-NLS-1$
		Files.write(cache, signed);

		final LotlLoader loader = new LotlLoader(
				() -> LOTL.getBytes(StandardCharsets.UTF_8), kp.getPublic(), cache);

		assertEquals("EU", loader.load().territory()); //$NON-NLS-1$
	}

	@Test
	@DisplayName("TslVerifier usa el certificado embebido en KeyInfo si no se aporta clave")
	void verifiesSelfContainedSignature() throws Exception {
		final KeyPair kp = rsa();
		final X509Certificate cert = selfSigned(kp);
		final byte[] signed = sign(LOTL, kp, cert);

		assertTrue(new TslVerifier().verify(signed));
	}

	@Test
	@DisplayName("TslVerifier rechaza certificado KeyInfo caducado")
	void rejectsExpiredKeyInfoCertificate() throws Exception {
		final KeyPair kp = rsa();
		final Instant expired = Instant.now().minus(Duration.ofDays(2));
		final byte[] signed = sign(LOTL, kp, selfSigned(kp, expired, expired.plus(Duration.ofDays(1))));

		assertThrows(TslException.class, () -> new TslVerifier().verify(signed));
		final Instant future = Instant.now().plus(Duration.ofDays(1));
		final byte[] notYetValid = sign(LOTL, kp, selfSigned(kp, future, future.plus(Duration.ofDays(1))));
		assertThrows(TslException.class, () -> new TslVerifier().verify(notYetValid));
	}

	@Test
	@DisplayName("TslVerifier rechaza KeyInfo con varios certificados X.509")
	void rejectsMultipleKeyInfoCertificates() throws Exception {
		final KeyPair kp = rsa();
		final byte[] signed = sign(LOTL, kp, selfSigned(kp), selfSigned(rsa()));

		assertThrows(TslException.class, () -> new TslVerifier().verify(signed));
	}

	@Test
	@DisplayName("TslVerifier rechaza KeyInfo con certificado X.509 inválido")
	void rejectsInvalidKeyInfoCertificate() throws Exception {
		final KeyPair kp = rsa();
		final String signed = new String(sign(LOTL, kp, selfSigned(kp)), StandardCharsets.UTF_8)
				.replaceFirst("(?s)<X509Certificate>.*?</X509Certificate>", //$NON-NLS-1$
						"<X509Certificate>AAAA</X509Certificate>"); //$NON-NLS-1$

		assertThrows(TslException.class, () -> new TslVerifier().verify(signed.getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	@DisplayName("TslVerifier rechaza XML con DOCTYPE")
	void rejectsDoctype() throws Exception {
		final String xml = """
			<?xml version="1.0" encoding="UTF-8"?>
			<!DOCTYPE TrustServiceStatusList [
			  <!ENTITY xxe SYSTEM "file:///etc/passwd">
			]>
			<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">&xxe;</TrustServiceStatusList>
			""";

		assertThrows(TslException.class,
				() -> new TslVerifier().verify(xml.getBytes(StandardCharsets.UTF_8), rsa().getPublic()));
	}

	@Test
	@DisplayName("TslVerifier rechaza TSL con varias firmas XMLDSig")
	void rejectsMultipleXmlSignatures() throws Exception {
		final KeyPair kp = rsa();
		final String signed = new String(sign(LOTL, kp), StandardCharsets.UTF_8);
		final int signatureStart = signed.indexOf("<Signature"); //$NON-NLS-1$
		final int signatureEnd = signed.indexOf("</Signature>") + "</Signature>".length(); //$NON-NLS-1$ //$NON-NLS-2$
		final String duplicateSignature = signed.substring(0, signatureEnd)
				+ signed.substring(signatureStart, signatureEnd)
				+ signed.substring(signatureEnd);

		assertThrows(TslException.class,
				() -> new TslVerifier().verify(duplicateSignature.getBytes(StandardCharsets.UTF_8), kp.getPublic()));
		final String selfContained = new String(sign(LOTL, kp, selfSigned(kp)), StandardCharsets.UTF_8);
		final int selfContainedSignatureStart = selfContained.indexOf("<Signature"); //$NON-NLS-1$
		final int selfContainedSignatureEnd = selfContained.indexOf("</Signature>") + "</Signature>".length(); //$NON-NLS-1$ //$NON-NLS-2$
		final String duplicateSelfContainedSignature = selfContained.substring(0, selfContainedSignatureEnd)
				+ selfContained.substring(selfContainedSignatureStart, selfContainedSignatureEnd)
				+ selfContained.substring(selfContainedSignatureEnd);
		assertThrows(TslException.class,
				() -> new TslVerifier().verify(duplicateSelfContainedSignature.getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	@DisplayName("TslVerifier rechaza XMLDSig que no referencia el documento completo")
	void rejectsNonRootXmlSignatureReference() throws Exception {
		final KeyPair kp = rsa();
		final String signed = new String(sign(LOTL, kp), StandardCharsets.UTF_8);
		assertTrue(signed.contains("URI=\"\"")); //$NON-NLS-1$
		final String alteredReference = signed.replace("URI=\"\"", "URI=\"#scheme\""); //$NON-NLS-1$ //$NON-NLS-2$

		assertThrows(TslException.class,
				() -> new TslVerifier().verify(alteredReference.getBytes(StandardCharsets.UTF_8), kp.getPublic()));
	}

	private static KeyPair rsa() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		return kpg.generateKeyPair();
	}

	private static byte[] sign(final String xml, final KeyPair kp) throws Exception {
		return sign(xml, kp, null);
	}

	private static byte[] sign(final String xml, final KeyPair kp, final X509Certificate... certs) throws Exception {
		final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		final Document doc;
		try (ByteArrayInputStream bais = new ByteArrayInputStream(
				xml.getBytes(StandardCharsets.UTF_8))) {
			doc = dbf.newDocumentBuilder().parse(bais);
		}

		final XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM"); //$NON-NLS-1$
		final Reference ref = factory.newReference(
				"", //$NON-NLS-1$
				factory.newDigestMethod(DigestMethod.SHA256, null),
				Collections.singletonList(factory.newTransform(
						Transform.ENVELOPED, (javax.xml.crypto.dsig.spec.TransformParameterSpec) null)),
				null,
				null);
		final SignedInfo signedInfo = factory.newSignedInfo(
				factory.newCanonicalizationMethod(
						CanonicalizationMethod.INCLUSIVE,
				(javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
				factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
				Collections.singletonList(ref));
		final KeyInfo keyInfo;
		if (certs != null && certs.length > 0) {
			final KeyInfoFactory kif = factory.getKeyInfoFactory();
			keyInfo = kif.newKeyInfo(List.of(kif.newX509Data(List.of(certs))));
		}
		else {
			keyInfo = null;
		}
		factory.newXMLSignature(signedInfo, keyInfo).sign(
				new DOMSignContext(kp.getPrivate(), doc.getDocumentElement()));
		return serialize(doc);
	}

	private static X509Certificate selfSigned(final KeyPair kp) throws Exception {
		final Instant now = Instant.now();
		return selfSigned(kp, now, now.plus(Duration.ofDays(365)));
	}

	private static X509Certificate selfSigned(final KeyPair kp,
			final Instant notBefore, final Instant notAfter) throws Exception {
		final X500Name dn = new X500Name("CN=TSL Test, O=AEAD"); //$NON-NLS-1$
		final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				dn, BigInteger.valueOf(System.currentTimeMillis()),
				Date.from(notBefore), Date.from(notAfter),
				dn, kp.getPublic());
		final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()); //$NON-NLS-1$
		final X509CertificateHolder holder = builder.build(signer);
		return (X509Certificate) CertificateFactory.getInstance("X.509") //$NON-NLS-1$
				.generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
	}

	private static byte[] serialize(final Document doc) throws Exception {
		final javax.xml.transform.Transformer transformer =
				javax.xml.transform.TransformerFactory.newInstance().newTransformer();
		final java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		transformer.transform(new javax.xml.transform.dom.DOMSource(doc),
				new javax.xml.transform.stream.StreamResult(baos));
		return baos.toByteArray();
	}
}
