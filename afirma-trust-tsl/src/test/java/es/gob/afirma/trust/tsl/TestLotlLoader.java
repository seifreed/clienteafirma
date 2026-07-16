/* Copyright (C) 2026 [Gobierno de España] / Agencia Estatal de Administración Digital */

package es.gob.afirma.trust.tsl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.parsers.DocumentBuilderFactory;

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
	@DisplayName("LotlLoader rechaza LOTL sin firma válida")
	void rejectsUnsignedLotl() throws Exception {
		final KeyPair kp = rsa();
		final LotlLoader loader = new LotlLoader(
				() -> LOTL.getBytes(StandardCharsets.UTF_8), kp.getPublic(), null);
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

	private static KeyPair rsa() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); //$NON-NLS-1$
		kpg.initialize(2048);
		return kpg.generateKeyPair();
	}

	private static byte[] sign(final String xml, final KeyPair kp) throws Exception {
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
		factory.newXMLSignature(signedInfo, null).sign(
				new DOMSignContext(kp.getPrivate(), doc.getDocumentElement()));
		return serialize(doc);
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
